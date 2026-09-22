using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Query;
using SecurityRoleAnalyzer.Models;
using Crm = Microsoft.Crm.Sdk.Messages;

namespace SecurityRoleAnalyzer.Services;

/// <summary>
/// Mọi thao tác thay đổi dữ liệu trên Dataverse. Mỗi thao tác được ghi vào lịch sử (ActionLogStore)
/// kèm thông tin để hoàn tác, và làm mới chỉ mục phân quyền đang cache.
/// </summary>
public sealed partial class DataverseService
{
    private const string UserEntity = "systemuser";
    private const string TeamEntity = "team";

    private Task LoggedAsync(string action, string target, string detail, UndoInfo? undo, Guid? undoOf, Func<Task> operation) =>
        LoggedAsync(action, target, detail, undo, undoOf, _ => operation());

    /// <summary>
    /// Chạy một thao tác ghi và ghi lại vào lịch sử. Thao tác gọi <c>progress.MarkApplied()</c> ngay khi
    /// đã thay đổi dữ liệu thật, để nếu lỗi giữa chừng thì mục lịch sử vẫn hoàn tác được.
    /// </summary>
    private async Task LoggedAsync(
        string action, string target, string detail, UndoInfo? undo, Guid? undoOf, Func<ChangeProgress, Task> operation,
        Action<ActionLogEntry>? describe = null)
    {
        var entry = new ActionLogEntry
        {
            Environment = EnvironmentKey,
            Operator = CurrentUserName,
            Action = undoOf is null ? action : $"Hoàn tác: {action}",
            Target = target,
            Detail = detail,
            Undo = undoOf is null ? undo : null,
            UndoOf = undoOf,
        };
        describe?.Invoke(entry);

        var progress = new ChangeProgress();
        try
        {
            await operation(progress);
            entry.Success = true;
        }
        catch (Exception ex)
        {
            entry.Error = ex.Message;
            entry.PartiallyApplied = progress.Applied;
            throw;
        }
        finally
        {
            ActionLogStore.Append(entry);
            _cache.TryRemove(IndexCacheKey, out _);
            _cache.TryRemove(RoleDirectoryCacheKey, out _);
        }
    }

    /// <summary>Đánh dấu thời điểm thao tác đã thực sự thay đổi dữ liệu trên Dataverse.</summary>
    private sealed class ChangeProgress
    {
        public bool Applied { get; private set; }

        public void MarkApplied() => Applied = true;
    }

    #region Security role assignment

    /// <summary>
    /// Gán role cho user/team. Dataverse yêu cầu dùng bản sao role thuộc đúng Business Unit của principal.
    /// </summary>
    public async Task AssignRoleAsync(bool isTeam, PrincipalSearchResult principal, IReadOnlyCollection<RoleCopy> copies,
        string roleName = "", CancellationToken ct = default)
    {
        var copy = copies.FirstOrDefault(c => c.BusinessUnitId == principal.BusinessUnitId)
            ?? throw new InvalidOperationException(
                $"Không tìm thấy bản sao của role trong Business Unit \"{principal.BusinessUnitName}\".");

        await AssociateRoleCopyAsync(isTeam, principal.Id, principal.Name, copy.RoleId, roleName, null, ct);
    }

    /// <summary>Gán role gốc cho user/team theo BU của principal.</summary>
    public async Task AssignRootRoleAsync(bool isTeam, Guid principalId, string principalName, Guid businessUnitId, string businessUnitName,
        Guid rootRoleId, string roleName, CancellationToken ct = default)
    {
        var copies = await GetRoleCopiesAsync(new SecurityRoleInfo { Id = rootRoleId, Name = roleName }, ct);
        var principal = new PrincipalSearchResult
        {
            Id = principalId,
            Name = principalName,
            BusinessUnitId = businessUnitId,
            BusinessUnitName = businessUnitName,
        };
        await AssignRoleAsync(isTeam, principal, copies, roleName, ct);
    }

    /// <summary>Gỡ role gốc khỏi user/team (tự tìm bản sao theo BU của principal).</summary>
    public async Task RemoveRootRoleAsync(bool isTeam, Guid principalId, string principalName, Guid businessUnitId,
        Guid rootRoleId, string roleName, CancellationToken ct = default)
    {
        var copies = await GetRoleCopiesAsync(new SecurityRoleInfo { Id = rootRoleId, Name = roleName }, ct);
        var copy = copies.FirstOrDefault(c => c.BusinessUnitId == businessUnitId)
                   ?? throw new InvalidOperationException($"Không tìm thấy bản sao role \"{roleName}\" trong BU của \"{principalName}\".");
        await RemoveRoleAsync(isTeam, principalId, copy.RoleId, principalName, roleName, null, ct);
    }

    public Task AssignRoleToTeamAsync(TeamInfo team, SecurityRoleInfo role, CancellationToken ct = default) =>
        AssignRootRoleAsync(true, team.Id, team.Name, team.BusinessUnitId, team.BusinessUnitName, role.Id, role.Name, ct);

    public Task AssociateRoleCopyAsync(bool isTeam, Guid principalId, string principalName, Guid roleCopyId, string roleName,
        Guid? undoOf = null, CancellationToken ct = default) =>
        LoggedAsync(
            "Gán role",
            $"{(isTeam ? "Team" : "User")}: {principalName}",
            $"Role: {roleName}",
            new UndoInfo { Kind = UndoKind.RemoveRole, PrincipalType = isTeam ? TeamEntity : UserEntity, PrincipalId = principalId, RoleId = roleCopyId },
            undoOf,
            () => _client.AssociateAsync(
                isTeam ? TeamEntity : UserEntity,
                principalId,
                new Relationship(isTeam ? "teamroles_association" : "systemuserroles_association"),
                [new EntityReference("role", roleCopyId)],
                ct));

    public Task RemoveRoleAsync(bool isTeam, Guid principalId, Guid assignedRoleId, string principalName = "", string roleName = "",
        Guid? undoOf = null, CancellationToken ct = default) =>
        LoggedAsync(
            "Gỡ role",
            $"{(isTeam ? "Team" : "User")}: {principalName}",
            $"Role: {roleName}",
            new UndoInfo { Kind = UndoKind.AssignRole, PrincipalType = isTeam ? TeamEntity : UserEntity, PrincipalId = principalId, RoleId = assignedRoleId },
            undoOf,
            () => _client.DisassociateAsync(
                isTeam ? TeamEntity : UserEntity,
                principalId,
                new Relationship(isTeam ? "teamroles_association" : "systemuserroles_association"),
                [new EntityReference("role", assignedRoleId)],
                ct));

    #endregion

    #region Team membership

    public Task AddTeamMembersAsync(Guid teamId, IEnumerable<Guid> userIds, string teamName = "", string usersText = "",
        Guid? undoOf = null, CancellationToken ct = default)
    {
        var ids = userIds.Distinct().ToList();
        return LoggedAsync(
            "Thêm thành viên team",
            $"Team: {teamName}",
            $"{ids.Count} user: {usersText}",
            new UndoInfo { Kind = UndoKind.RemoveTeamMembers, TeamId = teamId, Ids = ids },
            undoOf,
            () => _client.ExecuteAsync(new Crm.AddMembersTeamRequest { TeamId = teamId, MemberIds = ids.ToArray() }, ct));
    }

    public Task RemoveTeamMembersAsync(Guid teamId, IEnumerable<Guid> userIds, string teamName = "", string usersText = "",
        Guid? undoOf = null, CancellationToken ct = default)
    {
        var ids = userIds.Distinct().ToList();
        return LoggedAsync(
            "Gỡ thành viên team",
            $"Team: {teamName}",
            $"{ids.Count} user: {usersText}",
            new UndoInfo { Kind = UndoKind.AddTeamMembers, TeamId = teamId, Ids = ids },
            undoOf,
            () => _client.ExecuteAsync(new Crm.RemoveMembersTeamRequest { TeamId = teamId, MemberIds = ids.ToArray() }, ct));
    }

    #endregion

    #region Privileges

    /// <summary>
    /// Cập nhật privilege của role: depth &gt; None thì thêm/đổi mức, None thì gỡ.
    /// Tự sao lưu privilege hiện tại trước khi thay đổi; trả về đường dẫn file sao lưu.
    /// </summary>
    public async Task<string> UpdateRolePrivilegesAsync(Guid roleId, string roleName,
        IReadOnlyCollection<(PrivilegeDefinition Privilege, PrivilegeDepth Depth)> changes, string reason = "Sửa privilege",
        CancellationToken ct = default)
    {
        var current = await GetRolePrivilegesAsync(roleId, ct);
        var catalog = await GetPrivilegeCatalogAsync(ct);
        var backupFile = PrivilegeBackupStore.Save(EnvironmentKey, roleId, roleName, current, catalog, reason);

        var effective = changes
            .GroupBy(c => c.Privilege.Id)
            .Select(g => g.Last())
            .Where(c => current.GetValueOrDefault(c.Privilege.Id) != c.Depth)
            .ToList();
        if (effective.Count == 0)
            return backupFile;

        var detail = string.Join("; ", effective.Take(25).Select(c =>
            $"{c.Privilege.Name}: {current.GetValueOrDefault(c.Privilege.Id).ToText()} → {c.Depth.ToText()}"));
        if (effective.Count > 25)
            detail += $"; ... (+{effective.Count - 25})";

        await LoggedAsync(
            reason,
            $"Role: {roleName}",
            $"{effective.Count} thay đổi – {detail}",
            new UndoInfo { Kind = UndoKind.RestorePrivilegeBackup, RecordId = roleId, BackupFile = backupFile },
            null,
            async progress =>
            {
                var adds = effective.Where(c => c.Depth > PrivilegeDepth.None).ToList();
                if (adds.Count > 0)
                {
                    await _client.ExecuteAsync(new Crm.AddPrivilegesRoleRequest
                    {
                        RoleId = roleId,
                        Privileges = adds.Select(c => ToSdkPrivilege(c.Privilege.Id, c.Depth)).ToArray(),
                    }, ct);
                    progress.MarkApplied();
                }

                foreach (var remove in effective.Where(c => c.Depth == PrivilegeDepth.None))
                {
                    await _client.ExecuteAsync(new Crm.RemovePrivilegeRoleRequest
                    {
                        RoleId = roleId,
                        PrivilegeId = remove.Privilege.Id,
                    }, ct);
                    progress.MarkApplied();
                }
            });

        return backupFile;
    }

    /// <summary>
    /// Thay toàn bộ privilege của role theo bản sao lưu. Privilege được khớp theo Id, nếu không có (khác môi trường) thì theo tên.
    /// Trả về danh sách privilege không tìm thấy.
    /// </summary>
    public async Task<List<string>> RestorePrivilegeBackupAsync(PrivilegeBackup backup, Guid targetRoleId, string targetRoleName,
        Guid? undoOf = null, CancellationToken ct = default)
    {
        var catalog = await GetPrivilegeCatalogAsync(ct);
        var byId = catalog.GroupBy(p => p.Id).ToDictionary(g => g.Key, g => g.First());
        var byName = catalog.GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var missing = new List<string>();
        var privileges = new List<Crm.RolePrivilege>();
        foreach (var item in backup.Privileges.Where(p => p.Depth > PrivilegeDepth.None))
        {
            var definition = byId.GetValueOrDefault(item.PrivilegeId) ?? byName.GetValueOrDefault(item.Name);
            if (definition is null)
            {
                missing.Add(item.Name);
                continue;
            }
            privileges.Add(ToSdkPrivilege(definition.Id, definition.Clamp(item.Depth)));
        }

        var current = await GetRolePrivilegesAsync(targetRoleId, ct);
        var safetyBackup = PrivilegeBackupStore.Save(EnvironmentKey, targetRoleId, targetRoleName, current, catalog,
            $"Trước khi khôi phục từ bản sao lưu {backup.CreatedOn:dd/MM/yyyy HH:mm}");

        await LoggedAsync(
            "Khôi phục privilege",
            $"Role: {targetRoleName}",
            $"Từ bản sao lưu của \"{backup.RoleName}\" ({backup.Environment}, {backup.CreatedOn:dd/MM/yyyy HH:mm}) – {privileges.Count} privilege"
                + (missing.Count > 0 ? $", {missing.Count} không tìm thấy" : ""),
            new UndoInfo { Kind = UndoKind.RestorePrivilegeBackup, RecordId = targetRoleId, BackupFile = safetyBackup },
            undoOf,
            () => _client.ExecuteAsync(new Crm.ReplacePrivilegesRoleRequest
            {
                RoleId = targetRoleId,
                Privileges = privileges.GroupBy(p => p.PrivilegeId).Select(g => g.First()).ToArray(),
            }, ct));

        return missing;
    }

    /// <summary>Tạo role mới (cùng BU với role nguồn) và sao chép toàn bộ privilege.</summary>
    public async Task<Guid> CopyRoleAsync(SecurityRoleInfo source, string newName, CancellationToken ct = default)
    {
        var privileges = await GetRolePrivilegesAsync(source.Id, ct);
        var newRoleId = Guid.Empty;

        await LoggedAsync(
            "Sao chép role",
            $"Role: {newName}",
            $"Sao chép từ \"{source.Name}\" – {privileges.Count(p => p.Value > PrivilegeDepth.None)} privilege",
            null,
            null,
            async () =>
            {
                var role = new Entity("role")
                {
                    ["name"] = newName,
                    ["businessunitid"] = new EntityReference("businessunit", source.BusinessUnitId),
                };
                newRoleId = await _client.CreateAsync(role, ct);
                await _client.ExecuteAsync(new Crm.ReplacePrivilegesRoleRequest
                {
                    RoleId = newRoleId,
                    Privileges = privileges.Where(p => p.Value > PrivilegeDepth.None).Select(p => ToSdkPrivilege(p.Key, p.Value)).ToArray(),
                }, ct);
            });

        // Ghi thêm thông tin hoàn tác (xóa role vừa tạo).
        ActionLogStore.Append(new ActionLogEntry
        {
            Environment = EnvironmentKey,
            Operator = CurrentUserName,
            Action = "Tạo role",
            Target = $"Role: {newName}",
            Detail = $"Id: {newRoleId}",
            Success = true,
            Undo = new UndoInfo { Kind = UndoKind.DeleteRole, RecordId = newRoleId },
        });
        return newRoleId;
    }

    /// <summary>Tạo role mới, chưa có privilege nào.</summary>
    public async Task<Guid> CreateRoleAsync(string name, Guid businessUnitId, string businessUnitName,
        bool inherited = true, CancellationToken ct = default)
    {
        var newRoleId = Guid.Empty;
        await LoggedAsync(
            "Tạo role",
            $"Role: {name}",
            $"Business Unit: {businessUnitName}",
            null,
            null,
            async () =>
            {
                var role = new Entity("role")
                {
                    ["name"] = name,
                    ["businessunitid"] = new EntityReference("businessunit", businessUnitId),
                    ["isinherited"] = new OptionSetValue(inherited ? 1 : 0),
                };
                newRoleId = await _client.CreateAsync(role, ct);
            });

        // Ghi thêm mục hoàn tác (xóa role vừa tạo) sau khi đã biết Id.
        ActionLogStore.Append(new ActionLogEntry
        {
            Environment = EnvironmentKey,
            Operator = CurrentUserName,
            Action = "Tạo role",
            Target = $"Role: {name}",
            Detail = $"Id: {newRoleId}",
            Success = true,
            Undo = new UndoInfo { Kind = UndoKind.DeleteRole, RecordId = newRoleId },
        });
        return newRoleId;
    }

    /// <summary>
    /// Đổi tên và/hoặc chế độ kế thừa quyền của role. Dataverse tự đồng bộ thay đổi này
    /// xuống các bản sao theo Business Unit.
    /// </summary>
    public Task UpdateRoleAsync(SecurityRoleInfo role, string newName, bool inherited, CancellationToken ct = default)
    {
        var changes = new List<string>();
        var entity = new Entity("role", role.Id);

        if (!string.Equals(role.Name, newName, StringComparison.Ordinal))
        {
            entity["name"] = newName;
            changes.Add($"tên: \"{role.Name}\" → \"{newName}\"");
        }
        if (role.IsInherited != inherited)
        {
            entity["isinherited"] = new OptionSetValue(inherited ? 1 : 0);
            changes.Add($"kế thừa quyền: {role.InheritanceText} → {(inherited ? "User + Team" : "Chỉ quyền Team")}");
        }

        if (changes.Count == 0)
            return Task.CompletedTask;

        return LoggedAsync(
            "Sửa role",
            $"Role: {role.Name}",
            string.Join("; ", changes),
            null,
            null,
            () => _client.UpdateAsync(entity, ct));
    }

    public Task DeleteRoleAsync(Guid roleId, string roleName, Guid? undoOf = null, CancellationToken ct = default) =>
        LoggedAsync("Xóa role", $"Role: {roleName}", $"Id: {roleId}", null, undoOf, () => _client.DeleteAsync("role", roleId, ct));

    private static Crm.RolePrivilege ToSdkPrivilege(Guid privilegeId, PrivilegeDepth depth) => new()
    {
        PrivilegeId = privilegeId,
        Depth = depth switch
        {
            PrivilegeDepth.User => Crm.PrivilegeDepth.Basic,
            PrivilegeDepth.BusinessUnit => Crm.PrivilegeDepth.Local,
            PrivilegeDepth.ParentChild => Crm.PrivilegeDepth.Deep,
            _ => Crm.PrivilegeDepth.Global,
        },
    };

    #endregion

    #region App & field security profile associations

    public Task AssociateAppRolesAsync(Guid appId, string appName, IReadOnlyCollection<(Guid RoleId, string Name)> roles,
        Guid? undoOf = null, CancellationToken ct = default) =>
        LoggedAsync(
            "Thêm role vào app",
            $"App: {appName}",
            string.Join(", ", roles.Select(r => r.Name)),
            new UndoInfo { Kind = UndoKind.DisassociateAppRoles, RecordId = appId, Ids = roles.Select(r => r.RoleId).ToList() },
            undoOf,
            () => _client.AssociateAsync("appmodule", appId, new Relationship("appmoduleroles_association"),
                new EntityReferenceCollection(roles.Select(r => new EntityReference("role", r.RoleId)).ToList()), ct));

    public Task DisassociateAppRolesAsync(Guid appId, string appName, IReadOnlyCollection<(Guid RoleId, string Name)> roles,
        Guid? undoOf = null, CancellationToken ct = default) =>
        LoggedAsync(
            "Gỡ role khỏi app",
            $"App: {appName}",
            string.Join(", ", roles.Select(r => r.Name)),
            new UndoInfo { Kind = UndoKind.AssociateAppRoles, RecordId = appId, Ids = roles.Select(r => r.RoleId).ToList() },
            undoOf,
            () => _client.DisassociateAsync("appmodule", appId, new Relationship("appmoduleroles_association"),
                new EntityReferenceCollection(roles.Select(r => new EntityReference("role", r.RoleId)).ToList()), ct));

    public Task AssociateFieldProfileAsync(Guid profileId, string profileName, bool isTeam, IReadOnlyCollection<(Guid Id, string Name)> principals,
        Guid? undoOf = null, CancellationToken ct = default) =>
        LoggedAsync(
            isTeam ? "Thêm team vào field security profile" : "Thêm user vào field security profile",
            $"Profile: {profileName}",
            string.Join(", ", principals.Select(p => p.Name)),
            new UndoInfo
            {
                Kind = UndoKind.DisassociateFieldProfile, RecordId = profileId, PrincipalType = isTeam ? TeamEntity : UserEntity,
                Ids = principals.Select(p => p.Id).ToList(),
            },
            undoOf,
            () => _client.AssociateAsync("fieldsecurityprofile", profileId,
                new Relationship(isTeam ? "teamprofiles_association" : "systemuserprofiles_association"),
                new EntityReferenceCollection(principals.Select(p => new EntityReference(isTeam ? TeamEntity : UserEntity, p.Id)).ToList()), ct));

    public Task DisassociateFieldProfileAsync(Guid profileId, string profileName, bool isTeam, IReadOnlyCollection<(Guid Id, string Name)> principals,
        Guid? undoOf = null, CancellationToken ct = default) =>
        LoggedAsync(
            isTeam ? "Gỡ team khỏi field security profile" : "Gỡ user khỏi field security profile",
            $"Profile: {profileName}",
            string.Join(", ", principals.Select(p => p.Name)),
            new UndoInfo
            {
                Kind = UndoKind.AssociateFieldProfile, RecordId = profileId, PrincipalType = isTeam ? TeamEntity : UserEntity,
                Ids = principals.Select(p => p.Id).ToList(),
            },
            undoOf,
            () => _client.DisassociateAsync("fieldsecurityprofile", profileId,
                new Relationship(isTeam ? "teamprofiles_association" : "systemuserprofiles_association"),
                new EntityReferenceCollection(principals.Select(p => new EntityReference(isTeam ? TeamEntity : UserEntity, p.Id)).ToList()), ct));

    #endregion

    #region Form security roles

    /// <summary>Thay đổi role của form: thêm/gỡ role gốc, hoặc mở cho mọi role (Everyone).</summary>
    public sealed record FormRoleChange(IReadOnlyCollection<Guid> Add, IReadOnlyCollection<Guid> Remove, bool OpenToEveryone = false);

    /// <summary>
    /// Áp thay đổi lên cấu hình role <b>đang có trên Dataverse</b> (đọc lại formxml, không dùng cache 24 giờ)
    /// để không ghi đè thay đổi người khác vừa làm trong Form settings. Trả về danh sách role sau khi ghi.
    /// </summary>
    public async Task<List<Guid>> ChangeFormRolesAsync(Guid formId, string formName, FormRoleChange change,
        CancellationToken ct = default)
    {
        var directory = await GetRoleDirectoryAsync(null, ct);
        var action = change.OpenToEveryone ? "Mở form cho mọi role"
            : change.Remove.Count == 0 ? "Thêm role vào form"
            : change.Add.Count == 0 ? "Gỡ role khỏi form"
            : "Sửa role của form";

        return await WriteFormRolesAsync(formId, formName, action, null, null, current =>
        {
            if (change.OpenToEveryone)
                return [];

            var remove = change.Remove.ToHashSet();
            var kept = current.Where(id => !remove.Contains(id) && !remove.Contains(directory.Root(id))).ToList();
            var keptRoots = kept.Select(directory.Root).ToHashSet();
            kept.AddRange(change.Add.Where(id => !keptRoots.Contains(directory.Root(id))).Distinct());

            // Danh sách rỗng được ghi thành Everyone – gỡ hết role sẽ mở form cho tất cả, ngược hẳn ý người dùng.
            if (kept.Count == 0)
                throw new InvalidOperationException(
                    "Form phải còn ít nhất một role. Muốn mở form cho tất cả, dùng \"Mở cho mọi role\".");
            return kept;
        }, ct);
    }

    /// <summary>Đặt lại đúng danh sách role cũ của form (dùng khi hoàn tác).</summary>
    public Task<List<Guid>> RestoreFormRolesAsync(Guid formId, string formName, IReadOnlyCollection<Guid> roleIds, string reason,
        Guid? undoOf = null, CancellationToken ct = default) =>
        WriteFormRolesAsync(formId, formName, "Khôi phục role của form", reason, undoOf, _ => [.. roleIds], ct);

    /// <summary>
    /// Đọc formxml mới nhất, sao lưu nguyên bản, ghi danh sách role mới rồi publish. Lịch sử ghi đủ:
    /// entity, loại form, role thêm/gỡ thực tế, trạng thái trước/sau và đường dẫn file sao lưu.
    /// </summary>
    private async Task<List<Guid>> WriteFormRolesAsync(Guid formId, string formName, string action, string? reason, Guid? undoOf,
        Func<List<Guid>, List<Guid>> compute, CancellationToken ct)
    {
        var form = await _client.RetrieveAsync("systemform", formId, new ColumnSet("formxml", "objecttypecode", "type"), ct);
        var formXml = form.GetAttributeValue<string>("formxml");
        if (string.IsNullOrWhiteSpace(formXml) || !TryParseFormXmlRoles(formXml, out var parsed))
            throw new InvalidOperationException($"Không đọc được formxml của form \"{formName}\" – mở Form settings trong D365 để sửa.");

        var before = parsed.RoleIds.ToList();
        var after = compute(before);
        if (after.ToHashSet().SetEquals(before))
            return after;

        var entity = form.GetAttributeValue<string>("objecttypecode") is { Length: > 0 } name && name != "none" ? name : null;
        var type = form.GetAttributeValue<OptionSetValue>("type")?.Value ?? -1;
        var isDashboard = type is 0 or 10 or 103;

        var directory = await GetRoleDirectoryAsync(null, ct);
        string RoleName(Guid id) =>
            directory.RoleById.TryGetValue(directory.Root(id), out var role) ? role.Name : $"(role không còn tồn tại {id})";
        string Describe(List<Guid> ids) =>
            ids.Count == 0 ? "Everyone" : $"{ids.Count} role: " + string.Join(", ", ids.Select(RoleName).Order());

        var beforeRoots = before.Select(directory.Root).ToHashSet();
        var afterRoots = after.Select(directory.Root).ToHashSet();
        var added = after.Where(id => !beforeRoots.Contains(directory.Root(id))).Select(RoleName).ToList();
        var removed = before.Where(id => !afterRoots.Contains(directory.Root(id))).Select(RoleName).ToList();

        var detail = new List<string> { $"{entity ?? "Dashboard"} · {FormRoleAnalyzer.TypeText(type)}" };
        if (reason is not null)
            detail.Add(reason);
        if (added.Count > 0)
            detail.Add("Thêm: " + string.Join(", ", added));
        if (removed.Count > 0)
            detail.Add("Gỡ: " + string.Join(", ", removed));
        if (before.Count == 0 || after.Count == 0)
            detail.Add($"{(before.Count == 0 ? "Everyone" : "Role cụ thể")} → {(after.Count == 0 ? "Everyone" : "Role cụ thể")}");

        var backupFile = PrivilegeBackupStore.SaveFormXml(EnvironmentKey, formId, formName, formXml);

        await LoggedAsync(
            action,
            $"Form: {formName}",
            string.Join(" · ", detail),
            new UndoInfo { Kind = UndoKind.SetFormRoles, RecordId = formId, Ids = before, BackupFile = backupFile },
            undoOf,
            async progress =>
            {
                await _client.UpdateAsync(new Entity("systemform", formId) { ["formxml"] = ReplaceFormXmlRoles(formXml, after) }, ct);
                progress.MarkApplied();

                // Chưa publish thì người dùng vẫn thấy cấu hình cũ.
                var publish = (entity is null ? "" : $"<entities><entity>{entity}</entity></entities>")
                              + (isDashboard ? $"<dashboards><dashboard>{formId:B}</dashboard></dashboards>" : "");
                await _client.ExecuteAsync(new Crm.PublishXmlRequest { ParameterXml = $"<importexportxml>{publish}</importexportxml>" }, ct);
            },
            entry =>
            {
                entry.RecordId = formId;
                entry.Before = Describe(before);
                entry.After = Describe(after);
                entry.BackupFile = backupFile;
            });

        _cache.TryRemove("forms", out _);
        DiskCache.Update<Dictionary<Guid, FormDisplayConditions>>(EnvironmentKey, "form-roles",
            cached => cached[formId] = new FormDisplayConditions(after, after.Count == 0, false));
        return after;
    }

    #endregion

    #region Undo

    /// <summary>Thực hiện thao tác ngược của một mục lịch sử (chỉ trên môi trường đang kết nối).</summary>
    public async Task UndoAsync(ActionLogEntry entry, CancellationToken ct = default)
    {
        if (!entry.CanUndo || entry.Undo is not { } undo)
            throw new InvalidOperationException("Mục này không hỗ trợ hoàn tác.");
        if (!string.Equals(entry.Environment, EnvironmentKey, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Mục này thuộc môi trường \"{entry.Environment}\", không phải môi trường đang kết nối.");

        var isTeam = undo.PrincipalType == TeamEntity;
        var target = entry.Target;

        switch (undo.Kind)
        {
            case UndoKind.RemoveRole:
                await RemoveRoleAsync(isTeam, undo.PrincipalId, undo.RoleId, target, entry.Detail, entry.Id, ct);
                break;
            case UndoKind.AssignRole:
                await AssociateRoleCopyAsync(isTeam, undo.PrincipalId, target, undo.RoleId, entry.Detail, entry.Id, ct);
                break;
            case UndoKind.RemoveTeamMembers:
                await RemoveTeamMembersAsync(undo.TeamId, undo.Ids, target, entry.Detail, entry.Id, ct);
                break;
            case UndoKind.AddTeamMembers:
                await AddTeamMembersAsync(undo.TeamId, undo.Ids, target, entry.Detail, entry.Id, ct);
                break;
            case UndoKind.RestorePrivilegeBackup:
                var backup = PrivilegeBackupStore.Load(undo.BackupFile);
                await RestorePrivilegeBackupAsync(backup, undo.RecordId, backup.RoleName, entry.Id, ct);
                break;
            case UndoKind.DeleteRole:
                await DeleteRoleAsync(undo.RecordId, target, entry.Id, ct);
                break;
            case UndoKind.DisassociateAppRoles:
                await DisassociateAppRolesAsync(undo.RecordId, target, undo.Ids.Select(id => (id, id.ToString())).ToList(), entry.Id, ct);
                break;
            case UndoKind.AssociateAppRoles:
                await AssociateAppRolesAsync(undo.RecordId, target, undo.Ids.Select(id => (id, id.ToString())).ToList(), entry.Id, ct);
                break;
            case UndoKind.DisassociateFieldProfile:
                await DisassociateFieldProfileAsync(undo.RecordId, target, isTeam, undo.Ids.Select(id => (id, id.ToString())).ToList(), entry.Id, ct);
                break;
            case UndoKind.AssociateFieldProfile:
                await AssociateFieldProfileAsync(undo.RecordId, target, isTeam, undo.Ids.Select(id => (id, id.ToString())).ToList(), entry.Id, ct);
                break;
            case UndoKind.SetFormRoles:
                await RestoreFormRolesAsync(undo.RecordId, target.Replace("Form: ", ""),
                    undo.Ids, $"Hoàn tác \"{entry.Action}\" lúc {entry.Time:dd/MM/yyyy HH:mm:ss}", entry.Id, ct);
                break;
            default:
                throw new InvalidOperationException("Mục này không hỗ trợ hoàn tác.");
        }
    }

    #endregion
}
