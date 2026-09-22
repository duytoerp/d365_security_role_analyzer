using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ClosedXML.Excel;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

internal static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };
}

/// <summary>Sao lưu privilege của role ra file JSON trước mỗi lần chỉnh sửa.</summary>
public static class PrivilegeBackupStore
{
    public static string Folder(string environment) =>
        Path.Combine(ConnectionProfileStore.AppDataFolder, "Backups", Safe(environment));

    public static string Save(string environment, Guid roleId, string roleName, IReadOnlyDictionary<Guid, PrivilegeDepth> privileges,
        IReadOnlyCollection<PrivilegeDefinition> catalog, string reason)
    {
        var names = catalog.GroupBy(p => p.Id).ToDictionary(g => g.Key, g => g.First().Name);
        var backup = new PrivilegeBackup
        {
            Environment = environment,
            RoleId = roleId,
            RoleName = roleName,
            Reason = reason,
            Privileges = privileges
                .Where(p => p.Value > PrivilegeDepth.None)
                .Select(p => new PrivilegeBackupItem { PrivilegeId = p.Key, Name = names.GetValueOrDefault(p.Key, p.Key.ToString()), Depth = p.Value })
                .OrderBy(p => p.Name)
                .ToList(),
        };

        var folder = Folder(environment);
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, $"{Safe(roleName)}_{DateTime.Now:yyyyMMdd_HHmmss_fff}.json");
        File.WriteAllText(path, JsonSerializer.Serialize(backup, JsonDefaults.Options));
        return path;
    }

    public static PrivilegeBackup Load(string path) =>
        JsonSerializer.Deserialize<PrivilegeBackup>(File.ReadAllText(path), JsonDefaults.Options)
        ?? throw new InvalidDataException("File sao lưu không hợp lệ.");

    /// <summary>
    /// Lưu nguyên formxml trước khi sửa role của form, vào <c>Backups\&lt;môi trường&gt;\Forms\</c>.
    /// Là bản gốc để đối chiếu hoặc dán lại bằng tay nếu cần – không chỉ dựa vào hoàn tác.
    /// </summary>
    public static string SaveFormXml(string environment, Guid formId, string formName, string formXml)
    {
        var folder = Path.Combine(Folder(environment), "Forms");
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, $"{Safe(formName)}_{formId:N}_{DateTime.Now:yyyyMMdd_HHmmss_fff}.xml");
        File.WriteAllText(path, formXml);
        return path;
    }

    private static string Safe(string text) =>
        string.Concat(text.Select(c => Path.GetInvalidFileNameChars().Contains(c) || c == ' ' ? '_' : c));
}

/// <summary>Chụp và so sánh cấu hình phân quyền giữa các môi trường hoặc các thời điểm.</summary>
public static class SnapshotService
{
    public static EnvironmentSnapshot Create(AccessIndex index, IReadOnlyCollection<PrivilegeDefinition> catalog, string environment, string createdBy)
    {
        var privilegeNames = catalog.GroupBy(p => p.Id).ToDictionary(g => g.Key, g => g.First().Name);
        var roleKeys = RoleKeys(index.Roles);
        string UserKey(Guid id) => index.UserById.TryGetValue(id, out var u) ? (string.IsNullOrEmpty(u.DomainName) ? u.FullName : u.DomainName) : id.ToString();
        string UserName(Guid id) => index.UserById.TryGetValue(id, out var u) ? u.FullName : "";

        return new EnvironmentSnapshot
        {
            Environment = environment,
            CreatedBy = createdBy,
            Roles = index.Roles.Select(r => new SnapshotRole
            {
                Name = roleKeys[r.Id],
                BusinessUnit = r.BusinessUnitName,
                IsManaged = r.IsManaged,
                Privileges = new SortedDictionary<string, PrivilegeDepth>(
                    index.RolePrivileges.GetValueOrDefault(r.Id, [])
                        .Where(p => p.Value > PrivilegeDepth.None)
                        .GroupBy(p => privilegeNames.GetValueOrDefault(p.Key, p.Key.ToString()), StringComparer.OrdinalIgnoreCase)
                        .ToDictionary(g => g.Key, g => g.Max(p => p.Value), StringComparer.OrdinalIgnoreCase),
                    StringComparer.OrdinalIgnoreCase),
            }).ToList(),
            UserRoles = index.UserRoles
                .Where(x => roleKeys.ContainsKey(x.RoleId))
                .Select(x => new SnapshotLink { Principal = UserKey(x.UserId), PrincipalName = UserName(x.UserId), Target = roleKeys[x.RoleId] })
                .ToList(),
            TeamRoles = index.TeamRoles
                .Where(x => roleKeys.ContainsKey(x.RoleId))
                .Select(x => new SnapshotLink { Principal = index.TeamName(x.TeamId), PrincipalName = index.TeamName(x.TeamId), Target = roleKeys[x.RoleId] })
                .ToList(),
            TeamMembers = index.TeamMembers
                .Select(x => new SnapshotLink { Principal = index.TeamName(x.TeamId), PrincipalName = index.TeamName(x.TeamId), Target = UserKey(x.UserId) })
                .ToList(),
        };
    }

    /// <summary>Tên role làm khóa so sánh; role trùng tên được đánh số (#2, #3...).</summary>
    private static Dictionary<Guid, string> RoleKeys(IEnumerable<SecurityRoleInfo> roles)
    {
        var result = new Dictionary<Guid, string>();
        foreach (var group in roles.GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase))
        {
            var index = 0;
            foreach (var role in group.OrderBy(r => r.Id))
                result[role.Id] = index++ == 0 ? role.Name : $"{role.Name} #{index}";
        }
        return result;
    }

    public static void Save(EnvironmentSnapshot snapshot, string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(snapshot, JsonDefaults.Options));

    public static EnvironmentSnapshot Load(string path) =>
        JsonSerializer.Deserialize<EnvironmentSnapshot>(File.ReadAllText(path), JsonDefaults.Options)
        ?? throw new InvalidDataException("File snapshot không hợp lệ.");

    public const string CategoryRole = "Role";
    public const string CategoryPrivilege = "Privilege";
    public const string CategoryUserRole = "Gán role cho user";
    public const string CategoryTeamRole = "Gán role cho team";
    public const string CategoryTeamMember = "Thành viên team";

    public const string Added = "Thêm mới";
    public const string Removed = "Bị xóa";
    public const string Changed = "Thay đổi";

    public static List<SnapshotDiffRow> Compare(EnvironmentSnapshot before, EnvironmentSnapshot after)
    {
        var rows = new List<SnapshotDiffRow>();
        var comparer = StringComparer.OrdinalIgnoreCase;

        var beforeRoles = before.Roles.GroupBy(r => r.Name, comparer).ToDictionary(g => g.Key, g => g.First(), comparer);
        var afterRoles = after.Roles.GroupBy(r => r.Name, comparer).ToDictionary(g => g.Key, g => g.First(), comparer);

        foreach (var name in beforeRoles.Keys.Union(afterRoles.Keys, comparer).Order(comparer))
        {
            var a = beforeRoles.GetValueOrDefault(name);
            var b = afterRoles.GetValueOrDefault(name);
            if (a is null)
            {
                // Role chỉ có ở bản B: áp được bằng cách tạo role rồi gán toàn bộ privilege.
                rows.Add(new SnapshotDiffRow
                {
                    Category = CategoryRole,
                    ChangeType = Added,
                    Item = name,
                    Detail = $"{b!.Privileges.Count} privilege",
                    After = b.IsManaged ? "Managed" : "Unmanaged",
                    CanApply = true,
                });
                continue;
            }
            if (b is null)
            {
                rows.Add(new SnapshotDiffRow { Category = CategoryRole, ChangeType = Removed, Item = name, Detail = $"{a.Privileges.Count} privilege", Before = a.IsManaged ? "Managed" : "Unmanaged" });
                continue;
            }

            foreach (var privilege in a.Privileges.Keys.Union(b.Privileges.Keys, comparer).Order(comparer))
            {
                var da = a.Privileges.GetValueOrDefault(privilege);
                var db = b.Privileges.GetValueOrDefault(privilege);
                if (da == db)
                    continue;
                rows.Add(new SnapshotDiffRow
                {
                    Category = CategoryPrivilege,
                    ChangeType = da == PrivilegeDepth.None ? Added : db == PrivilegeDepth.None ? Removed : Changed,
                    Item = name,
                    Detail = privilege,
                    Before = da.ToText(),
                    After = db.ToText(),
                    TargetDepth = db,
                    CanApply = true,
                });
            }
        }

        CompareLinks(rows, CategoryUserRole, before.UserRoles, after.UserRoles);
        CompareLinks(rows, CategoryTeamRole, before.TeamRoles, after.TeamRoles);
        CompareLinks(rows, CategoryTeamMember, before.TeamMembers, after.TeamMembers);
        return rows;
    }

    private static void CompareLinks(List<SnapshotDiffRow> rows, string category, List<SnapshotLink> before, List<SnapshotLink> after)
    {
        static string Key(SnapshotLink l) => $"{l.Principal.ToLowerInvariant()}{l.Target.ToLowerInvariant()}";
        var a = before.GroupBy(Key).ToDictionary(g => g.Key, g => g.First());
        var b = after.GroupBy(Key).ToDictionary(g => g.Key, g => g.First());

        foreach (var (key, link) in b.Where(x => !a.ContainsKey(x.Key)).OrderBy(x => x.Value.Principal))
            rows.Add(new SnapshotDiffRow { Category = category, ChangeType = Added, Item = Display(link), Detail = link.Target, After = "Có" });
        foreach (var (key, link) in a.Where(x => !b.ContainsKey(x.Key)).OrderBy(x => x.Value.Principal))
            rows.Add(new SnapshotDiffRow { Category = category, ChangeType = Removed, Item = Display(link), Detail = link.Target, Before = "Có" });
    }

    private static string Display(SnapshotLink link) =>
        string.IsNullOrEmpty(link.PrincipalName) || link.PrincipalName == link.Principal ? link.Principal : $"{link.PrincipalName} ({link.Principal})";
}

/// <summary>Đọc file Excel/CSV để gán/gỡ role và thành viên team hàng loạt.</summary>
public static class ImportService
{
    public static void CreateTemplate(string path)
    {
        using var workbook = new XLWorkbook();
        var sheet = workbook.Worksheets.Add("Import");
        string[] headers = ["Loại", "Principal", "Hành động", "Đối tượng"];
        for (var i = 0; i < headers.Length; i++)
        {
            sheet.Cell(1, i + 1).Value = headers[i];
            sheet.Cell(1, i + 1).Style.Font.Bold = true;
            sheet.Cell(1, i + 1).Style.Fill.BackgroundColor = XLColor.FromHtml("#0F6CBD");
            sheet.Cell(1, i + 1).Style.Font.FontColor = XLColor.White;
        }

        object[][] samples =
        [
            ["User", "user1@contoso.com", ImportActions.AssignRole, "Salesperson"],
            ["User", "user2@contoso.com", ImportActions.RemoveRole, "Sales Manager"],
            ["Team", "Sales Team HCM", ImportActions.AssignRole, "Salesperson"],
            ["User", "user1@contoso.com", ImportActions.AddToTeam, "Sales Team HCM"],
            ["User", "user3@contoso.com", ImportActions.RemoveFromTeam, "Sales Team HCM"],
        ];
        for (var r = 0; r < samples.Length; r++)
        for (var c = 0; c < samples[r].Length; c++)
            sheet.Cell(r + 2, c + 1).Value = samples[r][c].ToString();

        var help = workbook.Worksheets.Add("Huong dan");
        string[] lines =
        [
            "Loại: User hoặc Team",
            "Principal: User = username (UPN) hoặc email hoặc họ tên; Team = tên team",
            $"Hành động: {string.Join(" | ", ImportActions.All)}",
            "Đối tượng: tên security role (Gán/Gỡ role) hoặc tên team (Thêm vào/Gỡ khỏi team – chỉ áp dụng cho User)",
            "Role được gán theo Business Unit của từng user/team.",
        ];
        for (var i = 0; i < lines.Length; i++)
            help.Cell(i + 1, 1).Value = lines[i];
        help.Column(1).Width = 110;

        sheet.Columns().AdjustToContents();
        workbook.SaveAs(path);
    }

    public static List<ImportRow> Read(string path)
    {
        var rows = new List<ImportRow>();
        if (Path.GetExtension(path).Equals(".csv", StringComparison.OrdinalIgnoreCase))
        {
            var number = 1;
            foreach (var line in File.ReadLines(path).Skip(1))
            {
                number++;
                if (string.IsNullOrWhiteSpace(line))
                    continue;
                var parts = SplitCsv(line);
                rows.Add(Row(number, parts.ElementAtOrDefault(0), parts.ElementAtOrDefault(1), parts.ElementAtOrDefault(2), parts.ElementAtOrDefault(3)));
            }
            return rows;
        }

        using var workbook = new XLWorkbook(path);
        var sheet = workbook.Worksheets.First();
        foreach (var r in sheet.RowsUsed().Skip(1))
        {
            var values = Enumerable.Range(1, 4).Select(c => r.Cell(c).GetString()).ToArray();
            if (values.All(string.IsNullOrWhiteSpace))
                continue;
            rows.Add(Row(r.RowNumber(), values[0], values[1], values[2], values[3]));
        }
        return rows;
    }

    private static ImportRow Row(int number, string? type, string? principal, string? action, string? target) => new()
    {
        RowNumber = number,
        PrincipalType = (type ?? "").Trim(),
        Principal = (principal ?? "").Trim(),
        Action = (action ?? "").Trim(),
        Target = (target ?? "").Trim(),
    };

    private static List<string> SplitCsv(string line)
    {
        var result = new List<string>();
        var current = new System.Text.StringBuilder();
        var quoted = false;
        var separator = line.Contains(';') && !line.Contains(',') ? ';' : ',';
        for (var i = 0; i < line.Length; i++)
        {
            var ch = line[i];
            if (ch == '"')
            {
                if (quoted && i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else
                {
                    quoted = !quoted;
                }
            }
            else if (ch == separator && !quoted)
            {
                result.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(ch);
            }
        }
        result.Add(current.ToString());
        return result;
    }

    /// <summary>Kiểm tra từng dòng dựa trên chỉ mục phân quyền hiện tại.</summary>
    public static void Resolve(IEnumerable<ImportRow> rows, AccessIndex index)
    {
        var comparer = StringComparer.OrdinalIgnoreCase;
        var usersByKey = new Dictionary<string, List<UserInfo>>(comparer);
        foreach (var user in index.Users)
        {
            foreach (var key in new[] { user.DomainName, user.Email, user.FullName }.Where(k => !string.IsNullOrWhiteSpace(k)).Distinct(comparer))
            {
                if (!usersByKey.TryGetValue(key, out var list))
                    usersByKey[key] = list = [];
                list.Add(user);
            }
        }
        var teamsByName = index.Teams.GroupBy(t => t.Name, comparer).ToDictionary(g => g.Key, g => g.ToList(), comparer);
        var rolesByName = index.Roles.GroupBy(r => r.Name, comparer).ToDictionary(g => g.Key, g => g.ToList(), comparer);

        foreach (var row in rows)
        {
            row.Status = ImportStatus.Error;
            var isTeam = row.PrincipalType.Equals("Team", StringComparison.OrdinalIgnoreCase);
            if (!isTeam && !row.PrincipalType.Equals("User", StringComparison.OrdinalIgnoreCase))
            {
                row.Message = "Cột Loại phải là User hoặc Team.";
                continue;
            }
            if (!ImportActions.All.Contains(row.Action, comparer))
            {
                row.Message = $"Hành động không hợp lệ. Dùng: {string.Join(", ", ImportActions.All)}.";
                continue;
            }

            row.IsTeam = isTeam;
            if (isTeam)
            {
                if (!teamsByName.TryGetValue(row.Principal, out var teams))
                {
                    row.Message = $"Không tìm thấy team \"{row.Principal}\".";
                    continue;
                }
                if (teams.Count > 1)
                {
                    row.Message = $"Có {teams.Count} team trùng tên \"{row.Principal}\".";
                    continue;
                }
                row.PrincipalId = teams[0].Id;
                row.PrincipalDisplay = teams[0].Name;
                row.PrincipalBusinessUnitId = teams[0].BusinessUnitId;
                row.PrincipalBusinessUnitName = teams[0].BusinessUnitName;
            }
            else
            {
                if (!usersByKey.TryGetValue(row.Principal, out var users))
                {
                    row.Message = $"Không tìm thấy user \"{row.Principal}\".";
                    continue;
                }
                if (users.Count > 1)
                {
                    row.Message = $"Có {users.Count} user khớp \"{row.Principal}\" – hãy dùng username.";
                    continue;
                }
                row.PrincipalId = users[0].Id;
                row.PrincipalDisplay = users[0].FullName;
                row.PrincipalBusinessUnitId = users[0].BusinessUnitId;
                row.PrincipalBusinessUnitName = users[0].BusinessUnitName;
            }

            var isRoleAction = row.Action.Equals(ImportActions.AssignRole, StringComparison.OrdinalIgnoreCase)
                               || row.Action.Equals(ImportActions.RemoveRole, StringComparison.OrdinalIgnoreCase);
            if (isRoleAction)
            {
                if (!rolesByName.TryGetValue(row.Target, out var roles))
                {
                    row.Message = $"Không tìm thấy role \"{row.Target}\".";
                    continue;
                }
                if (roles.Count > 1)
                {
                    row.Message = $"Có {roles.Count} role trùng tên \"{row.Target}\".";
                    continue;
                }
                row.TargetId = roles[0].Id;
                row.TargetDisplay = roles[0].Name;

                var has = isTeam
                    ? index.RolesOfTeam(row.PrincipalId).Contains(row.TargetId)
                    : index.DirectRolesOf(row.PrincipalId).Contains(row.TargetId);
                var assign = row.Action.Equals(ImportActions.AssignRole, StringComparison.OrdinalIgnoreCase);
                if (assign == has)
                {
                    row.Status = ImportStatus.Skipped;
                    row.Message = assign ? "Đã có role này." : "Không có role này.";
                    continue;
                }
            }
            else
            {
                if (isTeam)
                {
                    row.Message = "Thêm/gỡ thành viên team chỉ áp dụng cho User.";
                    continue;
                }
                if (!teamsByName.TryGetValue(row.Target, out var teams) || teams.Count != 1)
                {
                    row.Message = teams is null ? $"Không tìm thấy team \"{row.Target}\"." : $"Có {teams.Count} team trùng tên \"{row.Target}\".";
                    continue;
                }
                var team = teams[0];
                if (!team.CanManageMembers)
                {
                    row.Message = "Team mặc định của BU hoặc team Entra ID – không thể thêm/gỡ thành viên.";
                    continue;
                }
                row.TargetId = team.Id;
                row.TargetDisplay = team.Name;

                var isMember = index.MembersOf(team.Id).Contains(row.PrincipalId);
                var add = row.Action.Equals(ImportActions.AddToTeam, StringComparison.OrdinalIgnoreCase);
                if (add == isMember)
                {
                    row.Status = ImportStatus.Skipped;
                    row.Message = add ? "Đã là thành viên." : "Không phải thành viên.";
                    continue;
                }
            }

            row.Status = ImportStatus.Valid;
            row.Message = "";
        }
    }

    public static async Task ExecuteAsync(ImportRow row, DataverseService service, CancellationToken ct = default)
    {
        switch (row.Action.ToLowerInvariant())
        {
            case var a when a == ImportActions.AssignRole.ToLowerInvariant():
                await service.AssignRootRoleAsync(row.IsTeam, row.PrincipalId, row.PrincipalDisplay, row.PrincipalBusinessUnitId,
                    row.PrincipalBusinessUnitName, row.TargetId, row.TargetDisplay, ct);
                break;
            case var a when a == ImportActions.RemoveRole.ToLowerInvariant():
                await service.RemoveRootRoleAsync(row.IsTeam, row.PrincipalId, row.PrincipalDisplay, row.PrincipalBusinessUnitId,
                    row.TargetId, row.TargetDisplay, ct);
                break;
            case var a when a == ImportActions.AddToTeam.ToLowerInvariant():
                await service.AddTeamMembersAsync(row.TargetId, [row.PrincipalId], row.TargetDisplay, row.PrincipalDisplay, null, ct);
                break;
            default:
                await service.RemoveTeamMembersAsync(row.TargetId, [row.PrincipalId], row.TargetDisplay, row.PrincipalDisplay, null, ct);
                break;
        }
    }
}
