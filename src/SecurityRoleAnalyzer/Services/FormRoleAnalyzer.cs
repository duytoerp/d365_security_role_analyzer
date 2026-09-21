using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>
/// Chiều ngược của phân tích component: mỗi form/dashboard đang được mở cho những security role nào.
/// Đây chính là nội dung màn hình "Form settings → Security roles" của D365, đọc từ
/// <c>systemform.displayconditions</c>.
/// </summary>
public static class FormRoleAnalyzer
{
    /// <summary>
    /// Loại form gán được security role: 0 Dashboard, 2 Main, 10 Interactive Dashboard,
    /// 12 Main-Interactive, 103 Power BI Dashboard. Quick View (6) và Quick Create (7) thì không.
    /// </summary>
    private static readonly HashSet<int> RoleScopedTypes = [0, 2, 10, 12, 103];

    public static bool IsRoleScoped(int formType) => RoleScopedTypes.Contains(formType);

    public static string TypeText(int type) => type switch
    {
        0 => "Dashboard",
        2 => "Main",
        6 => "Quick View",
        7 => "Quick Create",
        10 => "Interactive Dashboard",
        12 => "Main - Interactive",
        103 => "Power BI Dashboard",
        _ => type.ToString(),
    };

    public static List<FormRoleRow> Build(
        IEnumerable<DataverseService.FormInfo> forms,
        RoleDirectory directory,
        IReadOnlyDictionary<string, EntityInfo>? metadata = null)
    {
        var rows = new List<FormRoleRow>();

        foreach (var form in forms)
        {
            // Entity "none" là dashboard – không gắn với bảng nào.
            var logicalName = form.Entity is "none" or "" ? "" : form.Entity;
            var displayName = logicalName.Length > 0 && metadata?.TryGetValue(logicalName, out var info) == true
                ? info.DisplayName
                : logicalName;

            rows.Add(new FormRoleRow
            {
                FormId = form.Id,
                FormName = form.Name,
                EntityLogicalName = logicalName,
                EntityDisplayName = displayName,
                FormType = form.Type,
                FormTypeText = TypeText(form.Type),
                IsManaged = form.IsManaged,
                IsActive = form.ActivationState == 1,
                Visibility = VisibilityOf(form),
                Roles = ResolveRoles(form.RoleIds, directory),
            });
        }

        return rows
            .OrderBy(r => r.EntityDisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(r => r.FormName, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    private static FormVisibility VisibilityOf(DataverseService.FormInfo form) =>
        !IsRoleScoped(form.Type) ? FormVisibility.NotRoleScoped
        : form.DisplayConditionsUnreadable ? FormVisibility.Unreadable
        : form.VisibleToEveryone ? FormVisibility.Everyone
        : FormVisibility.SpecificRoles;

    /// <summary>
    /// displayconditions có thể tham chiếu bản sao role theo BU, nên quy hết về role gốc
    /// rồi bỏ trùng – một role chỉ hiện một dòng.
    /// </summary>
    private static List<FormRoleAssignment> ResolveRoles(IEnumerable<Guid> roleIds, RoleDirectory directory)
    {
        var seen = new HashSet<Guid>();
        var assignments = new List<FormRoleAssignment>();

        foreach (var id in roleIds)
        {
            var rootId = directory.Root(id);
            if (!seen.Add(rootId))
                continue;

            assignments.Add(directory.RoleById.TryGetValue(rootId, out var role)
                ? new FormRoleAssignment(rootId, role.Name, role.BusinessUnitName, false)
                : new FormRoleAssignment(rootId, "", "", true));
        }

        return assignments
            .OrderBy(r => r.IsMissing)
            .ThenBy(r => r.RoleName, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }
}
