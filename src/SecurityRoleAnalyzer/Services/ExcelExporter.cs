using ClosedXML.Excel;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

public sealed record ExportColumn<T>(string Header, Func<T, object?> Value, double? Width = null);

public static class ExcelExporter
{
    private static readonly Dictionary<string, XLColor> DepthColors = new()
    {
        ["User"] = XLColor.FromHtml("#FCE3CC"),
        ["Business Unit"] = XLColor.FromHtml("#FFF2B3"),
        ["Parent: Child BU"] = XLColor.FromHtml("#D8EFCB"),
        ["Organization"] = XLColor.FromHtml("#A9DBA8"),
    };

    public static void ExportRoleAnalysis(RoleAnalysis analysis, string path)
    {
        using var workbook = new XLWorkbook();
        var role = analysis.Role;

        var overview = workbook.Worksheets.Add("Tong quan");
        var info = new (string, object?)[]
        {
            ("Role", role.Name),
            ("Role Id", role.Id.ToString()),
            ("Business Unit", role.BusinessUnitName),
            ("Managed", role.ManagedText),
            ("Modified On", role.ModifiedOn),
            ("Entity có privilege", analysis.EntityRows.Count(r => r.HasAnyPrivilege)),
            ("Privilege khác được cấp", analysis.MiscPrivileges.Count(m => m.IsGranted)),
            ("User gán trực tiếp", analysis.Users.Select(u => u.Id).Distinct().Count()),
            ("Team", analysis.Teams.Select(t => t.Id).Distinct().Count()),
            ("User nhận role qua team", analysis.TeamUsers.Select(u => u.UserId).Distinct().Count()),
            ("Ngày xuất", DateTime.Now),
        };
        for (var i = 0; i < info.Length; i++)
        {
            overview.Cell(i + 1, 1).Value = info[i].Item1;
            overview.Cell(i + 1, 1).Style.Font.Bold = true;
            overview.Cell(i + 1, 2).Value = XLCellValue.FromObject(info[i].Item2);
        }

        var findingsStart = info.Length + 3;
        overview.Cell(findingsStart, 1).Value = "Phát hiện";
        overview.Cell(findingsStart, 1).Style.Font.Bold = true;
        overview.Cell(findingsStart, 1).Style.Font.FontSize = 13;
        WriteTable(overview, findingsStart + 1, analysis.Findings,
            new ExportColumn<AnalysisFinding>("Mức độ", f => f.SeverityText),
            new ExportColumn<AnalysisFinding>("Nội dung", f => f.Title),
            new ExportColumn<AnalysisFinding>("Chi tiết", f => f.Detail, 100));
        overview.Column(1).Width = 26;
        overview.Column(2).Width = 60;

        var entitySheet = AddSheet(workbook, "Quyen Entity", analysis.EntityRows.Where(r => r.HasAnyPrivilege),
            new ExportColumn<EntityPrivilegeRow>("Entity", r => r.DisplayName),
            new ExportColumn<EntityPrivilegeRow>("Logical Name", r => r.LogicalName),
            new ExportColumn<EntityPrivilegeRow>("Custom", r => r.IsCustom ? "Yes" : "No"),
            new ExportColumn<EntityPrivilegeRow>("Create", r => r.Create.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Read", r => r.Read.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Write", r => r.Write.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Delete", r => r.Delete.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Append", r => r.Append.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Append To", r => r.AppendTo.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Assign", r => r.Assign.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Share", r => r.Share.ExportText));
        ColorDepthCells(entitySheet);

        AddSheet(workbook, "Quyen khac", analysis.MiscPrivileges.Where(m => m.IsGranted),
            new ExportColumn<MiscPrivilegeRow>("Privilege", m => m.Name),
            new ExportColumn<MiscPrivilegeRow>("Entity", m => m.Entity),
            new ExportColumn<MiscPrivilegeRow>("Mức", m => m.DepthText));

        AddSheet(workbook, "Users", analysis.Users,
            new ExportColumn<RoleUser>("Họ tên", u => u.FullName),
            new ExportColumn<RoleUser>("Username", u => u.DomainName),
            new ExportColumn<RoleUser>("Email", u => u.Email),
            new ExportColumn<RoleUser>("Business Unit", u => u.BusinessUnitName),
            new ExportColumn<RoleUser>("Trạng thái", u => u.StatusText),
            new ExportColumn<RoleUser>("Cũng nhận qua team", u => u.AlsoViaTeam ? "Yes" : "No"));

        AddSheet(workbook, "Teams", analysis.Teams,
            new ExportColumn<RoleTeam>("Team", t => t.Name),
            new ExportColumn<RoleTeam>("Loại", t => t.TeamTypeText),
            new ExportColumn<RoleTeam>("Business Unit", t => t.BusinessUnitName),
            new ExportColumn<RoleTeam>("Default team", t => t.IsDefault ? "Yes" : "No"),
            new ExportColumn<RoleTeam>("Số thành viên", t => t.MemberCount));

        AddSheet(workbook, "Users qua Team", analysis.TeamUsers,
            new ExportColumn<RoleTeamUser>("Họ tên", u => u.FullName),
            new ExportColumn<RoleTeamUser>("Username", u => u.DomainName),
            new ExportColumn<RoleTeamUser>("Business Unit", u => u.BusinessUnitName),
            new ExportColumn<RoleTeamUser>("Team", u => u.TeamName),
            new ExportColumn<RoleTeamUser>("Trạng thái", u => u.StatusText),
            new ExportColumn<RoleTeamUser>("Cũng gán trực tiếp", u => u.AlsoDirect ? "Yes" : "No"));

        AddSheet(workbook, "Components", analysis.Components,
            new ExportColumn<RoleComponent>("Loại", c => c.Category),
            new ExportColumn<RoleComponent>("Tên", c => c.Name),
            new ExportColumn<RoleComponent>("Entity", c => c.EntityDisplayName),
            new ExportColumn<RoleComponent>("Logical Name", c => c.EntityLogicalName),
            new ExportColumn<RoleComponent>("Kiểu", c => c.SubType),
            new ExportColumn<RoleComponent>("Gán", c => c.AssignmentText),
            new ExportColumn<RoleComponent>("Lý do truy cập", c => c.AccessReason, 70),
            new ExportColumn<RoleComponent>("Trạng thái", c => c.State),
            new ExportColumn<RoleComponent>("Managed", c => c.ManagedText),
            new ExportColumn<RoleComponent>("Id", c => c.Id.ToString()));

        workbook.SaveAs(path);
    }

    public static void ExportTeamAnalysis(TeamAnalysis analysis, string path)
    {
        using var workbook = new XLWorkbook();
        var team = analysis.Team;

        var overview = workbook.Worksheets.Add("Tong quan");
        var info = new (string, object?)[]
        {
            ("Team", team.Name),
            ("Team Id", team.Id.ToString()),
            ("Loại team", team.TeamTypeText),
            ("Business Unit", team.BusinessUnitName),
            ("Default team", team.IsDefault ? "Yes" : "No"),
            ("Entra ID Object Id", team.EntraObjectId?.ToString() ?? ""),
            ("Administrator", team.AdministratorName),
            ("Mô tả", team.Description),
            ("Số role", analysis.Roles.Count),
            ("Số thành viên", analysis.Members.Count),
            ("Entity có quyền hiệu lực", analysis.EntityRows.Count(r => r.HasAnyPrivilege)),
            ("Ngày xuất", DateTime.Now),
        };
        for (var i = 0; i < info.Length; i++)
        {
            overview.Cell(i + 1, 1).Value = info[i].Item1;
            overview.Cell(i + 1, 1).Style.Font.Bold = true;
            overview.Cell(i + 1, 2).Value = XLCellValue.FromObject(info[i].Item2);
        }

        var findingsStart = info.Length + 3;
        overview.Cell(findingsStart, 1).Value = "Phát hiện";
        overview.Cell(findingsStart, 1).Style.Font.Bold = true;
        overview.Cell(findingsStart, 1).Style.Font.FontSize = 13;
        WriteTable(overview, findingsStart + 1, analysis.Findings,
            new ExportColumn<AnalysisFinding>("Mức độ", f => f.SeverityText),
            new ExportColumn<AnalysisFinding>("Nội dung", f => f.Title),
            new ExportColumn<AnalysisFinding>("Chi tiết", f => f.Detail, 100));
        overview.Column(1).Width = 26;
        overview.Column(2).Width = 60;

        AddSheet(workbook, "Security Roles", analysis.Roles,
            new ExportColumn<TeamRoleAssignment>("Role", r => r.Name),
            new ExportColumn<TeamRoleAssignment>("Business Unit", r => r.BusinessUnitName),
            new ExportColumn<TeamRoleAssignment>("Managed", r => r.ManagedText),
            new ExportColumn<TeamRoleAssignment>("Số entity có quyền", r => r.GrantedEntityCount),
            new ExportColumn<TeamRoleAssignment>("Số quyền khác", r => r.GrantedMiscCount),
            new ExportColumn<TeamRoleAssignment>("Role Id (gốc)", r => r.RootRoleId.ToString()));

        AddSheet(workbook, "Thanh vien", analysis.Members,
            new ExportColumn<TeamMember>("Họ tên", m => m.FullName),
            new ExportColumn<TeamMember>("Username", m => m.DomainName),
            new ExportColumn<TeamMember>("Email", m => m.Email),
            new ExportColumn<TeamMember>("Business Unit", m => m.BusinessUnitName),
            new ExportColumn<TeamMember>("Trạng thái", m => m.StatusText));

        var entitySheet = AddSheet(workbook, "Quyen hieu luc", analysis.EntityRows.Where(r => r.HasAnyPrivilege),
            new ExportColumn<EntityPrivilegeRow>("Entity", r => r.DisplayName),
            new ExportColumn<EntityPrivilegeRow>("Logical Name", r => r.LogicalName),
            new ExportColumn<EntityPrivilegeRow>("Create", r => r.Create.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Read", r => r.Read.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Write", r => r.Write.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Delete", r => r.Delete.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Append", r => r.Append.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Append To", r => r.AppendTo.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Assign", r => r.Assign.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Share", r => r.Share.ExportText),
            new ExportColumn<EntityPrivilegeRow>("Từ role", r => r.SourcesText, 60));
        ColorDepthCells(entitySheet);

        AddSheet(workbook, "Quyen khac", analysis.MiscPrivileges.Where(m => m.IsGranted),
            new ExportColumn<MiscPrivilegeRow>("Privilege", m => m.Name),
            new ExportColumn<MiscPrivilegeRow>("Entity", m => m.Entity),
            new ExportColumn<MiscPrivilegeRow>("Mức", m => m.DepthText),
            new ExportColumn<MiscPrivilegeRow>("Từ role", m => m.SourcesText, 60));

        AddSheet(workbook, "Apps", analysis.Apps,
            new ExportColumn<RoleComponent>("App", a => a.Name),
            new ExportColumn<RoleComponent>("Unique Name", a => a.SubType),
            new ExportColumn<RoleComponent>("Trạng thái", a => a.State),
            new ExportColumn<RoleComponent>("Managed", a => a.ManagedText));

        workbook.SaveAs(path);
    }

    public static void ExportComparison(string roleA, string roleB, IEnumerable<PrivilegeDiffRow> rows, string path)
    {
        using var workbook = new XLWorkbook();
        var sheet = AddSheet(workbook, "So sanh", rows,
            new ExportColumn<PrivilegeDiffRow>("Entity", r => r.EntityDisplayName),
            new ExportColumn<PrivilegeDiffRow>("Logical Name", r => r.Entity),
            new ExportColumn<PrivilegeDiffRow>("Privilege", r => r.Privilege),
            new ExportColumn<PrivilegeDiffRow>(Truncate("A: " + roleA), r => r.DepthAText),
            new ExportColumn<PrivilegeDiffRow>(Truncate("B: " + roleB), r => r.DepthBText),
            new ExportColumn<PrivilegeDiffRow>("Kết quả", r => r.Status));
        ColorDepthCells(sheet);
        workbook.SaveAs(path);
    }

    public static IXLWorksheet AddSheet<T>(XLWorkbook workbook, string name, IEnumerable<T> rows, params ExportColumn<T>[] columns)
    {
        var sheet = workbook.Worksheets.Add(name);
        WriteTable(sheet, 1, rows, columns);
        sheet.SheetView.FreezeRows(1);
        return sheet;
    }

    private static void WriteTable<T>(IXLWorksheet sheet, int startRow, IEnumerable<T> rows, params ExportColumn<T>[] columns)
    {
        for (var c = 0; c < columns.Length; c++)
        {
            var header = sheet.Cell(startRow, c + 1);
            header.Value = columns[c].Header;
            header.Style.Font.Bold = true;
            header.Style.Font.FontColor = XLColor.White;
            header.Style.Fill.BackgroundColor = XLColor.FromHtml("#0F6CBD");
        }

        var r = startRow + 1;
        foreach (var row in rows)
        {
            for (var c = 0; c < columns.Length; c++)
                sheet.Cell(r, c + 1).Value = XLCellValue.FromObject(columns[c].Value(row));
            r++;
        }

        var range = sheet.Range(startRow, 1, Math.Max(r - 1, startRow), columns.Length);
        range.SetAutoFilter();
        sheet.Columns(1, columns.Length).AdjustToContents(startRow, Math.Min(r, startRow + 500), 8, 60);
        for (var c = 0; c < columns.Length; c++)
        {
            if (columns[c].Width is { } width)
                sheet.Column(c + 1).Width = width;
        }
    }

    /// <summary>Sheet thông tin dạng "nhãn – giá trị" và danh sách phát hiện.</summary>
    public static IXLWorksheet AddInfoSheet(XLWorkbook workbook, string name, IEnumerable<(string Label, object? Value)> info, IEnumerable<AnalysisFinding> findings)
    {
        var sheet = workbook.Worksheets.Add(name);
        var items = info.ToList();
        for (var i = 0; i < items.Count; i++)
        {
            sheet.Cell(i + 1, 1).Value = items[i].Label;
            sheet.Cell(i + 1, 1).Style.Font.Bold = true;
            sheet.Cell(i + 1, 2).Value = XLCellValue.FromObject(items[i].Value);
            sheet.Cell(i + 1, 2).Style.Alignment.WrapText = true;
        }

        var findingList = findings.ToList();
        if (findingList.Count > 0)
        {
            var start = items.Count + 3;
            sheet.Cell(start, 1).Value = "Phát hiện";
            sheet.Cell(start, 1).Style.Font.Bold = true;
            WriteTable(sheet, start + 1, findingList,
                new ExportColumn<AnalysisFinding>("Mức độ", f => f.SeverityText),
                new ExportColumn<AnalysisFinding>("Nội dung", f => f.Title),
                new ExportColumn<AnalysisFinding>("Chi tiết", f => f.Detail, 100));
        }
        sheet.Column(1).Width = 26;
        sheet.Column(2).Width = 70;
        return sheet;
    }

    public static IXLWorksheet AddEntityPrivilegeSheet(XLWorkbook workbook, string name, IEnumerable<EntityPrivilegeRow> rows, bool includeSources)
    {
        var columns = new List<ExportColumn<EntityPrivilegeRow>>
        {
            new("Entity", r => r.DisplayName),
            new("Logical Name", r => r.LogicalName),
            new("Create", r => r.Create.ExportText),
            new("Read", r => r.Read.ExportText),
            new("Write", r => r.Write.ExportText),
            new("Delete", r => r.Delete.ExportText),
            new("Append", r => r.Append.ExportText),
            new("Append To", r => r.AppendTo.ExportText),
            new("Assign", r => r.Assign.ExportText),
            new("Share", r => r.Share.ExportText),
        };
        if (includeSources)
            columns.Add(new("Từ role", r => r.SourcesText, 60));
        var sheet = AddSheet(workbook, name, rows.Where(r => r.HasAnyPrivilege), columns.ToArray());
        ColorDepthCells(sheet);
        return sheet;
    }

    public static IXLWorksheet AddPrincipalSheet(XLWorkbook workbook, string name, IEnumerable<PrincipalAccessRow> rows) =>
        AddSheet(workbook, name, rows,
            new ExportColumn<PrincipalAccessRow>("Loại", r => r.Type),
            new ExportColumn<PrincipalAccessRow>("Tên", r => r.Name),
            new ExportColumn<PrincipalAccessRow>("Chi tiết", r => r.Detail),
            new ExportColumn<PrincipalAccessRow>("Business Unit", r => r.BusinessUnitName),
            new ExportColumn<PrincipalAccessRow>("Trạng thái", r => r.StatusText),
            new ExportColumn<PrincipalAccessRow>("Mức", r => r.Depth == PrivilegeDepth.None ? "" : r.DepthText),
            new ExportColumn<PrincipalAccessRow>("Nguồn", r => r.Via, 60));

    public static IXLWorksheet AddUserSheet(XLWorkbook workbook, string name, IEnumerable<UserInfo> users) =>
        AddSheet(workbook, name, users,
            new ExportColumn<UserInfo>("Họ tên", u => u.FullName),
            new ExportColumn<UserInfo>("Username", u => u.DomainName),
            new ExportColumn<UserInfo>("Email", u => u.Email),
            new ExportColumn<UserInfo>("Business Unit", u => u.BusinessUnitName),
            new ExportColumn<UserInfo>("Access mode", u => u.AccessModeText),
            new ExportColumn<UserInfo>("Trạng thái", u => u.StatusText));

    /// <summary>Ma trận user (dòng) × role (cột): D = trực tiếp, T = qua team, D+T = cả hai.</summary>
    public static IXLWorksheet AddUserRoleMatrix(XLWorkbook workbook, string name, AccessIndex index)
    {
        var sheet = workbook.Worksheets.Add(name.Length > 31 ? name[..31] : name);
        var roles = index.Roles.Where(r => index.EffectiveUsersOf(r.Id).Any()).OrderBy(r => r.Name).ToList();
        string[] fixedHeaders = ["Họ tên", "Username", "Business Unit", "Trạng thái"];
        for (var c = 0; c < fixedHeaders.Length; c++)
            sheet.Cell(1, c + 1).Value = fixedHeaders[c];
        for (var c = 0; c < roles.Count; c++)
        {
            var cell = sheet.Cell(1, fixedHeaders.Length + c + 1);
            cell.Value = roles[c].Name;
            cell.Style.Alignment.TextRotation = 90;
        }
        var header = sheet.Range(1, 1, 1, fixedHeaders.Length + roles.Count);
        header.Style.Font.Bold = true;
        header.Style.Fill.BackgroundColor = XLColor.FromHtml("#0F6CBD");
        header.Style.Font.FontColor = XLColor.White;

        var row = 2;
        foreach (var user in index.Users.OrderBy(u => u.FullName))
        {
            var effective = index.EffectiveRolesOf(user.Id).ToList();
            if (effective.Count == 0)
                continue;
            sheet.Cell(row, 1).Value = user.FullName;
            sheet.Cell(row, 2).Value = user.DomainName;
            sheet.Cell(row, 3).Value = user.BusinessUnitName;
            sheet.Cell(row, 4).Value = user.StatusText;
            for (var c = 0; c < roles.Count; c++)
            {
                var direct = effective.Any(e => e.RoleId == roles[c].Id && e.TeamId is null);
                var team = effective.Any(e => e.RoleId == roles[c].Id && e.TeamId is not null);
                if (!direct && !team)
                    continue;
                var cell = sheet.Cell(row, fixedHeaders.Length + c + 1);
                cell.Value = direct && team ? "D+T" : direct ? "D" : "T";
                cell.Style.Fill.BackgroundColor = direct ? XLColor.FromHtml("#A9DBA8") : XLColor.FromHtml("#D8EFCB");
                cell.Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
            }
            row++;
        }

        sheet.Columns(1, fixedHeaders.Length).AdjustToContents(1, Math.Min(row, 300), 8, 45);
        sheet.Columns(fixedHeaders.Length + 1, fixedHeaders.Length + Math.Max(roles.Count, 1)).Width = 4.5;
        sheet.Row(1).Height = 160;
        sheet.SheetView.Freeze(1, 2);
        return sheet;
    }

    private static void ColorDepthCells(IXLWorksheet sheet)
    {
        foreach (var cell in sheet.CellsUsed())
        {
            if (cell.Address.RowNumber > 1 && DepthColors.TryGetValue(cell.GetString(), out var color))
                cell.Style.Fill.BackgroundColor = color;
        }
    }

    private static string Truncate(string text) => text.Length > 60 ? text[..60] : text;
}
