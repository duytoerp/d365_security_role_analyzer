namespace SecurityRoleAnalyzer.Models;

public static class ComponentCategory
{
    public const string App = "Model-driven App";
    public const string Form = "Form";
    public const string Dashboard = "Dashboard";
    public const string View = "View";
    public const string Chart = "Chart";
    public const string BusinessProcessFlow = "Business Process Flow";
    public const string CustomApi = "Custom API";

    public static readonly string[] All = [App, Form, Dashboard, View, Chart, BusinessProcessFlow, CustomApi];
}

public sealed class RoleComponent
{
    public string Category { get; init; } = "";
    public Guid Id { get; init; }
    public string Name { get; init; } = "";
    public string EntityLogicalName { get; init; } = "";
    public string EntityDisplayName { get; init; } = "";
    public string SubType { get; init; } = "";
    /// <summary>Diễn giải vì sao role truy cập được component này.</summary>
    public string AccessReason { get; init; } = "";
    /// <summary>true nếu component được gán trực tiếp cho role (không phải "mọi người").</summary>
    public bool IsDirect { get; init; }
    public bool IsManaged { get; init; }
    public string State { get; init; } = "";

    public string AssignmentText => IsDirect ? "Gán trực tiếp" : "Kế thừa / mọi người";
    public string ManagedText => IsManaged ? "Managed" : "Unmanaged";
}

public sealed class AnalysisFinding
{
    public FindingSeverity Severity { get; init; }
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";

    public string SeverityText => Severity.ToText();
}

public sealed class RoleAnalysis
{
    public required SecurityRoleInfo Role { get; init; }
    public List<RoleCopy> RoleCopies { get; init; } = [];
    public List<EntityPrivilegeRow> EntityRows { get; init; } = [];
    public List<MiscPrivilegeRow> MiscPrivileges { get; init; } = [];
    public List<RoleUser> Users { get; init; } = [];
    public List<RoleTeam> Teams { get; init; } = [];
    public List<RoleTeamUser> TeamUsers { get; init; } = [];
    public List<RoleComponent> Components { get; init; } = [];
    public List<AnalysisFinding> Findings { get; init; } = [];
    public List<string> Warnings { get; init; } = [];
}
