namespace SecurityRoleAnalyzer.Models;

#region Model-driven apps

public sealed class AppModuleInfo
{
    public Guid Id { get; init; }
    public Guid UniqueId { get; init; }
    public string Name { get; init; } = "";
    public string UniqueName { get; init; } = "";
    public string Description { get; init; } = "";
    public bool IsManaged { get; init; }
    public int State { get; init; }
    public int RoleCount { get; set; } = -1;

    public string StateText => State == 0 ? "Active" : "Inactive";
    public string ManagedText => IsManaged ? "Managed" : "Unmanaged";
    public string ListCaption => $"{UniqueName} · {ManagedText}" + (RoleCount >= 0 ? $" · {RoleCount} role" : "");

    public override string ToString() => Name;
}

public sealed class AppRoleRow
{
    public Guid RoleId { get; init; }
    public string Name { get; init; } = "";
    public bool IsManaged { get; init; }
    public int DirectUserCount { get; init; }
    public int TeamCount { get; init; }
    public int EffectiveUserCount { get; init; }

    public string ManagedText => IsManaged ? "Managed" : "Unmanaged";
}

/// <summary>User hoặc team (Type) truy cập được một đối tượng, kèm nguồn.</summary>
public sealed class PrincipalAccessRow
{
    public string Type { get; init; } = "User";
    public Guid Id { get; init; }
    public string Name { get; init; } = "";
    public string Detail { get; init; } = "";
    public string BusinessUnitName { get; init; } = "";
    public bool IsDisabled { get; init; }
    public PrivilegeDepth Depth { get; init; }
    public string Via { get; init; } = "";

    public string StatusText => IsDisabled ? "Disabled" : "Enabled";
    public string DepthText => Depth.ToText();
}

public sealed class AppAnalysis
{
    public required AppModuleInfo App { get; init; }
    public List<AppRoleRow> Roles { get; init; } = [];
    public List<PrincipalAccessRow> Users { get; init; } = [];
    public List<AnalysisFinding> Findings { get; init; } = [];
}

#endregion

#region Field security

public sealed class FieldSecurityProfileInfo
{
    public Guid Id { get; init; }
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public bool IsManaged { get; init; }

    public string ManagedText => IsManaged ? "Managed" : "Unmanaged";
    public override string ToString() => Name;
}

public sealed class FieldPermissionRow
{
    public string Entity { get; init; } = "";
    public string EntityDisplayName { get; init; } = "";
    public string Attribute { get; init; } = "";
    public string AttributeDisplayName { get; init; } = "";
    public bool CanRead { get; init; }
    public bool CanCreate { get; init; }
    public bool CanUpdate { get; init; }

    public string ReadText => CanRead ? "✔" : "✖";
    public string CreateText => CanCreate ? "✔" : "✖";
    public string UpdateText => CanUpdate ? "✔" : "✖";
}

public sealed class FieldProfileAnalysis
{
    public required FieldSecurityProfileInfo Profile { get; init; }
    public List<UserInfo> Users { get; init; } = [];
    public List<TeamInfo> Teams { get; init; } = [];
    /// <summary>Tổng user hiệu lực (trực tiếp + thành viên team).</summary>
    public List<PrincipalAccessRow> EffectiveUsers { get; init; } = [];
    public List<FieldPermissionRow> Permissions { get; init; } = [];
    public List<AnalysisFinding> Findings { get; init; } = [];
}

#endregion

#region Business units

public sealed class BusinessUnitInfo
{
    public Guid Id { get; init; }
    public string Name { get; init; } = "";
    public Guid? ParentId { get; init; }
    public bool IsDisabled { get; init; }

    public override string ToString() => Name;
}

public sealed class BusinessUnitNode
{
    public required BusinessUnitInfo Unit { get; init; }
    public BusinessUnitNode? Parent { get; init; }
    public List<BusinessUnitNode> Children { get; } = [];
    public int UserCount { get; set; }
    public int TeamCount { get; set; }
    public bool IsExpanded { get; set; }

    public int Depth => Parent is null ? 0 : Parent.Depth + 1;

    public IEnumerable<BusinessUnitNode> DescendantsAndSelf()
    {
        yield return this;
        foreach (var child in Children)
        foreach (var node in child.DescendantsAndSelf())
            yield return node;
    }

    public string Path => Parent is null ? Unit.Name : $"{Parent.Path} › {Unit.Name}";

    public string Caption => $"{Unit.Name}  ({UserCount} user · {TeamCount} team)" + (Unit.IsDisabled ? " · Disabled" : "");
}

public sealed class RoleUsageRow
{
    public Guid RoleId { get; init; }
    public string Name { get; init; } = "";
    public int DirectUserCount { get; init; }
    public int TeamUserCount { get; init; }
    public int TotalUserCount { get; init; }
}

public sealed class BusinessUnitAnalysis
{
    public required BusinessUnitNode Node { get; init; }
    public List<UserInfo> Users { get; init; } = [];
    public List<TeamInfo> Teams { get; init; } = [];
    public List<BusinessUnitInfo> Children { get; init; } = [];
    public List<RoleUsageRow> RoleUsage { get; init; } = [];
    public List<AnalysisFinding> Findings { get; init; } = [];
    public string ScopeText { get; init; } = "";
}

#endregion
