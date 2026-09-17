namespace SecurityRoleAnalyzer.Models;

/// <summary>Mức quyền của privilege (giá trị trùng với privilegedepthmask trong Dataverse).</summary>
public enum PrivilegeDepth
{
    None = 0,
    User = 1,
    BusinessUnit = 2,
    ParentChild = 4,
    Organization = 8,
}

/// <summary>Giá trị privilege.accessright.</summary>
public enum AccessRight
{
    None = 0,
    Read = 1,
    Write = 2,
    Append = 4,
    AppendTo = 16,
    Create = 32,
    Delete = 65536,
    Share = 262144,
    Assign = 524288,
}

public enum FindingSeverity
{
    High,
    Medium,
    Low,
    Info,
}

public static class EnumText
{
    public static string ToText(this PrivilegeDepth depth) => depth switch
    {
        PrivilegeDepth.User => "User",
        PrivilegeDepth.BusinessUnit => "Business Unit",
        PrivilegeDepth.ParentChild => "Parent: Child BU",
        PrivilegeDepth.Organization => "Organization",
        _ => "None",
    };

    public static PrivilegeDepth FromMask(int mask)
    {
        if ((mask & 8) != 0) return PrivilegeDepth.Organization;
        if ((mask & 4) != 0) return PrivilegeDepth.ParentChild;
        if ((mask & 2) != 0) return PrivilegeDepth.BusinessUnit;
        if ((mask & 1) != 0) return PrivilegeDepth.User;
        return PrivilegeDepth.None;
    }

    public static string ToText(this FindingSeverity severity) => severity switch
    {
        FindingSeverity.High => "Cao",
        FindingSeverity.Medium => "Trung bình",
        FindingSeverity.Low => "Thấp",
        _ => "Thông tin",
    };
}
