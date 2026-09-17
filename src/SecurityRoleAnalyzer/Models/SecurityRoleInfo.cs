namespace SecurityRoleAnalyzer.Models;

public sealed class SecurityRoleInfo
{
    public Guid Id { get; init; }
    public string Name { get; init; } = "";
    public Guid BusinessUnitId { get; init; }
    public string BusinessUnitName { get; init; } = "";
    public bool IsManaged { get; init; }
    public DateTime? ModifiedOn { get; init; }

    public string ManagedText => IsManaged ? "Managed" : "Unmanaged";

    public override string ToString() => Name;
}

/// <summary>Bản sao của role trong từng Business Unit (Dataverse tự tạo cho mỗi BU).</summary>
public sealed record RoleCopy(Guid RoleId, Guid BusinessUnitId, string BusinessUnitName);

public sealed class EntityInfo
{
    public string LogicalName { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public bool IsCustom { get; init; }
    public bool IsIntersect { get; init; }
    public bool IsBpfEntity { get; init; }
}
