using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace SecurityRoleAnalyzer.Models;

public sealed class PrivilegeDefinition
{
    public Guid Id { get; init; }
    public string Name { get; init; } = "";
    public AccessRight AccessRight { get; init; }
    /// <summary>Logical name entity; null nếu là privilege dạng "Miscellaneous".</summary>
    public string? EntityLogicalName { get; init; }
    public bool CanBeBasic { get; init; }
    public bool CanBeLocal { get; init; }
    public bool CanBeDeep { get; init; }
    public bool CanBeGlobal { get; init; }

    public string AllowedDepthsText
    {
        get
        {
            var parts = new List<string>();
            if (CanBeBasic) parts.Add("User");
            if (CanBeLocal) parts.Add("BU");
            if (CanBeDeep) parts.Add("Parent:Child");
            if (CanBeGlobal) parts.Add("Org");
            return string.Join(", ", parts);
        }
    }

    /// <summary>Các mức có thể gán (luôn gồm None) theo thứ tự tăng dần.</summary>
    public IReadOnlyList<PrivilegeDepth> AllowedDepthList
    {
        get
        {
            var list = new List<PrivilegeDepth> { PrivilegeDepth.None };
            if (CanBeBasic) list.Add(PrivilegeDepth.User);
            if (CanBeLocal) list.Add(PrivilegeDepth.BusinessUnit);
            if (CanBeDeep) list.Add(PrivilegeDepth.ParentChild);
            if (CanBeGlobal) list.Add(PrivilegeDepth.Organization);
            return list;
        }
    }

    /// <summary>Mức hợp lệ gần nhất (không vượt quá mức yêu cầu); None nếu không có.</summary>
    public PrivilegeDepth Clamp(PrivilegeDepth requested) =>
        AllowedDepthList.Where(d => d <= requested).DefaultIfEmpty(PrivilegeDepth.None).Max();

    /// <summary>Chuyển sang mức kế tiếp (hoặc trước đó) trong các mức cho phép, quay vòng.</summary>
    public PrivilegeDepth Cycle(PrivilegeDepth current, bool backward)
    {
        var list = AllowedDepthList;
        var index = Math.Max(0, list.ToList().IndexOf(current));
        index = backward ? (index - 1 + list.Count) % list.Count : (index + 1) % list.Count;
        return list[index];
    }
}

/// <summary>Một ô trong ma trận quyền entity.</summary>
public sealed class PrivilegeCell
{
    public static readonly PrivilegeCell NotApplicable = new() { Exists = false };

    public bool Exists { get; init; } = true;
    public PrivilegeDefinition? Definition { get; init; }
    public string PrivilegeName { get; init; } = "";
    public PrivilegeDepth Depth { get; init; }
    /// <summary>Mức đang lưu trên Dataverse (dùng để đánh dấu ô đã chỉnh sửa).</summary>
    public PrivilegeDepth OriginalDepth { get; init; }
    public string AllowedDepths { get; init; } = "";
    /// <summary>Các role cấp privilege này (dùng khi gộp quyền từ nhiều role, ví dụ quyền hiệu lực của team).</summary>
    public IReadOnlyList<string> SourceRoles { get; init; } = [];

    public bool IsChanged => Exists && Depth != OriginalDepth;

    /// <summary>Dùng để sort cột: -1 = không áp dụng.</summary>
    public int SortKey => Exists ? (int)Depth : -1;

    public string ToolTip => Exists
        ? $"{PrivilegeName}\nMức hiện tại: {Depth.ToText()}\nCác mức cho phép: {AllowedDepths}"
          + (IsChanged ? $"\nĐã sửa (trên hệ thống: {OriginalDepth.ToText()})" : "")
          + (SourceRoles.Count > 0 ? $"\nTừ role: {string.Join(", ", SourceRoles)}" : "")
        : "Entity không có privilege này";

    public string ExportText => Exists ? Depth.ToText() : "N/A";

    public PrivilegeCell WithDepth(PrivilegeDepth depth) => new()
    {
        Exists = Exists,
        Definition = Definition,
        PrivilegeName = PrivilegeName,
        Depth = depth,
        OriginalDepth = OriginalDepth,
        AllowedDepths = AllowedDepths,
        SourceRoles = SourceRoles,
    };
}

public sealed class EntityPrivilegeRow : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    public string LogicalName { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public bool IsCustom { get; init; }

    public PrivilegeCell Create { get; private set; } = PrivilegeCell.NotApplicable;
    public PrivilegeCell Read { get; private set; } = PrivilegeCell.NotApplicable;
    public PrivilegeCell Write { get; private set; } = PrivilegeCell.NotApplicable;
    public PrivilegeCell Delete { get; private set; } = PrivilegeCell.NotApplicable;
    public PrivilegeCell Append { get; private set; } = PrivilegeCell.NotApplicable;
    public PrivilegeCell AppendTo { get; private set; } = PrivilegeCell.NotApplicable;
    public PrivilegeCell Assign { get; private set; } = PrivilegeCell.NotApplicable;
    public PrivilegeCell Share { get; private set; } = PrivilegeCell.NotApplicable;

    public IEnumerable<PrivilegeCell> Cells => [Create, Read, Write, Delete, Append, AppendTo, Assign, Share];

    public bool HasAnyPrivilege => Cells.Any(c => c.Depth > PrivilegeDepth.None);

    public int GrantedCount => Cells.Count(c => c.Depth > PrivilegeDepth.None);

    public bool HasChanges => Cells.Any(c => c.IsChanged);

    /// <summary>Tên các role cấp ít nhất một privilege trên entity (mức chi tiết nằm trong tooltip của từng ô).</summary>
    public string SourcesText => string.Join(", ", Cells
        .SelectMany(c => c.SourceRoles)
        .Select(StripDepthSuffix)
        .Distinct()
        .Order());

    /// <summary>"Role A (Organization)" → "Role A".</summary>
    private static string StripDepthSuffix(string source)
    {
        var index = source.LastIndexOf(" (", StringComparison.Ordinal);
        return index > 0 && source.EndsWith(')') ? source[..index] : source;
    }

    public static readonly AccessRight[] StandardRights =
    [
        AccessRight.Create, AccessRight.Read, AccessRight.Write, AccessRight.Delete,
        AccessRight.Append, AccessRight.AppendTo, AccessRight.Assign, AccessRight.Share,
    ];

    public PrivilegeCell Get(AccessRight right) => right switch
    {
        AccessRight.Create => Create,
        AccessRight.Read => Read,
        AccessRight.Write => Write,
        AccessRight.Delete => Delete,
        AccessRight.Append => Append,
        AccessRight.AppendTo => AppendTo,
        AccessRight.Assign => Assign,
        AccessRight.Share => Share,
        _ => PrivilegeCell.NotApplicable,
    };

    /// <summary>Gán ô theo access right; trả về false nếu access right không thuộc 8 cột chuẩn.</summary>
    public bool TrySet(AccessRight right, PrivilegeCell cell)
    {
        if (!StandardRights.Contains(right))
            return false;

        // Nếu entity có nhiều privilege cùng access right, giữ mức cao nhất.
        var current = Get(right);
        if (current.Exists && current.Depth >= cell.Depth)
            return true;

        Replace(right, cell);
        return true;
    }

    /// <summary>Thay ô (khi người dùng chỉnh sửa) và thông báo cho giao diện.</summary>
    public void Replace(AccessRight right, PrivilegeCell cell)
    {
        switch (right)
        {
            case AccessRight.Create: Create = cell; break;
            case AccessRight.Read: Read = cell; break;
            case AccessRight.Write: Write = cell; break;
            case AccessRight.Delete: Delete = cell; break;
            case AccessRight.Append: Append = cell; break;
            case AccessRight.AppendTo: AppendTo = cell; break;
            case AccessRight.Assign: Assign = cell; break;
            case AccessRight.Share: Share = cell; break;
            default: return;
        }
        OnPropertyChanged(right.ToString());
        OnPropertyChanged(nameof(HasAnyPrivilege));
        OnPropertyChanged(nameof(HasChanges));
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class MiscPrivilegeRow : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    public PrivilegeDefinition? Definition { get; init; }
    public string Name { get; init; } = "";
    public string Entity { get; init; } = "";
    public PrivilegeDepth OriginalDepth { get; init; }
    public string AllowedDepths { get; init; } = "";
    public IReadOnlyList<string> SourceRoles { get; init; } = [];

    public PrivilegeDepth Depth
    {
        get;
        set
        {
            if (field == value)
                return;
            field = value;
            foreach (var name in new[] { nameof(Depth), nameof(DepthText), nameof(IsGranted), nameof(IsChanged) })
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public string SourcesText => string.Join(", ", SourceRoles);
    public bool IsGranted => Depth > PrivilegeDepth.None;
    public bool IsChanged => Depth != OriginalDepth;
    public string DepthText => Depth.ToText();
}

public sealed class PrivilegeDiffRow
{
    public string Entity { get; init; } = "";
    public string EntityDisplayName { get; init; } = "";
    public string Privilege { get; init; } = "";
    public PrivilegeDepth DepthA { get; init; }
    public PrivilegeDepth DepthB { get; init; }

    public bool IsDifferent => DepthA != DepthB;
    public string DepthAText => DepthA.ToText();
    public string DepthBText => DepthB.ToText();

    public string Status => (DepthA, DepthB) switch
    {
        var (a, b) when a == b => "Giống nhau",
        (PrivilegeDepth.None, _) => "Chỉ có ở Role B",
        (_, PrivilegeDepth.None) => "Chỉ có ở Role A",
        var (a, b) when a > b => "Role A rộng hơn",
        _ => "Role B rộng hơn",
    };
}
