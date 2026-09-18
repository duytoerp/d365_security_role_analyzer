using System.Windows;

namespace SecurityRoleAnalyzer.Views;

// Code-behind tối thiểu cho các cửa sổ công cụ (logic nằm ở ViewModel tương ứng trong ToolViewModels.cs).
// WindowMemory: nhớ vị trí và kích thước giữa các lần mở.

public partial class LookupWindow : Window
{
    public LookupWindow()
    {
        InitializeComponent();
        WindowMemory.Attach(this);
    }
}

public partial class AccessReviewWindow : Window
{
    public AccessReviewWindow()
    {
        InitializeComponent();
        WindowMemory.Attach(this);
    }
}

public partial class BulkPrivilegeWindow : Window
{
    public BulkPrivilegeWindow()
    {
        InitializeComponent();
        WindowMemory.Attach(this);
    }
}

public partial class SnapshotWindow : Window
{
    public SnapshotWindow()
    {
        InitializeComponent();
        WindowMemory.Attach(this);
    }
}

public partial class ImportWindow : Window
{
    public ImportWindow()
    {
        InitializeComponent();
        WindowMemory.Attach(this);
    }
}

public partial class HistoryWindow : Window
{
    public HistoryWindow()
    {
        InitializeComponent();
        WindowMemory.Attach(this);
    }
}

public partial class RoleOverlapWindow : Window
{
    public RoleOverlapWindow()
    {
        InitializeComponent();
        WindowMemory.Attach(this);
    }
}

public partial class AuditWindow : Window
{
    public AuditWindow()
    {
        InitializeComponent();
        WindowMemory.Attach(this);
    }
}

public partial class RecordAccessWindow : Window
{
    public RecordAccessWindow()
    {
        InitializeComponent();
        WindowMemory.Attach(this);
    }
}
