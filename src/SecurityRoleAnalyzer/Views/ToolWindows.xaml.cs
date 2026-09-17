using System.Windows;

namespace SecurityRoleAnalyzer.Views;

// Code-behind tối thiểu cho các cửa sổ công cụ (logic nằm ở ViewModel tương ứng trong ToolViewModels.cs).

public partial class LookupWindow : Window
{
    public LookupWindow() => InitializeComponent();
}

public partial class AccessReviewWindow : Window
{
    public AccessReviewWindow() => InitializeComponent();
}

public partial class BulkPrivilegeWindow : Window
{
    public BulkPrivilegeWindow() => InitializeComponent();
}

public partial class SnapshotWindow : Window
{
    public SnapshotWindow() => InitializeComponent();
}

public partial class ImportWindow : Window
{
    public ImportWindow() => InitializeComponent();
}

public partial class HistoryWindow : Window
{
    public HistoryWindow() => InitializeComponent();
}
