using System.Windows;
using System.Windows.Controls;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.ViewModels;

namespace SecurityRoleAnalyzer.Views;

// Code-behind tối thiểu cho các view chế độ (logic nằm ở ViewModel).

public partial class UsersView : UserControl
{
    public UsersView() => InitializeComponent();
}

public partial class AppsView : UserControl
{
    public AppsView() => InitializeComponent();
}

public partial class FieldSecurityView : UserControl
{
    public FieldSecurityView() => InitializeComponent();
}

public partial class BusinessUnitsView : UserControl
{
    public BusinessUnitsView() => InitializeComponent();

    // TreeView.SelectedItem không bind được hai chiều.
    private void OnSelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (DataContext is BusinessUnitsViewModel vm && e.NewValue is BusinessUnitNode node)
            vm.SelectedNode = node;
    }
}
