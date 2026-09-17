using System.Windows;
using System.Windows.Controls;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Views;

public partial class ConnectionWindow : Window
{
    private string _connectionString = "";
    private ConnectionProfile _profile = new();

    public ConnectionWindow(ConnectionProfile? preset = null)
    {
        InitializeComponent();

        var profiles = ConnectionProfileStore.Load();
        UrlBox.ItemsSource = profiles;
        AppIdBox.Text = ConnectionProfile.DefaultAppId;
        RedirectUriBox.Text = ConnectionProfile.DefaultRedirectUri;
        var initial = preset is null ? profiles.FirstOrDefault() : profiles.FirstOrDefault(p => p.DisplayName == preset.DisplayName && p.AuthType == preset.AuthType);
        if (initial is not null)
            UrlBox.SelectedItem = initial;
        Loaded += (_, _) =>
        {
            if (SelectedAuthType == ConnectionAuthType.ClientSecret)
                SecretBox.Focus();
        };
    }

    public static (string ConnectionString, ConnectionProfile Profile)? Show(Window? owner, ConnectionProfile? preset = null)
    {
        var window = new ConnectionWindow(preset) { Owner = owner };
        return window.ShowDialog() == true ? (window._connectionString, window._profile) : null;
    }

    private ConnectionAuthType SelectedAuthType =>
        AuthTypeBox.SelectedItem is ComboBoxItem { Tag: string tag } && Enum.TryParse<ConnectionAuthType>(tag, out var type)
            ? type
            : ConnectionAuthType.OAuthInteractive;

    private void OnAuthTypeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsInitialized)
            return;

        var type = SelectedAuthType;
        UrlPanel.Visibility = type == ConnectionAuthType.ConnectionString ? Visibility.Collapsed : Visibility.Visible;
        OAuthPanel.Visibility = type == ConnectionAuthType.OAuthInteractive ? Visibility.Visible : Visibility.Collapsed;
        SecretPanel.Visibility = type == ConnectionAuthType.ClientSecret ? Visibility.Visible : Visibility.Collapsed;
        ConnectionStringPanel.Visibility = type == ConnectionAuthType.ConnectionString ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnProfileSelected(object sender, SelectionChangedEventArgs e)
    {
        if (UrlBox.SelectedItem is not ConnectionProfile profile)
            return;

        foreach (ComboBoxItem item in AuthTypeBox.Items)
        {
            if ((string)item.Tag == profile.AuthType.ToString())
                AuthTypeBox.SelectedItem = item;
        }
        UserNameBox.Text = profile.UserName;
        AppIdBox.Text = string.IsNullOrWhiteSpace(profile.AppId) ? ConnectionProfile.DefaultAppId : profile.AppId;
        RedirectUriBox.Text = string.IsNullOrWhiteSpace(profile.RedirectUri) ? ConnectionProfile.DefaultRedirectUri : profile.RedirectUri;
        ClientIdBox.Text = profile.ClientId;
        NameBox.Text = profile.Name;
        SaveSecretBox.IsChecked = profile.HasSavedSecret;
        if (profile.GetSecret() is { } secret)
            SecretBox.Password = secret;
    }

    private void OnConnect(object sender, RoutedEventArgs e)
    {
        var url = (UrlBox.SelectedItem as ConnectionProfile)?.Url ?? UrlBox.Text;
        if (UrlBox.SelectedItem is ConnectionProfile selected && !string.Equals(UrlBox.Text, selected.DisplayName, StringComparison.OrdinalIgnoreCase))
            url = UrlBox.Text;

        var profile = new ConnectionProfile
        {
            Name = NameBox.Text.Trim(),
            Url = NormalizeUrl(url),
            AuthType = SelectedAuthType,
            UserName = UserNameBox.Text.Trim(),
            AppId = AppIdBox.Text.Trim(),
            RedirectUri = RedirectUriBox.Text.Trim(),
            ClientId = ClientIdBox.Text.Trim(),
        };

        try
        {
            _connectionString = profile.BuildConnectionString(SecretBox.Password, ConnectionStringBox.Text);
            if (profile.AuthType == ConnectionAuthType.ClientSecret && SaveSecretBox.IsChecked == true)
                profile.SetSecret(SecretBox.Password);
            _profile = profile;
            DialogResult = true;
        }
        catch (ArgumentException ex)
        {
            MessageBox.Show(this, ex.Message, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static string NormalizeUrl(string url)
    {
        url = url.Trim().TrimEnd('/');
        if (url.Length > 0 && !url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            url = "https://" + url;
        return url;
    }
}
