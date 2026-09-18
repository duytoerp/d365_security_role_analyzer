using System.Windows;
using Microsoft.Win32;

namespace SecurityRoleAnalyzer.Services;

/// <summary>
/// Đổi bảng màu sáng/tối lúc chạy. Bảng màu nằm ở Themes/Light.xaml và Themes/Dark.xaml,
/// được nạp vào MergedDictionaries đầu tiên của App; mọi view tham chiếu bằng DynamicResource.
/// </summary>
public static class Theme
{
    // Pack URI có tên assembly: URI tương đối sẽ phân giải theo assembly khởi chạy nên hỏng
    // khi app được nạp từ tiến trình khác (ví dụ test host).
    private const string LightUri = "pack://application:,,,/SecurityRoleAnalyzer;component/Themes/Light.xaml";
    private const string DarkUri = "pack://application:,,,/SecurityRoleAnalyzer;component/Themes/Dark.xaml";

    public static AppTheme Selected { get; private set; } = AppTheme.System;

    /// <summary>Theme đang thực sự hiển thị (đã quy đổi System sang Light/Dark).</summary>
    public static bool IsDark { get; private set; }

    public static event Action? Changed;

    public static void Apply(AppTheme theme)
    {
        var application = Application.Current;
        if (application is null)
            return;

        Selected = theme;
        IsDark = theme == AppTheme.Dark || (theme == AppTheme.System && WindowsUsesDarkTheme());

        var uri = new Uri(IsDark ? DarkUri : LightUri, UriKind.Absolute);
        var dictionaries = application.Resources.MergedDictionaries;
        var replacement = new ResourceDictionary { Source = uri };

        var index = dictionaries.ToList().FindIndex(d =>
            d.Source is { } source &&
            (source.OriginalString.EndsWith("Light.xaml", StringComparison.OrdinalIgnoreCase)
             || source.OriginalString.EndsWith("Dark.xaml", StringComparison.OrdinalIgnoreCase)));

        if (index >= 0)
            dictionaries[index] = replacement;
        else
            dictionaries.Insert(0, replacement);

        Changed?.Invoke();
    }

    /// <summary>Windows đang ở chế độ tối hay không (AppsUseLightTheme = 0).</summary>
    public static bool WindowsUsesDarkTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int value && value == 0;
        }
        catch (Exception ex)
        {
            ErrorLog.Write("Đọc chế độ sáng/tối của Windows", ex);
            return false;
        }
    }

    public static string ToText(AppTheme theme) => theme switch
    {
        AppTheme.Light => "Sáng",
        AppTheme.Dark => "Tối",
        _ => "Theo Windows",
    };
}
