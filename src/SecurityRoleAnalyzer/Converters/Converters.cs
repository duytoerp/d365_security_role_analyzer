using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Converters;

/// <summary>Lấy brush theo key trong bảng màu đang dùng, để glyph quyền đổi màu theo theme.</summary>
internal static class ThemeBrush
{
    public static Brush Get(string key, Color fallback)
    {
        if (Application.Current?.TryFindResource(key) is Brush brush)
            return brush;

        var solid = new SolidColorBrush(fallback);
        solid.Freeze();
        return solid;
    }
}

internal static class DepthVisuals
{
    private static readonly Dictionary<PrivilegeDepth, (string Glyph, string Key, Color Fallback)> Map = new()
    {
        [PrivilegeDepth.None] = ("○", "DepthNoneBrush", Color.FromRgb(0xB8, 0xBE, 0xC7)),
        [PrivilegeDepth.User] = ("◔", "DepthUserBrush", Color.FromRgb(0xD9, 0x6C, 0x1E)),
        [PrivilegeDepth.BusinessUnit] = ("◑", "DepthBusinessUnitBrush", Color.FromRgb(0xB8, 0x8A, 0x00)),
        [PrivilegeDepth.ParentChild] = ("◕", "DepthParentChildBrush", Color.FromRgb(0x4C, 0x9A, 0x2A)),
        [PrivilegeDepth.Organization] = ("●", "DepthOrganizationBrush", Color.FromRgb(0x10, 0x7C, 0x10)),
    };

    public static Brush NotApplicable => ThemeBrush.Get("HintBrush", Color.FromRgb(0xD0, 0xD4, 0xDA));

    public static (string Glyph, Brush Brush) For(object? value)
    {
        var depth = value switch
        {
            PrivilegeCell { Exists: false } => (PrivilegeDepth?)null,
            PrivilegeCell cell => cell.Depth,
            PrivilegeDepth d => d,
            _ => null,
        };

        if (depth is null)
            return (value is PrivilegeCell ? "–" : "", NotApplicable);

        var (glyph, key, fallback) = Map[depth.Value];
        return (glyph, ThemeBrush.Get(key, fallback));
    }
}

/// <summary>PrivilegeCell / PrivilegeDepth → ký hiệu hình tròn giống trình chỉnh sửa role cổ điển.</summary>
public sealed class DepthGlyphConverter : IValueConverter
{
    public static readonly DepthGlyphConverter Instance = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => DepthVisuals.For(value).Glyph;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class DepthBrushConverter : IValueConverter
{
    public static readonly DepthBrushConverter Instance = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => DepthVisuals.For(value).Brush;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class SeverityBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        FindingSeverity.High => ThemeBrush.Get("SeverityHighBrush", Color.FromRgb(0xC5, 0x0F, 0x1F)),
        FindingSeverity.Medium => ThemeBrush.Get("SeverityMediumBrush", Color.FromRgb(0xD8, 0x6C, 0x00)),
        FindingSeverity.Low => ThemeBrush.Get("SeverityLowBrush", Color.FromRgb(0x9A, 0x7B, 0x00)),
        _ => ThemeBrush.Get("SeverityInfoBrush", Color.FromRgb(0x0F, 0x6C, 0xBD)),
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Ô đã chỉnh sửa (chưa lưu) → nền nhấn theo theme.</summary>
public sealed class ChangedBrushConverter : IValueConverter
{
    public static readonly ChangedBrushConverter Instance = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? ThemeBrush.Get("ChangedCellBrush", Color.FromRgb(0xFF, 0xE9, 0x9A)) : Brushes.Transparent;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Enum == ConverterParameter (tên giá trị) → bool; dùng cho RadioButton chọn chế độ.</summary>
public sealed class EnumEqualsConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is not null && string.Equals(value.ToString(), parameter as string, StringComparison.Ordinal);

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true && parameter is string name ? Enum.Parse(targetType, name) : Binding.DoNothing;
}

/// <summary>Enum == ConverterParameter → Visible, ngược lại Collapsed.</summary>
public sealed class EnumVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is not null && string.Equals(value.ToString(), parameter as string, StringComparison.Ordinal)
            ? Visibility.Visible
            : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;
}

/// <summary>bool → Visibility; ConverterParameter="Invert" để đảo ngược.</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var flag = value is true || (value is not null and not bool && value is not 0);
        if (string.Equals(parameter as string, "Invert", StringComparison.OrdinalIgnoreCase))
            flag = !flag;
        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
