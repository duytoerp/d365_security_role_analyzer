using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Converters;

internal static class DepthVisuals
{
    public static readonly Brush NotApplicable = Freeze(new SolidColorBrush(Color.FromRgb(0xD0, 0xD4, 0xDA)));

    private static readonly Dictionary<PrivilegeDepth, (string Glyph, Brush Brush)> Map = new()
    {
        [PrivilegeDepth.None] = ("○", Freeze(new SolidColorBrush(Color.FromRgb(0xB8, 0xBE, 0xC7)))),
        [PrivilegeDepth.User] = ("◔", Freeze(new SolidColorBrush(Color.FromRgb(0xD9, 0x6C, 0x1E)))),
        [PrivilegeDepth.BusinessUnit] = ("◑", Freeze(new SolidColorBrush(Color.FromRgb(0xB8, 0x8A, 0x00)))),
        [PrivilegeDepth.ParentChild] = ("◕", Freeze(new SolidColorBrush(Color.FromRgb(0x4C, 0x9A, 0x2A)))),
        [PrivilegeDepth.Organization] = ("●", Freeze(new SolidColorBrush(Color.FromRgb(0x10, 0x7C, 0x10)))),
    };

    public static (string Glyph, Brush Brush) For(object? value) => value switch
    {
        PrivilegeCell { Exists: false } => ("–", NotApplicable),
        PrivilegeCell cell => Map[cell.Depth],
        PrivilegeDepth depth => Map[depth],
        _ => ("", NotApplicable),
    };

    private static Brush Freeze(Brush brush)
    {
        brush.Freeze();
        return brush;
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
    private static readonly Brush High = new SolidColorBrush(Color.FromRgb(0xC5, 0x0F, 0x1F));
    private static readonly Brush Medium = new SolidColorBrush(Color.FromRgb(0xD8, 0x6C, 0x00));
    private static readonly Brush Low = new SolidColorBrush(Color.FromRgb(0x9A, 0x7B, 0x00));
    private static readonly Brush Info = new SolidColorBrush(Color.FromRgb(0x0F, 0x6C, 0xBD));

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        FindingSeverity.High => High,
        FindingSeverity.Medium => Medium,
        FindingSeverity.Low => Low,
        _ => Info,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Ô đã chỉnh sửa (chưa lưu) → nền vàng nhạt.</summary>
public sealed class ChangedBrushConverter : IValueConverter
{
    public static readonly ChangedBrushConverter Instance = new();
    private static readonly Brush Changed = CreateFrozen(Color.FromRgb(0xFF, 0xE9, 0x9A));

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? Changed : Brushes.Transparent;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();

    private static Brush CreateFrozen(Color color)
    {
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        return brush;
    }
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
