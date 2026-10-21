using System.Windows;

namespace SecurityRoleAnalyzer.Services;

/// <summary>
/// Phiên bản đang chạy. Bản Viewer (build với <c>-p:Edition=Viewer</c>) bị khóa chỉ xem ngay lúc biên dịch:
/// các nút thay đổi dữ liệu bị ẩn và <see cref="DataverseService"/> từ chối mọi thao tác ghi.
/// </summary>
public static class AppEdition
{
#if VIEWER
    public static bool IsReadOnly { get; internal set; } = true;
#else
    public static bool IsReadOnly { get; internal set; }
#endif

    public static string DisplayName => IsReadOnly ? "Viewer (chỉ xem)" : "";

    /// <summary>Dùng trong XAML cho các nút/menu thay đổi dữ liệu.</summary>
    public static Visibility WriteVisibility => IsReadOnly ? Visibility.Collapsed : Visibility.Visible;

    public static void EnsureCanModify()
    {
        if (IsReadOnly)
            throw new ReadOnlyEditionException();
    }
}

public sealed class ReadOnlyEditionException()
    : InvalidOperationException("Đây là bản Viewer (chỉ xem): không được phép thay đổi dữ liệu trên Dataverse.");
