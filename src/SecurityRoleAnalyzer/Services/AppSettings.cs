using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecurityRoleAnalyzer.Services;

public enum AppTheme
{
    /// <summary>Theo thiết lập sáng/tối của Windows.</summary>
    System,
    Light,
    Dark,
}

/// <summary>Vị trí và kích thước một cửa sổ.</summary>
public sealed class WindowPlacement
{
    public double Left { get; set; }
    public double Top { get; set; }
    public double Width { get; set; }
    public double Height { get; set; }
    public bool Maximized { get; set; }

    public bool IsValid => Width >= 400 && Height >= 300;
}

/// <summary>
/// Thiết lập của ứng dụng, lưu tại %LOCALAPPDATA%\SecurityRoleAnalyzer\settings.json.
/// Khác với <see cref="ConnectionProfile"/> (thông tin kết nối), đây là trạng thái giao diện.
/// </summary>
public sealed class AppSettings
{
    public AppTheme Theme { get; set; } = AppTheme.System;
    /// <summary>Tên chế độ đang mở lần trước (giá trị của AppMode).</summary>
    public string LastMode { get; set; } = "";
    /// <summary>URL môi trường dùng lần trước, để chọn sẵn trong ô chuyển nhanh.</summary>
    public string LastEnvironmentUrl { get; set; } = "";
    /// <summary>Tự kết nối lại môi trường đó khi mở ứng dụng.</summary>
    public bool ReconnectOnStartup { get; set; }
    public Dictionary<string, WindowPlacement> Windows { get; set; } = [];

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private static string FilePath => Path.Combine(ConnectionProfileStore.AppDataFolder, "settings.json");

    public static AppSettings Current { get; private set; } = Load();

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath), Options) ?? new AppSettings();
        }
        catch (Exception ex)
        {
            ErrorLog.Write("Đọc settings.json", ex);
        }
        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(ConnectionProfileStore.AppDataFolder);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, Options));
            Current = this;
        }
        catch (Exception ex)
        {
            ErrorLog.Write("Ghi settings.json", ex);
        }
    }

    public WindowPlacement? PlacementOf(string window) => Windows.GetValueOrDefault(window);

    public void Remember(string window, WindowPlacement placement)
    {
        Windows[window] = placement;
        Save();
    }
}

/// <summary>
/// Ghi lỗi ra %LOCALAPPDATA%\SecurityRoleAnalyzer\errors.log kèm stack trace, để còn lần theo được
/// sau khi hộp thoại lỗi đã đóng.
/// </summary>
public static class ErrorLog
{
    private static readonly object Sync = new();
    private const long MaxBytes = 2 * 1024 * 1024;

    public static string FilePath => Path.Combine(ConnectionProfileStore.AppDataFolder, "errors.log");

    public static void Write(string context, Exception exception) =>
        Write(context, exception.ToString());

    public static void Write(string context, string detail)
    {
        try
        {
            lock (Sync)
            {
                Directory.CreateDirectory(ConnectionProfileStore.AppDataFolder);
                Rotate();
                File.AppendAllText(FilePath,
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {context}{Environment.NewLine}{detail}{Environment.NewLine}{Environment.NewLine}");
            }
        }
        catch
        {
            // Không còn nơi nào để báo lỗi ghi log.
        }
    }

    /// <summary>Giữ tối đa một file cũ để log không phình vô hạn.</summary>
    private static void Rotate()
    {
        var info = new FileInfo(FilePath);
        if (!info.Exists || info.Length < MaxBytes)
            return;

        var old = FilePath + ".1";
        File.Delete(old);
        File.Move(FilePath, old);
    }
}
