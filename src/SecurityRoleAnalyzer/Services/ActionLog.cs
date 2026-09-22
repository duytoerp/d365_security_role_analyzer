using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecurityRoleAnalyzer.Services;

/// <summary>Loại thao tác hoàn tác được cho một mục lịch sử.</summary>
public enum UndoKind
{
    None,
    AssignRole,
    RemoveRole,
    AddTeamMembers,
    RemoveTeamMembers,
    RestorePrivilegeBackup,
    DeleteRole,
    AssociateAppRoles,
    DisassociateAppRoles,
    AssociateFieldProfile,
    DisassociateFieldProfile,
    SetFormRoles,
}

/// <summary>Dữ liệu cần để thực hiện thao tác ngược lại.</summary>
public sealed class UndoInfo
{
    public UndoKind Kind { get; set; }
    /// <summary>"systemuser" hoặc "team".</summary>
    public string PrincipalType { get; set; } = "";
    public Guid PrincipalId { get; set; }
    /// <summary>Id bản sao role (theo BU) dùng khi gán/gỡ.</summary>
    public Guid RoleId { get; set; }
    public Guid TeamId { get; set; }
    public List<Guid> Ids { get; set; } = [];
    /// <summary>Id app / field security profile / role tùy loại.</summary>
    public Guid RecordId { get; set; }
    public string BackupFile { get; set; } = "";
}

public sealed class ActionLogEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTime Time { get; set; } = DateTime.Now;
    public string Environment { get; set; } = "";
    public string Operator { get; set; } = "";
    public string Action { get; set; } = "";
    public string Target { get; set; } = "";
    public string Detail { get; set; } = "";
    /// <summary>Id bản ghi bị thay đổi (form…) – để lọc lịch sử của riêng một đối tượng.</summary>
    public Guid? RecordId { get; set; }
    /// <summary>Trạng thái trước và sau thay đổi, dạng đọc được.</summary>
    public string Before { get; set; } = "";
    public string After { get; set; } = "";
    /// <summary>File sao lưu dữ liệu gốc trước khi sửa (nếu có).</summary>
    public string BackupFile { get; set; } = "";
    public bool Success { get; set; }
    public string Error { get; set; } = "";
    public UndoInfo? Undo { get; set; }
    /// <summary>Mục này là thao tác hoàn tác của mục có Id tương ứng.</summary>
    public Guid? UndoOf { get; set; }

    /// <summary>Thao tác lỗi giữa chừng: một phần thay đổi đã được ghi, cần hoàn tác để đưa về trạng thái cũ.</summary>
    public bool PartiallyApplied { get; set; }

    [JsonIgnore] public bool IsUndone { get; set; }

    [JsonIgnore]
    public string ResultText => Success
        ? (IsUndone ? "Thành công (đã hoàn tác)" : "Thành công")
        : (PartiallyApplied ? (IsUndone ? "Lỗi dở dang (đã hoàn tác)" : "⚠ Lỗi dở dang") : "Lỗi");

    /// <summary>
    /// Hoàn tác được khi thao tác thành công, hoặc khi thao tác lỗi nhưng đã kịp thay đổi dữ liệu –
    /// trường hợp này chính là lúc cần hoàn tác nhất.
    /// </summary>
    [JsonIgnore]
    public bool CanUndo => (Success || PartiallyApplied) && !IsUndone && UndoOf is null
                           && Undo is { Kind: not UndoKind.None };
}

/// <summary>Lưu lịch sử thao tác dạng JSON Lines tại %LOCALAPPDATA%\SecurityRoleAnalyzer\history.jsonl.</summary>
public static class ActionLogStore
{
    private static readonly object Sync = new();
    private static readonly JsonSerializerOptions Options = new() { Converters = { new JsonStringEnumConverter() } };

    /// <summary>Khóa liên tiến trình: nhiều cửa sổ app cùng ghi sẽ không xen kẽ dòng.</summary>
    private static readonly Mutex FileLock = new(false, @"Global\SecurityRoleAnalyzer.history");

    public static string FilePath => Path.Combine(ConnectionProfileStore.AppDataFolder, "history.jsonl");

    public static event Action<ActionLogEntry>? EntryAdded;

    /// <summary>Lỗi ghi nhật ký gần nhất; null nếu lần ghi cuối thành công.</summary>
    public static string? LastWriteError { get; private set; }

    /// <summary>Báo khi không ghi được nhật ký – mất dấu vết thao tác là chuyện phải cho người dùng biết.</summary>
    public static event Action<string>? WriteFailed;

    public static void Append(ActionLogEntry entry)
    {
        try
        {
            WithFileLock(() =>
            {
                Directory.CreateDirectory(ConnectionProfileStore.AppDataFolder);
                File.AppendAllText(FilePath, JsonSerializer.Serialize(entry, Options) + Environment.NewLine);
            });
            LastWriteError = null;
        }
        catch (Exception ex)
        {
            // Không để lỗi ghi log làm hỏng thao tác chính, nhưng phải báo ra ngoài.
            LastWriteError = ex.Message;
            WriteFailed?.Invoke($"Không ghi được nhật ký thao tác vào {FilePath}: {ex.Message}");
        }
        EntryAdded?.Invoke(entry);
    }

    private static void WithFileLock(Action action)
    {
        var acquired = false;
        try
        {
            try
            {
                acquired = FileLock.WaitOne(TimeSpan.FromSeconds(5));
            }
            catch (AbandonedMutexException)
            {
                // Tiến trình giữ khóa đã thoát đột ngột; khóa vẫn thuộc về ta.
                acquired = true;
            }

            lock (Sync)
                action();
        }
        finally
        {
            if (acquired)
                FileLock.ReleaseMutex();
        }
    }

    public static List<ActionLogEntry> Load()
    {
        var entries = new List<ActionLogEntry>();
        try
        {
            if (!File.Exists(FilePath))
                return entries;

            WithFileLock(() =>
            {
                foreach (var line in File.ReadLines(FilePath))
                {
                    if (string.IsNullOrWhiteSpace(line))
                        continue;
                    try
                    {
                        if (JsonSerializer.Deserialize<ActionLogEntry>(line, Options) is { } entry)
                            entries.Add(entry);
                    }
                    catch
                    {
                        // Bỏ qua dòng hỏng.
                    }
                }
            });
        }
        catch
        {
            return entries;
        }

        var undone = entries.Where(e => e.UndoOf is not null && e.Success).Select(e => e.UndoOf!.Value).ToHashSet();
        foreach (var entry in entries)
            entry.IsUndone = undone.Contains(entry.Id);

        return entries.OrderByDescending(e => e.Time).ToList();
    }
}

/// <summary>Cache metadata ra ổ đĩa theo môi trường để lần mở sau nhanh hơn.</summary>
public static class DiskCache
{
    public static readonly TimeSpan DefaultMaxAge = TimeSpan.FromHours(24);

    private static readonly JsonSerializerOptions Options = new() { Converters = { new JsonStringEnumConverter() } };

    private static string Folder(string environment)
    {
        var safe = string.Concat(environment.Select(c => char.IsLetterOrDigit(c) || c is '.' or '-' ? c : '_'));
        return Path.Combine(ConnectionProfileStore.AppDataFolder, "Cache", safe);
    }

    public static T? Load<T>(string environment, string name, TimeSpan maxAge) where T : class
    {
        try
        {
            var path = Path.Combine(Folder(environment), name + ".json");
            if (!File.Exists(path) || DateTime.Now - File.GetLastWriteTime(path) > maxAge)
                return null;
            return JsonSerializer.Deserialize<T>(File.ReadAllText(path), Options);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Sửa một mục trong cache còn hạn mà không làm mới hạn của cả file – các mục khác
    /// vẫn phải hết hạn đúng lúc để được tải lại từ Dataverse.
    /// </summary>
    public static void Update<T>(string environment, string name, Action<T> mutate) where T : class
    {
        try
        {
            var path = Path.Combine(Folder(environment), name + ".json");
            if (Load<T>(environment, name, DefaultMaxAge) is not { } value)
                return;

            var lastWrite = File.GetLastWriteTime(path);
            mutate(value);
            File.WriteAllText(path, JsonSerializer.Serialize(value, Options));
            File.SetLastWriteTime(path, lastWrite);
        }
        catch
        {
            // Cache là tùy chọn.
        }
    }

    public static void Save<T>(string environment, string name, T value)
    {
        try
        {
            var folder = Folder(environment);
            Directory.CreateDirectory(folder);
            File.WriteAllText(Path.Combine(folder, name + ".json"), JsonSerializer.Serialize(value, Options));
        }
        catch
        {
            // Cache là tùy chọn.
        }
    }

    public static void Clear(string environment)
    {
        try
        {
            var folder = Folder(environment);
            if (Directory.Exists(folder))
                Directory.Delete(folder, recursive: true);
        }
        catch
        {
            // Bỏ qua.
        }
    }
}
