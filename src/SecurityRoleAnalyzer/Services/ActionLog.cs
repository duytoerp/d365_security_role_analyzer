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
    public bool Success { get; set; }
    public string Error { get; set; } = "";
    public UndoInfo? Undo { get; set; }
    /// <summary>Mục này là thao tác hoàn tác của mục có Id tương ứng.</summary>
    public Guid? UndoOf { get; set; }

    [JsonIgnore] public bool IsUndone { get; set; }
    [JsonIgnore] public string ResultText => Success ? (IsUndone ? "Thành công (đã hoàn tác)" : "Thành công") : "Lỗi";
    [JsonIgnore] public bool CanUndo => Success && !IsUndone && UndoOf is null && Undo is { Kind: not UndoKind.None };
}

/// <summary>Lưu lịch sử thao tác dạng JSON Lines tại %LOCALAPPDATA%\SecurityRoleAnalyzer\history.jsonl.</summary>
public static class ActionLogStore
{
    private static readonly object Sync = new();
    private static readonly JsonSerializerOptions Options = new() { Converters = { new JsonStringEnumConverter() } };

    public static string FilePath => Path.Combine(ConnectionProfileStore.AppDataFolder, "history.jsonl");

    public static event Action<ActionLogEntry>? EntryAdded;

    public static void Append(ActionLogEntry entry)
    {
        try
        {
            lock (Sync)
            {
                Directory.CreateDirectory(ConnectionProfileStore.AppDataFolder);
                File.AppendAllText(FilePath, JsonSerializer.Serialize(entry, Options) + Environment.NewLine);
            }
        }
        catch
        {
            // Không để lỗi ghi log làm hỏng thao tác chính.
        }
        EntryAdded?.Invoke(entry);
    }

    public static List<ActionLogEntry> Load()
    {
        var entries = new List<ActionLogEntry>();
        try
        {
            if (!File.Exists(FilePath))
                return entries;

            lock (Sync)
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
            }
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
