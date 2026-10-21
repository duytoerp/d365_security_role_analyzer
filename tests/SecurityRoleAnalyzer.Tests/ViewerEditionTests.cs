using System.IO;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Tests;

public class ViewerEditionTests
{
    [Fact]
    public async Task Viewer_edition_rejects_writes_before_touching_dataverse()
    {
        var previous = AppEdition.IsReadOnly;
        AppEdition.IsReadOnly = true;
        try
        {
            // Không có ServiceClient: nếu chốt chặn để lọt thì thao tác sẽ lỗi NullReference thay vì ReadOnlyEditionException.
            var service = (DataverseService)RuntimeHelpers.GetUninitializedObject(typeof(DataverseService));

            await Assert.ThrowsAsync<ReadOnlyEditionException>(() => service.DeleteRoleAsync(Guid.NewGuid(), "Sales"));
            await Assert.ThrowsAsync<ReadOnlyEditionException>(() =>
                service.AddTeamMembersAsync(Guid.NewGuid(), [Guid.NewGuid()], "Team", "User"));
        }
        finally
        {
            AppEdition.IsReadOnly = previous;
        }
    }

    /// <summary>
    /// Bản Viewer chỉ chặn ở <c>LoggedAsync</c> trong DataverseService.Changes.cs, nên mọi lệnh ghi lên Dataverse
    /// phải nằm trong file đó. Test này bắt lỗi khi ai đó thêm lệnh ghi ở chỗ khác.
    /// </summary>
    [Fact]
    public void Dataverse_writes_only_live_in_the_guarded_changes_file()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "SecurityRoleAnalyzer.slnx")))
            root = root.Parent;
        Assert.NotNull(root);

        var writeCall = new Regex(
            @"\.(Create|Update|Delete|Associate|Disassociate|Upsert)Async\s*\(|new\s+[\w.]*(Privileges?Role|MembersTeam|Assign|SetState|Upsert|Merge|GrantAccess|ModifyAccess|RevokeAccess|PublishXml|PublishAllXml|ExecuteMultiple|ExecuteTransaction|Create|Update|Delete)Request\b");
        var source = Path.Combine(root!.FullName, "src", "SecurityRoleAnalyzer");
        var offenders = Directory.EnumerateFiles(source, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                        && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                        && Path.GetFileName(f) != "DataverseService.Changes.cs")
            .SelectMany(f => File.ReadLines(f).Select((line, i) => (f, i, line)))
            .Where(x => writeCall.IsMatch(x.line))
            .Select(x => $"{Path.GetRelativePath(source, x.f)}:{x.i + 1}: {x.line.Trim()}")
            .ToList();

        Assert.Empty(offenders);
    }
}
