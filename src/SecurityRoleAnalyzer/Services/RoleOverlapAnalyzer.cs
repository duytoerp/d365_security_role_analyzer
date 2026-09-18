using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>Một cặp role có tập privilege chồng lấn nhiều, ứng viên để gộp hoặc dọn bớt.</summary>
public sealed class RoleOverlapRow
{
    public required SecurityRoleInfo RoleA { get; init; }
    public required SecurityRoleInfo RoleB { get; init; }
    public int SharedCount { get; init; }
    public int OnlyInA { get; init; }
    public int OnlyInB { get; init; }
    /// <summary>Jaccard: phần chung / tổng hợp, 0–1.</summary>
    public double Similarity { get; init; }
    public int UsersA { get; init; }
    public int UsersB { get; init; }

    public string NameA => RoleA.Name;
    public string NameB => RoleB.Name;
    public string SimilarityText => $"{Similarity:P0}";

    /// <summary>A chứa trọn B (hoặc ngược lại) thì role nhỏ hơn là thừa.</summary>
    public bool IsSubset => OnlyInA == 0 || OnlyInB == 0;

    public string Suggestion => Similarity >= 1
        ? "Hai role giống hệt nhau – nên giữ một"
        : OnlyInB == 0
            ? $"\"{NameB}\" nằm trọn trong \"{NameA}\" – user chỉ cần role lớn hơn"
            : OnlyInA == 0
                ? $"\"{NameA}\" nằm trọn trong \"{NameB}\" – user chỉ cần role lớn hơn"
                : "Trùng lặp nhiều – cân nhắc tách phần chung thành một role riêng";
}

/// <summary>
/// So sánh privilege của mọi role trong môi trường để tìm role trùng nhau hoặc chứa nhau.
/// Dùng để dọn bớt role thay vì phải mở từng cặp bằng công cụ so sánh 2 role.
/// </summary>
public static class RoleOverlapAnalyzer
{
    public static List<RoleOverlapRow> Find(AccessIndex index, double minimumSimilarity)
    {
        var sets = new Dictionary<Guid, HashSet<Guid>>();
        foreach (var role in index.Roles)
        {
            var granted = index.RolePrivileges.GetValueOrDefault(role.Id, [])
                .Where(p => p.Value > PrivilegeDepth.None)
                .Select(p => p.Key)
                .ToHashSet();
            if (granted.Count > 0)
                sets[role.Id] = granted;
        }

        var roles = index.Roles.Where(r => sets.ContainsKey(r.Id)).ToList();
        var userCount = roles.ToDictionary(r => r.Id, r => index.EffectiveUsersOf(r.Id).Select(u => u.UserId).Distinct().Count());

        var rows = new List<RoleOverlapRow>();
        for (var i = 0; i < roles.Count; i++)
        for (var j = i + 1; j < roles.Count; j++)
        {
            var a = sets[roles[i].Id];
            var b = sets[roles[j].Id];

            // Bỏ sớm khi kích thước chênh nhau quá nhiều để không phải giao tập.
            var maxPossible = (double)Math.Min(a.Count, b.Count) / Math.Max(a.Count, b.Count);
            if (maxPossible < minimumSimilarity)
                continue;

            var shared = a.Count <= b.Count ? a.Count(b.Contains) : b.Count(a.Contains);
            var union = a.Count + b.Count - shared;
            var similarity = union == 0 ? 0 : (double)shared / union;
            if (similarity < minimumSimilarity)
                continue;

            rows.Add(new RoleOverlapRow
            {
                RoleA = roles[i],
                RoleB = roles[j],
                SharedCount = shared,
                OnlyInA = a.Count - shared,
                OnlyInB = b.Count - shared,
                Similarity = similarity,
                UsersA = userCount.GetValueOrDefault(roles[i].Id),
                UsersB = userCount.GetValueOrDefault(roles[j].Id),
            });
        }

        return rows.OrderByDescending(r => r.Similarity).ThenBy(r => r.NameA).ToList();
    }
}
