using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>Dữ liệu mẫu để xem thử giao diện khi chạy với tham số --demo (không cần kết nối D365).</summary>
public static class DemoData
{
    public static (List<SecurityRoleInfo> Roles, RoleAnalysis Analysis) Create()
    {
        var bu = "contoso";
        var roles = new List<SecurityRoleInfo>
        {
            new() { Id = Guid.NewGuid(), Name = "Salesperson", BusinessUnitName = bu, IsManaged = true, ModifiedOn = DateTime.Now.AddDays(-12) },
            new() { Id = Guid.NewGuid(), Name = "Sales Manager", BusinessUnitName = bu, IsManaged = true, ModifiedOn = DateTime.Now.AddDays(-40) },
            new() { Id = Guid.NewGuid(), Name = "Customer Service Representative", BusinessUnitName = bu, IsManaged = true },
            new() { Id = Guid.NewGuid(), Name = "Contoso - Loan Officer", BusinessUnitName = bu, IsManaged = false, ModifiedOn = DateTime.Now.AddDays(-2) },
            new() { Id = Guid.NewGuid(), Name = "System Customizer", BusinessUnitName = bu, IsManaged = true },
        };
        var role = roles[3];

        var metadata = new Dictionary<string, EntityInfo>(StringComparer.OrdinalIgnoreCase);
        var catalog = new List<PrivilegeDefinition>();
        var granted = new Dictionary<Guid, PrivilegeDepth>();
        var random = new Random(7);

        void AddEntity(string logical, string display, bool custom, params PrivilegeDepth[] depths)
        {
            metadata[logical] = new EntityInfo { LogicalName = logical, DisplayName = display, IsCustom = custom };
            for (var i = 0; i < EntityPrivilegeRow.StandardRights.Length; i++)
            {
                var right = EntityPrivilegeRow.StandardRights[i];
                var id = Guid.NewGuid();
                catalog.Add(new PrivilegeDefinition
                {
                    Id = id, Name = $"prv{right}{logical}", AccessRight = right, EntityLogicalName = logical,
                    CanBeBasic = true, CanBeLocal = true, CanBeDeep = true, CanBeGlobal = true,
                });
                var depth = depths.Length > i ? depths[i] : PrivilegeDepth.None;
                if (depth > PrivilegeDepth.None)
                    granted[id] = depth;
            }
        }

        const PrivilegeDepth N = PrivilegeDepth.None, U = PrivilegeDepth.User, B = PrivilegeDepth.BusinessUnit,
            P = PrivilegeDepth.ParentChild, O = PrivilegeDepth.Organization;

        AddEntity("account", "Account", false, U, O, B, U, O, O, U, U);
        AddEntity("contact", "Contact", false, U, O, B, N, O, O, U, U);
        AddEntity("lead", "Lead", false, U, P, P, U, P, P, U, U);
        AddEntity("opportunity", "Opportunity", false, U, B, U, N, B, B, U, N);
        AddEntity("new_loanapplication", "Loan Application", true, U, P, U, O, P, P, U, U);
        AddEntity("new_collateral", "Collateral", true, U, B, B, U, B, B, N, N);
        AddEntity("new_creditscore", "Credit Score", true, N, O, N, N, N, O, N, N);
        AddEntity("systemuser", "User", false, N, O, U, N, O, O, N, N);
        AddEntity("role", "Security Role", false, N, O, N, N, N, N, N, N);
        AddEntity("new_loanprocess", "Loan Process (BPF)", true, O, O, O, O, O, O, N, N);
        AddEntity("invoice", "Invoice", false);
        AddEntity("campaign", "Campaign", false);

        foreach (var (name, depth) in new[] { ("prvExportToExcel", O), ("prvBulkDelete", O), ("prvGoMobile", O), ("prvPrint", O), ("prvMerge", N), ("prvActOnBehalfOfAnotherUser", N) })
        {
            var id = Guid.NewGuid();
            catalog.Add(new PrivilegeDefinition { Id = id, Name = name, CanBeGlobal = true });
            if (depth > N)
                granted[id] = depth;
        }

        var (entityRows, misc) = RoleAnalyzer.BuildPrivilegeRows(catalog, granted, metadata);

        string[] names = ["Nguyễn Văn An", "Trần Thị Bình", "Lê Minh Châu", "Phạm Quốc Dũng", "Hoàng Gia Hân", "Võ Thanh Khoa"];
        var users = names.Select((n, i) => new RoleUser
        {
            Id = Guid.NewGuid(), FullName = n, DomainName = $"user{i + 1}@contoso.vn", Email = $"user{i + 1}@contoso.vn",
            BusinessUnitName = i % 2 == 0 ? bu : "Hà Nội", IsDisabled = i == 5, AlsoViaTeam = i == 1,
        }).ToList();

        var teams = new List<RoleTeam>
        {
            new() { Id = Guid.NewGuid(), Name = "Loan Officers - HCM", TeamType = 0, BusinessUnitName = bu, MemberCount = 3 },
            new() { Id = Guid.NewGuid(), Name = "SG-D365-LoanOfficers", TeamType = 2, BusinessUnitName = bu, MemberCount = 2 },
        };

        var teamUsers = new List<RoleTeamUser>
        {
            new() { UserId = users[1].Id, FullName = users[1].FullName, DomainName = users[1].DomainName, TeamName = teams[0].Name, BusinessUnitName = bu, AlsoDirect = true },
            new() { UserId = Guid.NewGuid(), FullName = "Đặng Thu Trang", DomainName = "trang.dt@contoso.vn", TeamName = teams[0].Name, BusinessUnitName = bu },
            new() { UserId = Guid.NewGuid(), FullName = "Bùi Đức Long", DomainName = "long.bd@contoso.vn", TeamName = teams[0].Name, BusinessUnitName = bu },
            new() { UserId = Guid.NewGuid(), FullName = "Ngô Bảo Ngọc", DomainName = "ngoc.nb@contoso.vn", TeamName = teams[1].Name, BusinessUnitName = bu },
            new() { UserId = Guid.NewGuid(), FullName = "Đỗ Hải Nam", DomainName = "nam.dh@contoso.vn", TeamName = teams[1].Name, BusinessUnitName = bu },
        };

        var components = new List<RoleComponent>
        {
            new() { Category = ComponentCategory.App, Name = "Loan Management", SubType = "new_LoanManagement", AccessReason = "Role được thêm vào app (App security roles)", IsDirect = true, State = "Active" },
            new() { Category = ComponentCategory.App, Name = "Sales Hub", SubType = "msdynce_saleshub", AccessReason = "Role được thêm vào app (App security roles)", IsDirect = true, IsManaged = true, State = "Active" },
            new() { Category = ComponentCategory.Form, Name = "Loan Application - Officer", EntityLogicalName = "new_loanapplication", EntityDisplayName = "Loan Application", SubType = "Main", AccessReason = "Form được gán trực tiếp cho role (Form Order / Assign Security Roles)", IsDirect = true, State = "Active" },
            new() { Category = ComponentCategory.Form, Name = "Account", EntityLogicalName = "account", EntityDisplayName = "Account", SubType = "Main", AccessReason = "Form hiển thị cho mọi role (Display to everyone)", IsManaged = true, State = "Active" },
            new() { Category = ComponentCategory.Form, Name = "Quick Create Contact", EntityLogicalName = "contact", EntityDisplayName = "Contact", SubType = "Quick Create", AccessReason = "Loại form không phân quyền theo role – truy cập theo quyền Read entity", IsManaged = true, State = "Active" },
            new() { Category = ComponentCategory.Dashboard, Name = "Loan Officer Dashboard", SubType = "Dashboard", AccessReason = "Form được gán trực tiếp cho role (Form Order / Assign Security Roles)", IsDirect = true, State = "Active" },
            new() { Category = ComponentCategory.View, Name = "Active Loan Applications", EntityLogicalName = "new_loanapplication", EntityDisplayName = "Loan Application", SubType = "Public (mặc định)", AccessReason = "Có quyền Read entity – thấy dữ liệu mức Parent: Child BU", State = "Active" },
            new() { Category = ComponentCategory.View, Name = "My Active Accounts", EntityLogicalName = "account", EntityDisplayName = "Account", SubType = "Public", AccessReason = "Có quyền Read entity – thấy dữ liệu mức Organization", IsManaged = true, State = "Active" },
            new() { Category = ComponentCategory.Chart, Name = "Loans by Status", EntityLogicalName = "new_loanapplication", EntityDisplayName = "Loan Application", SubType = "System chart", AccessReason = "Có quyền Read entity – mức Parent: Child BU", State = "Active" },
            new() { Category = ComponentCategory.BusinessProcessFlow, Name = "Loan Approval Process", EntityLogicalName = "new_loanapplication", EntityDisplayName = "Loan Application", SubType = "new_loanprocess", AccessReason = "Có privilege trên BPF entity – Read: Organization, Create: Organization, Write: Organization", IsDirect = true, State = "Activated" },
            new() { Category = ComponentCategory.CustomApi, Name = "Calculate Credit Score", SubType = "new_CalculateCreditScore", AccessReason = "Role có privilege prvReadnew_creditscore", IsDirect = true, State = "Active" },
        };

        var analysis = new RoleAnalysis
        {
            Role = role,
            RoleCopies = [new RoleCopy(role.Id, Guid.Empty, bu), new RoleCopy(Guid.NewGuid(), Guid.Empty, "Hà Nội")],
            EntityRows = entityRows,
            MiscPrivileges = misc,
            Users = users,
            Teams = teams,
            TeamUsers = teamUsers,
            Components = components,
            Warnings = ["(Demo) Đây là dữ liệu mẫu – không kết nối tới Dynamics 365."],
        };
        analysis.Findings.AddRange(RoleAnalyzer.BuildFindings(analysis));
        return (roles, analysis);
    }

    public sealed record Extended(
        List<UserInfo> Users, UserAnalysis UserAnalysis,
        List<AppModuleInfo> Apps, AppAnalysis AppAnalysis,
        List<FieldSecurityProfileInfo> Profiles, FieldProfileAnalysis ProfileAnalysis,
        AccessIndex Index);

    /// <summary>Dữ liệu mẫu cho chế độ Users, Apps, Field Security và Business Units.</summary>
    public static Extended CreateExtended(List<SecurityRoleInfo> roles, List<TeamInfo> demoTeams, TeamAnalysis teamAnalysis)
    {
        var root = new BusinessUnitInfo { Id = Guid.NewGuid(), Name = "contoso" };
        var hn = new BusinessUnitInfo { Id = Guid.NewGuid(), Name = "Hà Nội", ParentId = root.Id };
        var hcm = new BusinessUnitInfo { Id = Guid.NewGuid(), Name = "Hồ Chí Minh", ParentId = root.Id };
        var q1 = new BusinessUnitInfo { Id = Guid.NewGuid(), Name = "HCM - Quận 1", ParentId = hcm.Id };
        var dn = new BusinessUnitInfo { Id = Guid.NewGuid(), Name = "Đà Nẵng", ParentId = root.Id, IsDisabled = true };
        List<BusinessUnitInfo> units = [root, hn, hcm, q1, dn];

        UserInfo User(string name, string login, BusinessUnitInfo bu, bool disabled = false, bool app = false, int roleCount = 0) => new()
        {
            Id = Guid.NewGuid(), FullName = name, DomainName = login, Email = login, BusinessUnitId = bu.Id, BusinessUnitName = bu.Name,
            IsDisabled = disabled, IsApplicationUser = app, AccessMode = app ? 4 : 0, RoleCount = roleCount, Title = app ? "" : "Chuyên viên",
        };

        List<UserInfo> users =
        [
            User("Trần Thị Bình", "binh.tt@contoso.vn", hcm, roleCount: 1),
            User("Nguyễn Văn An", "an.nv@contoso.vn", root, roleCount: 2),
            User("Lê Minh Châu", "chau.lm@contoso.vn", hn, roleCount: 1),
            User("Phạm Quốc Dũng", "dung.pq@contoso.vn", q1, roleCount: 0),
            User("Hoàng Gia Hân", "han.hg@contoso.vn", q1, roleCount: 1),
            User("Võ Thanh Khoa", "khoa.vt@contoso.vn", hn, disabled: true, roleCount: 1),
            User("Đặng Thu Trang", "trang.dt@contoso.vn", hcm, roleCount: 0),
            User("Integration – Loan API", "loan-api#app", root, app: true, roleCount: 1),
        ];

        var teams = demoTeams.Select((t, i) => new TeamInfo
        {
            Id = t.Id, Name = t.Name, TeamType = t.TeamType, IsDefault = t.IsDefault, EntraObjectId = t.EntraObjectId, RoleCount = t.RoleCount,
            BusinessUnitId = i switch { 1 => hn.Id, 2 => hcm.Id, _ => root.Id },
            BusinessUnitName = i switch { 1 => hn.Name, 2 => hcm.Name, _ => root.Name },
        }).ToList();

        var officer = roles.First(r => r.Name.Contains("Loan Officer"));
        var sales = roles.First(r => r.Name == "Salesperson");
        var manager = roles.First(r => r.Name == "Sales Manager");
        var customizer = roles.First(r => r.Name == "System Customizer");

        var index = new AccessIndex
        {
            Roles = roles,
            BusinessUnits = units,
            Users = users,
            Teams = teams,
            UserRoles = [(users[0].Id, officer.Id), (users[1].Id, manager.Id), (users[1].Id, sales.Id), (users[2].Id, sales.Id), (users[4].Id, officer.Id), (users[5].Id, sales.Id), (users[7].Id, customizer.Id)],
            TeamRoles = [(teams[2].Id, officer.Id), (teams[2].Id, sales.Id), (teams[1].Id, sales.Id), (teams[4].Id, officer.Id)],
            TeamMembers = [(teams[2].Id, users[0].Id), (teams[2].Id, users[6].Id), (teams[1].Id, users[2].Id), (teams[1].Id, users[5].Id), (teams[4].Id, users[4].Id)],
        };

        var binh = users[0];
        var userAnalysis = new UserAnalysis
        {
            User = binh,
            DirectRoles = [new() { AssignedRoleId = officer.Id, RootRoleId = officer.Id, Name = officer.Name, BusinessUnitName = hcm.Name, IsDirect = true, IsDuplicated = true }],
            Teams = [teams[2]],
            TeamRoles =
            [
                new() { AssignedRoleId = officer.Id, RootRoleId = officer.Id, Name = officer.Name, BusinessUnitName = hcm.Name, TeamId = teams[2].Id, TeamName = teams[2].Name, IsDuplicated = true },
                new() { AssignedRoleId = sales.Id, RootRoleId = sales.Id, Name = sales.Name, BusinessUnitName = hcm.Name, IsManaged = true, TeamId = teams[2].Id, TeamName = teams[2].Name },
            ],
            EntityRows = teamAnalysis.EntityRows,
            MiscPrivileges = teamAnalysis.MiscPrivileges,
            Apps = teamAnalysis.Apps,
            FieldProfiles =
            [
                new() { ProfileId = Guid.NewGuid(), Name = "Loan – Thông tin thu nhập", IsDirect = true },
                new() { ProfileId = Guid.NewGuid(), Name = "Sales – Giá vốn", TeamName = teams[2].Name },
            ],
            Warnings = ["(Demo) Đây là dữ liệu mẫu – không kết nối tới Dynamics 365."],
        };
        userAnalysis.Findings.AddRange(UserAnalyzer.BuildFindings(userAnalysis));

        var loanApp = new AppModuleInfo { Id = Guid.NewGuid(), Name = "Loan Management", UniqueName = "new_LoanManagement", RoleCount = 1 };
        List<AppModuleInfo> apps =
        [
            loanApp,
            new() { Id = Guid.NewGuid(), Name = "Sales Hub", UniqueName = "msdynce_saleshub", IsManaged = true, RoleCount = 2 },
            new() { Id = Guid.NewGuid(), Name = "Customer Service Hub", UniqueName = "msdynce_csh", IsManaged = true, RoleCount = 0 },
        ];
        var appAnalysis = AppAnalyzer.Analyze(loanApp, [(loanApp.Id, officer.Id), (loanApp.Id, customizer.Id)], index);

        var incomeProfile = new FieldSecurityProfileInfo { Id = Guid.NewGuid(), Name = "Loan – Thông tin thu nhập", Description = "Bảo mật thu nhập và điểm tín dụng" };
        List<FieldSecurityProfileInfo> profiles =
        [
            incomeProfile,
            new() { Id = Guid.NewGuid(), Name = "Sales – Giá vốn" },
            new() { Id = Guid.NewGuid(), Name = "System Administrator", IsManaged = true },
        ];
        var profileAnalysis = new FieldProfileAnalysis
        {
            Profile = incomeProfile,
            Users = [binh, users[4]],
            Teams = [teams[2]],
            EffectiveUsers =
            [
                new() { Id = binh.Id, Name = binh.FullName, Detail = binh.DomainName, BusinessUnitName = binh.BusinessUnitName, Via = $"Trực tiếp, Team {teams[2].Name}" },
                new() { Id = users[4].Id, Name = users[4].FullName, Detail = users[4].DomainName, BusinessUnitName = users[4].BusinessUnitName, Via = "Trực tiếp" },
                new() { Id = users[6].Id, Name = users[6].FullName, Detail = users[6].DomainName, BusinessUnitName = users[6].BusinessUnitName, Via = $"Team {teams[2].Name}" },
            ],
            Permissions =
            [
                new() { Entity = "new_loanapplication", EntityDisplayName = "Loan Application", Attribute = "new_monthlyincome", AttributeDisplayName = "Thu nhập hàng tháng", CanRead = true, CanUpdate = true },
                new() { Entity = "new_loanapplication", EntityDisplayName = "Loan Application", Attribute = "new_creditscore", AttributeDisplayName = "Điểm tín dụng", CanRead = true },
                new() { Entity = "contact", EntityDisplayName = "Contact", Attribute = "new_nationalid", AttributeDisplayName = "Số CCCD", CanRead = true, CanCreate = true, CanUpdate = true },
            ],
        };
        profileAnalysis.Findings.Add(new AnalysisFinding { Severity = FindingSeverity.Low, Title = "1 cột được cấp đủ Read/Create/Update", Detail = "Contact.Số CCCD" });

        return new Extended(users, userAnalysis, apps, appAnalysis, profiles, profileAnalysis, index);
    }

    public static (List<TeamInfo> Teams, TeamAnalysis Analysis) CreateTeams(List<SecurityRoleInfo> roles)
    {
        var teams = new List<TeamInfo>
        {
            new() { Id = Guid.NewGuid(), Name = "contoso", TeamType = 0, BusinessUnitName = "contoso", IsDefault = true, RoleCount = 0 },
            new() { Id = Guid.NewGuid(), Name = "Hà Nội", TeamType = 0, BusinessUnitName = "Hà Nội", IsDefault = true, RoleCount = 1 },
            new() { Id = Guid.NewGuid(), Name = "Loan Officers - HCM", TeamType = 0, BusinessUnitName = "contoso", AdministratorName = "Nguyễn Văn An", RoleCount = 2 },
            new() { Id = Guid.NewGuid(), Name = "Loan Review Access", TeamType = 1, BusinessUnitName = "contoso", RoleCount = 0 },
            new() { Id = Guid.NewGuid(), Name = "SG-D365-LoanOfficers", TeamType = 2, BusinessUnitName = "contoso", EntraObjectId = Guid.NewGuid(), RoleCount = 1 },
        };
        var team = teams[2];

        // Hai role với privilege chồng lấn để minh họa quyền hiệu lực gộp.
        var metadata = new Dictionary<string, EntityInfo>(StringComparer.OrdinalIgnoreCase);
        var catalog = new List<PrivilegeDefinition>();
        var officer = new Dictionary<Guid, PrivilegeDepth>();
        var sales = new Dictionary<Guid, PrivilegeDepth>();

        void AddEntity(string logical, string display, bool custom, PrivilegeDepth[] a, PrivilegeDepth[] b)
        {
            metadata[logical] = new EntityInfo { LogicalName = logical, DisplayName = display, IsCustom = custom };
            for (var i = 0; i < EntityPrivilegeRow.StandardRights.Length; i++)
            {
                var id = Guid.NewGuid();
                catalog.Add(new PrivilegeDefinition
                {
                    Id = id, Name = $"prv{EntityPrivilegeRow.StandardRights[i]}{logical}", AccessRight = EntityPrivilegeRow.StandardRights[i],
                    EntityLogicalName = logical, CanBeBasic = true, CanBeLocal = true, CanBeDeep = true, CanBeGlobal = true,
                });
                if (a.Length > i && a[i] > PrivilegeDepth.None) officer[id] = a[i];
                if (b.Length > i && b[i] > PrivilegeDepth.None) sales[id] = b[i];
            }
        }

        const PrivilegeDepth N = PrivilegeDepth.None, U = PrivilegeDepth.User, B = PrivilegeDepth.BusinessUnit,
            P = PrivilegeDepth.ParentChild, O = PrivilegeDepth.Organization;

        AddEntity("account", "Account", false, [U, O, B, U, O, O, U, U], [B, B, B, N, B, B, B, B]);
        AddEntity("contact", "Contact", false, [U, O, B, N, O, O, U, U], [B, O, B, U, B, B, U, U]);
        AddEntity("lead", "Lead", false, [], [B, B, B, U, B, B, B, B]);
        AddEntity("opportunity", "Opportunity", false, [], [U, B, U, N, B, B, U, N]);
        AddEntity("new_loanapplication", "Loan Application", true, [U, P, U, O, P, P, U, U], []);
        AddEntity("new_collateral", "Collateral", true, [U, B, B, U, B, B, N, N], []);
        AddEntity("systemuser", "User", false, [N, O, U, N, O, O, N, N], [N, O, N, N, N, O, N, N]);
        AddEntity("invoice", "Invoice", false, [], []);

        var exportId = Guid.NewGuid();
        catalog.Add(new PrivilegeDefinition { Id = exportId, Name = "prvExportToExcel", CanBeGlobal = true });
        sales[exportId] = O;
        var printId = Guid.NewGuid();
        catalog.Add(new PrivilegeDefinition { Id = printId, Name = "prvPrint", CanBeGlobal = true });
        officer[printId] = O;
        sales[printId] = O;

        var roleA = roles.First(r => r.Name.Contains("Loan Officer"));
        var roleB = roles.First(r => r.Name == "Salesperson");
        var (entityRows, misc) = TeamAnalyzer.MergePrivileges(catalog, [(roleA.Name, officer), (roleB.Name, sales)], metadata);

        var analysis = new TeamAnalysis
        {
            Team = team,
            Roles =
            [
                new() { AssignedRoleId = roleA.Id, RootRoleId = roleA.Id, Name = roleA.Name, BusinessUnitName = "contoso", IsManaged = roleA.IsManaged, GrantedEntityCount = 5, GrantedMiscCount = 1 },
                new() { AssignedRoleId = roleB.Id, RootRoleId = roleB.Id, Name = roleB.Name, BusinessUnitName = "contoso", IsManaged = roleB.IsManaged, GrantedEntityCount = 5, GrantedMiscCount = 2 },
            ],
            Members =
            [
                new() { Id = Guid.NewGuid(), FullName = "Trần Thị Bình", DomainName = "user2@contoso.vn", Email = "user2@contoso.vn", BusinessUnitName = "contoso" },
                new() { Id = Guid.NewGuid(), FullName = "Đặng Thu Trang", DomainName = "trang.dt@contoso.vn", Email = "trang.dt@contoso.vn", BusinessUnitName = "contoso" },
                new() { Id = Guid.NewGuid(), FullName = "Bùi Đức Long", DomainName = "long.bd@contoso.vn", Email = "long.bd@contoso.vn", BusinessUnitName = "contoso", IsDisabled = true },
            ],
            EntityRows = entityRows,
            MiscPrivileges = misc,
            Apps =
            [
                new() { Category = ComponentCategory.App, Name = "Loan Management", SubType = "new_LoanManagement", IsDirect = true, State = "Active" },
                new() { Category = ComponentCategory.App, Name = "Sales Hub", SubType = "msdynce_saleshub", IsDirect = true, IsManaged = true, State = "Active" },
            ],
            Warnings = ["(Demo) Đây là dữ liệu mẫu – không kết nối tới Dynamics 365."],
        };
        analysis.Findings.AddRange(TeamAnalyzer.BuildFindings(analysis));
        return (teams, analysis);
    }
}
