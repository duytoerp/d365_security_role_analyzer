# Security Role Analyzer – Ghi chú đọc nhanh cho dev

> Tóm tắt kiến trúc và "sửa cái gì ở đâu". Tính năng phía người dùng, phím tắt, cách build bộ cài:
> xem [README.md](../README.md).

## 1. Tổng quan 30 giây

- **Là gì:** app desktop WPF để phân tích & quản lý phân quyền Dynamics 365 / Dataverse
  (security role, team, user, Model-driven App, Field Security Profile, Business Unit, role của form).
- **Stack:** .NET 10 (`net10.0-windows`), WPF, MVVM bằng `CommunityToolkit.Mvvm` 8.4,
  `Microsoft.PowerPlatform.Dataverse.Client` 1.2 (`ServiceClient`), `ClosedXML` cho Excel. Test: xUnit.
- **Phiên bản:** `<Version>` trong [SecurityRoleAnalyzer.csproj](../src/SecurityRoleAnalyzer/SecurityRoleAnalyzer.csproj) (đang 3.0.1).
- **Quy mô:** ~16k dòng C#, 1 project app + 1 project test, solution `SecurityRoleAnalyzer.slnx`.
- **Ngôn ngữ:** UI, comment, commit message đều tiếng Việt.

```powershell
dotnet run --project src/SecurityRoleAnalyzer -- --demo   # chạy với dữ liệu mẫu, không cần D365
dotnet test
.\installer\build-installer.ps1                         # test → publish → Inno Setup, ra dist\
```

## 2. Luồng khởi động

```
Program.Main
 ├─ có --export-review / --snapshot / --help → CommandLineRunner.RunAsync (gắn console, chạy rồi thoát, exit 0/1)
 └─ ngược lại → App (WPF)
       App.OnStartup: gắn handler lỗi toàn cục → ErrorLog/Dialogs.ShowError, Theme.Apply(AppSettings.Current.Theme)
       MainWindow: DataContext = MainViewModel; có --demo → vm.LoadDemo() (DemoData.cs)
```

Kết nối: `ConnectionWindow` → connection string → `DataverseService.ConnectAsync` (bắt buộc https,
`ConnectionSecurity.EnsureHttps`) → `MainViewModel._service`. Hồ sơ kết nối lưu ở `ConnectionProfileStore`
(secret mã hóa DPAPI).

## 3. Kiến trúc theo tầng

| Tầng | Thư mục | Vai trò |
| --- | --- | --- |
| Model | `Models/` | POCO/record thuần, không gọi Dataverse. `AccessIndex`, `Privileges`, `*Models.cs` |
| Truy cập dữ liệu | `Services/DataverseService*.cs` | **Mọi** lệnh tới Dataverse (FetchXML/QueryExpression/Request) |
| Phân tích | `Services/*Analyzer*.cs`, `RecordAccessExplainer`, `AccessReviewBuilder`, `AccessLookup` | Logic thuần, dễ test, nhận dữ liệu từ service/AccessIndex |
| Tiện ích | `Services/ToolServices.cs`, `ActionLog.cs`, `AppSettings.cs`, `ExcelExporter.cs`… | Snapshot, import, backup, lịch sử, cache đĩa, setting, log lỗi |
| ViewModel | `ViewModels/` | `MainViewModel` (partial) là "host"; VM con nhận `MainViewModel host` |
| View | `Views/`, `Controls/`, `Converters/`, `Themes/` | XAML + code-behind mỏng; một số hộp thoại dựng bằng code (`Dialogs2.cs`, `RoleImportWindow.cs`) |

### DataverseService (partial, chia theo chủ đề)

| File | Nội dung |
| --- | --- |
| `DataverseService.cs` | Kết nối, cache, role/privilege/metadata, user/team của role, app, form/view/chart/BPF/Custom API, parse `formxml` (`TryParseFormXmlRoles`, `ReplaceFormXmlRoles`) |
| `DataverseService.Directory.cs` | User, team, app, field security, BU; **`GetAccessIndexAsync`** và `GetRoleDirectoryAsync` |
| `DataverseService.Changes.cs` | **Mọi thao tác ghi** + `UndoAsync` |
| `DataverseService.Access.cs` | Quyền trên từng bản ghi: `RetrievePrincipalAccess`, share, owner, access team template, hierarchy security, manager chain |
| `DataverseService.Audit.cs` | Đọc audit log liên quan phân quyền |

### MainViewModel (partial)

| File | Nội dung |
| --- | --- |
| `MainViewModel.cs` | Kết nối, busy/progress/cancel, danh sách role, phân tích role đang chọn, `LoadDemo` |
| `MainViewModel.Shell.cs` | `AppMode` (Roles/Teams/Users/Apps/FieldSecurity/BusinessUnits), điều hướng chéo (`OpenTeam`, `OpenUserAsync`…), hồ sơ kết nối, **lệnh mở cửa sổ công cụ** (`ShowTool`), xuất Excel |
| `MainViewModel.Editing.cs` | Sửa privilege trên ma trận (`IPrivilegeEditHost.CycleDepth`), lưu/bỏ, tạo/sao chép/đổi tên/xóa role, xuất/nhập định nghĩa role |

VM của từng chế độ: `TeamManagerViewModel`, `UserManagerViewModel`, `AdminViewModels.cs`
(`AppManagerViewModel`, `FieldSecurityViewModel`, `BusinessUnitsViewModel`). Chế độ được **tải lười** lần đầu mở
(`EnsureModeLoadedAsync`).

VM công cụ (cửa sổ riêng) kế thừa `ToolViewModelBase` trong `ToolViewModels.cs`: `Lookup`, `EntityRole`, `AccessReview`,
`BulkPrivilege`, `Snapshot`, `Import`, `History`, `RoleOverlap`, `Audit`, `RecordAccess`; riêng
`FormRoleViewModel.cs`. Base có sẵn `RunAsync` / `RunCancellableAsync` (busy + hủy + % + bắt lỗi hiện dialog)
và `RequireService()`.

## 4. Khái niệm Dataverse cần nhớ

- **Role gốc vs bản sao theo BU:** mỗi role có một bản sao ở mỗi Business Unit. Gán role cho user/team phải dùng
  **bản sao thuộc đúng BU** của principal (`RoleCopy`, `GetRoleCopiesAsync`). `AccessIndex.CopyToRoot` /
  `RoleDirectory.Root()` quy mọi Id bản sao về Id gốc – trong `AccessIndex` mọi Id role đều là Id gốc.
- **PrivilegeDepth** = `privilegedepthmask`: None 0, User 1, BU 2, Parent:Child 4, Org 8 (`EnumText.FromMask`).
  Mỗi privilege chỉ cho phép một số mức (`CanBeBasic/Local/Deep/Global` → `AllowedDepthList`, `Clamp`, `Cycle`).
- **AccessRight** = `privilege.accessright` (Read 1, Write 2, Append 4, AppendTo 16, Create 32, Delete 65536, Share 262144, Assign 524288).
- **System Administrator** nhận diện theo role template (`IsSystemAdministrator`), không theo tên → không phụ thuộc ngôn ngữ.
- **Role của form** không có bảng riêng: nằm trong node `DisplayConditions` của `systemform.formxml`.
  Ghi = sửa formxml rồi publish (`ChangeFormRolesAsync`). formxml rất lớn → tải lô 50 (`FormXmlPageSize`) và cache đĩa `form-roles`.
- **Team role scope:** role gán cho team có thể chỉ áp dụng trên record của team (không cộng vào quyền User) – UI có đánh dấu.
- Quyền từ **share / access team / hierarchy security** gắn với từng bản ghi → chỉ công cụ *Vì sao user không thấy bản ghi*
  (`RecordAccessExplainer`) xét tới; các chế độ khác chỉ tính security role.

## 5. AccessIndex – chỉ mục toàn môi trường

`Models/AccessIndex.cs`. Ảnh chụp role + privilege của mọi role + gán role user/team + thành viên team + BU.
Dùng cho tra cứu ngược, rà soát, snapshot, import, Apps, Business Units.
Helper: `EffectiveRolesOf(user)` (kèm nguồn team), `EffectiveUsersOf(role)`, `DepthOf(role, privilege)`, `RoleName`, `IsAdminRole`.
Tải nặng (lần đầu lâu với môi trường lớn), được cache trong bộ nhớ và **tự xóa sau mỗi thao tác ghi**.
`RoleDirectory` là bản nhẹ (chỉ role + bản sao) khi chỉ cần đổi Id → tên.

## 6. Cache

| Lớp | Ở đâu | Ghi chú |
| --- | --- | --- |
| Bộ nhớ | `DataverseService._cache` (`GetCachedAsync(key, factory)`) | Key: `entities`, `privileges`, `apps`, `forms`, `views`, `charts`, `bpf`, `customapi`, `teamtemplates`, `attributes:<entity>`, `access-index`, `role-directory` |
| Ổ đĩa (24h) | `DiskCache` trong `ActionLog.cs` → `%LOCALAPPDATA%\SecurityRoleAnalyzer\Cache\<host>\<name>.json` | `entities`, `privileges`, `form-roles`. `DiskCache.Update` sửa 1 mục mà **giữ nguyên hạn file** |
| Xóa | `ClearCache(includeDisk)` – nút ⟳ trên header | `LoggedAsync` tự xóa `access-index` và `role-directory` sau mỗi lần ghi |

## 7. Pattern thao tác ghi (quan trọng nhất)

Mọi thao tác ghi nằm trong `DataverseService.Changes.cs` và **phải** đi qua `LoggedAsync(...)`:

1. `AppEdition.EnsureCanModify()` – chốt chặn cuối cho bản Viewer (ném `ReadOnlyEditionException`).
2. Tạo `ActionLogEntry` (môi trường, người thực hiện, action, target, detail, `UndoInfo`, before/after).
3. Chạy thao tác; gọi `progress.MarkApplied()` **ngay khi dữ liệu thật sự đã đổi** → nếu lỗi giữa chừng, mục lịch sử
   được đánh dấu `PartiallyApplied` và vẫn hoàn tác được.
4. `finally`: `ActionLogStore.Append` (ghi `history.jsonl`, khóa liên tiến trình bằng Mutex) + xóa cache index.

Hoàn tác: `UndoAsync(entry)` switch theo `UndoKind`, gọi lại chính các hàm ghi với `undoOf = entry.Id`
(chỉ cho môi trường đang kết nối). Sửa privilege: trước khi ghi lưu backup qua `PrivilegeBackupStore` vào
`Backups\<môi trường>\`, rồi `AddPrivilegesRoleRequest` / `RemovePrivilegeRoleRequest`; undo = khôi phục backup.

**Thêm một thao tác ghi mới:**
1. Viết hàm trong `DataverseService.Changes.cs`, bọc bằng `LoggedAsync`, gọi `MarkApplied()` đúng chỗ.
2. Nếu hoàn tác được: thêm giá trị vào `UndoKind`, điền `UndoInfo`, thêm `case` trong `UndoAsync`.
3. Ẩn nút/menu trong bản Viewer: `Visibility="{x:Static s:AppEdition.WriteVisibility}"` (hoặc kiểm tra `AppEdition.IsReadOnly` trong VM).
4. Thêm test vào `ViewerEditionTests` nếu cần đảm bảo Viewer chặn.

## 8. Hai edition: Full và Viewer

- Build với `-p:Edition=Viewer` → hằng `VIEWER` → `AppEdition.IsReadOnly = true` (khóa lúc biên dịch).
- Hai lớp chặn: UI ẩn nút (`AppEdition.WriteVisibility`) **và** `DataverseService.LoggedAsync` từ chối ghi.
- Tiêu đề cửa sổ thêm "Viewer (chỉ xem)". Bộ cài `installer/SecurityRoleAnalyzer.iss` + `build-installer.ps1 -Edition Full|Viewer|All`, hỗ trợ ký số (`-CertThumbprint` / `-PfxPath` + `SRA_PFX_PASSWORD`).

## 9. Bảo mật kết nối

`Services/ConnectionSecurity.cs`: `EnsureHttps` (từ chối URL không phải https cho mọi kiểu kết nối, kể cả CLI)
và `Redact` (che `ClientSecret`, `Password`, token, `Bearer …` trước khi ghi log/hiện lỗi). Khi log hoặc hiện
exception có thể chứa connection string → luôn đi qua `Redact`. CLI đọc secret từ biến môi trường `SRA_CLIENT_SECRET`.

## 10. "Muốn sửa X thì vào đâu?"

| Muốn… | File |
| --- | --- |
| Thêm/sửa quy tắc cảnh báo rủi ro role | `Services/RoleAnalyzer.cs` (`BuildPrivilegeFindings`, `BuildFindings`) + ngưỡng trong `Services/SecurityPolicy.cs` (`policy.json`) |
| Phân tích team / user / app / field security / BU | `TeamAnalyzer.cs`, `Analyzers.cs` (`UserAnalyzer`, `AppAnalyzer`, `FieldProfileAnalyzer`, `BusinessUnitAnalyzer`) |
| Rà soát quyền, tra cứu ngược | `Analyzers.cs` (`AccessReviewBuilder`, `AccessLookup`) + `ToolViewModels.cs` |
| Entity này có trong role nào | `Analyzers.cs` (`EntityRoleLookup`), `EntityRoleViewModel` trong `ToolViewModels.cs`, `Views/EntityRoleWindow.xaml`; model `EntityRoleRow`/`EntityRoleOption` trong `ToolModels.cs` |
| Form mở cho role nào | `FormRoleAnalyzer.cs`, `FormRoleViewModel.cs`, `FormRoleWindow.xaml`, formxml ở `DataverseService.cs` |
| Vì sao user không thấy bản ghi | `RecordAccessExplainer.cs`, `DataverseService.Access.cs`, `RecordAccessViewModel` |
| Role trùng lặp | `RoleOverlapAnalyzer.cs` |
| Xuất/nhập định nghĩa role giữa môi trường | `RoleDefinitionService.cs`, `Views/RoleImportWindow.cs` |
| Snapshot / so sánh / áp snapshot | `ToolServices.cs` (`SnapshotService`), `SnapshotApplyService.cs`, `SnapshotViewModel` |
| Import Excel/CSV | `ToolServices.cs` (`ImportService`), `ImportViewModel` |
| Xuất Excel | `ExcelExporter.cs` (`ExportColumn<T>`, `AddInfoSheet`) |
| Ma trận privilege (hiển thị & click sửa mức) | `Controls/DepthColumn.cs`, `Converters/Converters.cs` (`DepthVisuals`), `MainViewModel.Editing.cs` |
| Màu, theme sáng/tối | `Themes/Light.xaml`, `Themes/Dark.xaml` (cùng bộ key `*Brush`, dùng `DynamicResource`), `Services/Theme.cs` |
| Hộp thoại xác nhận/lỗi/nhập liệu | `Views/Dialogs.cs`, `Dialogs2.cs`, `ErrorWindow.cs` |
| Nhớ vị trí/kích thước cửa sổ | `Views/WindowState.cs` (`WindowMemory`), lưu trong `settings.json` |
| Click phải chọn dòng trước khi mở ContextMenu của DataGrid | `c:GridSelection.SelectRowOnRightClick="True"` (`Controls/GridSelection.cs`) |
| Thêm công cụ mới vào menu 🧰 | VM kế thừa `ToolViewModelBase` → Window XAML + partial class trong `ToolWindows.xaml.cs` → `[RelayCommand] OpenXxx` trong `MainViewModel.Shell.cs` gọi `ShowTool(...)` → `MenuItem` trong `MainWindow.xaml` |
| Chế độ dòng lệnh | `Services/CommandLineRunner.cs` |
| Dữ liệu mẫu cho `--demo` | `Services/DemoData.cs` |

## 11. Dữ liệu cục bộ – `%LOCALAPPDATA%\SecurityRoleAnalyzer`

`connections.json` · `settings.json` · `policy.json` · `TokenCache\` · `Cache\<host>\` · `Backups\<host>\` (privilege;
formxml gốc ở `Backups\<host>\Forms\`) · `Snapshots\` · `history.jsonl` · `errors.log`.
Thư mục gốc lấy từ `ConnectionProfileStore.AppDataFolder`.

## 12. Test

`tests/SecurityRoleAnalyzer.Tests` (xUnit, `InternalsVisibleTo` nên test được `internal`):

| File | Nội dung |
| --- | --- |
| `RoleAnalyzerTests`, `TeamAnalyzerTests` | Ma trận quyền, finding, quyền hiệu lực của team |
| `PolicyAndOverlapTests` | `SecurityPolicy`, role trùng lặp |
| `EntityRoleLookupTests` | Entity → role: mức từng quyền, lọc theo quyền/mức, đếm role theo entity |
| `RecordAccessTests` | Giải thích quyền trên bản ghi |
| `FormRoleTests` | Parse/ghi `formxml` DisplayConditions |
| `RoleDeploymentTests` | Xuất/nhập role, áp snapshot |
| `ExtendedFeatureTests` | Tính năng mở rộng + `XamlSmokeTests` (dựng cửa sổ trên STA) |
| `CorrectnessFixTests` | Hồi quy các lỗi đã sửa |
| `ConnectionSecurityTests`, `ViewerEditionTests` | https/redact, bản Viewer chặn ghi |
| `RenderPreview` | Render MainWindow sáng/tối ra PNG – chỉ chạy khi `SRA_RENDER=1` (thư mục `SRA_RENDER_DIR`) |

Không có test gọi Dataverse thật; logic phân tích được tách khỏi service để test bằng dữ liệu dựng tay.

## 13. Quy ước code

- C# mới: primary constructor, collection expression `[]`, `record` cho DTO nhỏ, `Nullable` bật.
- MVVM Toolkit: `[ObservableProperty] private T _field;`, `[RelayCommand]`, `NotifyCanExecuteChangedFor`.
- Mọi hàm async nhận `CancellationToken ct = default`; tác vụ dài báo tiến độ qua `IProgress<string>` hoặc `(Text, Percent)`.
- Lỗi phụ không chặn luồng chính: `RoleAnalyzer.TryAsync(..., fallback, "mô tả", warnings)` gom vào danh sách cảnh báo.
- Comment, thông báo UI và commit message viết tiếng Việt.

## 14. Giới hạn đã biết (tóm tắt)

Snapshot/import khớp role theo **tên** (khác ngôn ngữ hiển thị sẽ lệch) · Quick View / Quick Create không gán role
được · formxml hỏng → báo "không đọc được", không coi là Everyone · audit log chỉ có khi môi trường bật Auditing.
