# D365 Security Role Analyzer

Ứng dụng desktop (WPF, .NET 10) để **phân tích và quản lý phân quyền** trong Dynamics 365 / Dataverse:
security role, team, user, Model-driven App, Field Security Profile và Business Unit.

## Chế độ làm việc (thanh điều hướng trên header)

| Chế độ | Phân tích | Quản lý |
| --- | --- | --- |
| **🛡 Roles** | Ma trận quyền entity (Create…Share × User/BU/Parent:Child/Org), quyền khác, user/team được gán, user nhận qua team, component (App, Form, Dashboard, View, Chart, BPF, Custom API – double-click một dòng để xem **chiều ngược: form đó đang mở cho role nào**), phát hiện rủi ro | **Tạo / sao chép / đổi tên / xóa role**; **sửa privilege trực tiếp trên ma trận** (click trái tăng mức, click phải giảm, `+`/`-` bằng bàn phím, có sao lưu tự động); **xuất / nhập định nghĩa role** giữa các môi trường; gán/gỡ nhiều user/team |
| **👥 Teams** | Role của team (kèm **phạm vi quyền** User+Team hay chỉ record của team), thành viên, **quyền hiệu lực** gộp từ các role, app | Gán/gỡ role, thêm/gỡ thành viên (Owner/Access team) |
| **👤 Users** | Role trực tiếp + qua team (đánh dấu trùng nguồn và role chỉ áp dụng trên record của team), team, quyền hiệu lực, app, Field Security Profile, cảnh báo | Gán/gỡ role trực tiếp, thêm/gỡ khỏi team, **sao chép quyền sang user khác / lấy quyền từ user khác** |
| **📱 Apps** | Role được thêm vào app, user truy cập được (trực tiếp/qua team) | Thêm/gỡ role của app |
| **🔒 Field Security** | Cột bảo mật (Read/Create/Update), user/team, user hiệu lực | Thêm/gỡ user, team |
| **🏢 Business Units** | Cây BU, user/team/role đang dùng theo BU, **phạm vi dữ liệu** của từng mức quyền, **hierarchy security và access team template** đang bật | – |

Double-click để điều hướng chéo: role ↔ team ↔ user ↔ app ↔ BU.

## Công cụ (menu **🧰 Công cụ**)

| Công cụ | Mô tả |
| --- | --- |
| ❓ **Vì sao user không thấy bản ghi này?** | Dán URL bản ghi + chọn user → quyền hiệu lực **hỏi trực tiếp Dataverse**, kèm lý do: chủ sở hữu, Business Unit, role nào cấp mức nào, **chia sẻ bản ghi**, **hierarchy security** |
| 🧾 **Form này đang mở cho role nào?** | Chiều ngược của tab Components: mỗi form/dashboard kèm danh sách security role được gán (đọc node `DisplayConditions` trong `systemform.formxml`), lọc được theo role, theo entity, theo kiểu phân quyền; chỉ ra form đang để *Everyone* và form chưa chọn role nào. **Thêm / gỡ role hoặc chuyển form sang Everyone** ngay trên panel bên phải – ghi `formxml` rồi publish, đọc lại cấu hình mới nhất trước khi ghi, sao lưu `formxml` gốc vào `Backups\<môi trường>\Forms\`, ghi lịch sử (role thêm/gỡ, trạng thái trước → sau, người thực hiện) và hiện **lịch sử thay đổi của riêng form đó** ngay trên panel; hoàn tác được |
| 🔎 **Tra cứu ngược** | Chọn privilege + mức tối thiểu → role, team và toàn bộ user có quyền (kèm nguồn) |
| 🗂 **Entity này có trong role nào?** | Chọn entity → mọi role đang có quyền trên entity đó, kèm mức Create/Read/Write/Delete/Append/Append To/Assign/Share của từng role; lọc theo quyền + mức tối thiểu, ẩn role managed, xuất Excel. Mở nhanh bằng chuột phải lên một dòng của ma trận quyền entity |
| 📋 **Rà soát quyền** | Toàn bộ user & role, cờ cảnh báo, role không dùng; xuất Excel kèm **ma trận User × Role** |
| ⇄ **So sánh 2 role** | Khác biệt từng privilege |
| ⧉ **Tìm role trùng lặp** | So tập privilege của mọi role, phát hiện role giống hệt hoặc chứa trọn nhau, kèm gợi ý gộp |
| 🔍 **Audit log phân quyền** | Đọc audit log của chính D365 – thấy cả thay đổi người khác làm ngoài ứng dụng này |
| ⚙ **Áp quyền hàng loạt** | Chọn nhiều entity × quyền × mức → nhiều role, xem trước rồi áp dụng (sao lưu từng role) |
| ♻ **Khôi phục privilege** | Khôi phục role từ file sao lưu |
| 📥 **Import Excel/CSV** | Gán/gỡ role, thêm/gỡ thành viên team hàng loạt; tạo file mẫu, kiểm tra trước, xuất kết quả |
| 📸 **Snapshot & so sánh môi trường** | Chụp role/privilege/gán quyền ra JSON; so sánh Dev ↔ UAT ↔ Prod, và **áp bản B lên môi trường đang kết nối** |
| 🕘 **Lịch sử thao tác** | Mọi thay đổi do ứng dụng thực hiện và **hoàn tác** |
| 📐 **Bộ quy tắc rà soát** | Mở `policy.json` để tự đặt entity/privilege nhạy cảm và ngưỡng cảnh báo |
| 🎨 **Giao diện** | Sáng / Tối / theo Windows |

## Đưa role giữa các môi trường

1. **Một role:** mở role → `⚙ Role ▾` → *Xuất định nghĩa role ra file* (privilege + app, khớp theo tên).
   Sang môi trường đích: `⚙ Role ▾` → *Nhập định nghĩa role từ file* → chọn tạo mới hay ghi đè.
2. **Nhiều role cùng lúc:** Công cụ → *Snapshot* → chụp môi trường nguồn ra file, mở làm B ở môi trường đích,
   `⇄ So sánh` rồi `▶ Áp B lên môi trường này` (chọn dòng để áp một phần).

Privilege của solution chưa cài trên môi trường đích sẽ bị bỏ qua và liệt kê lại sau khi chạy.

## An toàn khi thay đổi dữ liệu

- Mọi thao tác ghi đều hỏi xác nhận và được ghi vào `%LOCALAPPDATA%\SecurityRoleAnalyzer\history.jsonl`.
- Trước khi sửa privilege, privilege hiện tại được **sao lưu** vào `...\Backups\<môi trường>\`.
- Hoàn tác được: gán/gỡ role, thêm/gỡ thành viên, sửa privilege, tạo role, role của app, role của form, field security profile.
  Thao tác **lỗi giữa chừng** vẫn hoàn tác được (đánh dấu "Lỗi dở dang" trong lịch sử).
- Gán role luôn dùng **bản sao role thuộc đúng Business Unit** của user/team (yêu cầu của Dataverse).
- Lỗi được ghi kèm stack trace vào `errors.log`; hộp thoại lỗi có nút sao chép.

## Phím tắt

`F1` bảng phím tắt · `F5` làm mới · `Ctrl+F` ô tìm kiếm · `Ctrl+S` lưu privilege · `Ctrl+E` xuất Excel ·
`Ctrl+K` kết nối · `Ctrl+L` tra cứu ngược · `Ctrl+H` lịch sử · `Ctrl+Shift+C` chép tên và Id ·
`Ctrl+1…6` chuyển chế độ · `+`/`-` đổi mức quyền trên ô đang chọn.

## Kết nối

1. **Đăng nhập tương tác (OAuth, hỗ trợ MFA)** – App Id mẫu của Microsoft, đổi được trong *Nâng cao*.
2. **Application User (Client Id + Secret)** – có thể lưu secret (mã hóa DPAPI theo tài khoản Windows).
3. **Connection string** tùy chỉnh (certificate…).

Các môi trường đã dùng hiện trong combobox trên header để **chuyển nhanh**.
Metadata entity/privilege được **cache ra ổ đĩa 24 giờ**; nút ⟳ trên header xóa cache và tải lại.

## Chạy

```powershell
cd SecurityRoleAnalyzer
dotnet run --project src/SecurityRoleAnalyzer            # kết nối môi trường thật
dotnet run --project src/SecurityRoleAnalyzer -- --demo  # xem giao diện với dữ liệu mẫu
dotnet test                                              # unit test + UI smoke test
dotnet publish src/SecurityRoleAnalyzer -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o publish
```

### Build bộ cài cho user

Cần [Inno Setup 6](https://jrsoftware.org/isinfo.php) (`winget install JRSoftware.InnoSetup`).

```powershell
.\installer\build-installer.ps1                   # chạy test → publish → đóng gói cả 2 edition
.\installer\build-installer.ps1 -Edition Viewer   # chỉ build bản Viewer
.\installer\build-installer.ps1 -SkipTests
```

Có hai edition, cài song song được trên cùng máy:

| Edition | Dành cho | File trong `dist\` |
|---|---|---|
| **Full** | Admin – đầy đủ chức năng | `SecurityRoleAnalyzer-Setup-<version>.exe`, `SecurityRoleAnalyzer-<version>-portable.zip` |
| **Viewer** | User – chỉ xem, phân tích, xuất Excel | `SecurityRoleAnalyzer-Viewer-Setup-<version>.exe`, `SecurityRoleAnalyzer-Viewer-<version>-portable.zip` |

Bản Viewer được build với `-p:Edition=Viewer` (hằng số `VIEWER`), khóa cứng lúc biên dịch nên user không tự mở khóa được: ẩn mọi nút gán/gỡ role, sửa privilege, tạo/sao chép/đổi tên/xóa role, team member, app, field profile, áp quyền hàng loạt, import, khôi phục sao lưu, áp snapshot, hoàn tác; đồng thời `DataverseService` từ chối mọi thao tác ghi (`ReadOnlyEditionException`). Tiêu đề cửa sổ có chữ "Viewer (chỉ xem)".

Bộ cài mặc định cài cho user hiện tại, không cần quyền admin; đã kèm .NET runtime nên máy user không cần cài .NET. Phiên bản lấy từ `<Version>` trong csproj.

#### Ký số và cảnh báo SmartScreen

File chưa ký sẽ bị SmartScreen chặn ("Windows protected your PC") khi tải qua email, Teams hoặc trình duyệt. Script ký exe của app và bộ cài (SHA256 + timestamp) khi có chứng chỉ:

```powershell
.\installer\build-installer.ps1 -CertThumbprint <SHA1>        # chứng chỉ trong kho Windows / USB token
$env:SRA_PFX_PASSWORD = '...'; .\installer\build-installer.ps1 -PfxPath C:\certs\codesign.pfx
```

Lưu ý: chữ ký thay "Unknown publisher" bằng tên công ty, nhưng SmartScreen vẫn có thể cảnh báo cho tới khi file có đủ "uy tín" (chứng chỉ EV không còn được miễn từ 2024). Với công cụ nội bộ, cách chắc chắn là phát hành qua kênh không gắn dấu "tải từ Internet": thư mục chia sẻ trong mạng công ty, hoặc IT đẩy cài qua Intune / SCCM / GPO.

#### Tự cập nhật phiên bản

Ứng dụng tự kiểm tra GitHub Releases của repo này khi mở (tối đa khoảng mỗi ngày một lần), hoặc khi bấm **Công cụ → Kiểm tra cập nhật**. Có bản mới thì hỏi user, đồng ý là tự tải, kiểm tra, cài và mở lại. Bản portable chỉ mở trang tải.

Phát hành một phiên bản mới:

```powershell
.\installer\build-installer.ps1 -Bump Patch            # 3.0.1 → 3.0.2, chạy test, build cả 2 edition + SHA256SUMS.txt
$env:GITHUB_TOKEN = '<fine-grained token, quyền Contents: Read and write cho repo>'
.\installer\publish-release.ps1 -Notes "Nội dung thay đổi user sẽ thấy"
```

Bộ cài chỉ được chạy khi: tải qua https từ đúng repo `duytoerp/d365_security_role_analyzer`; đúng edition (bản Viewer chỉ nhận `SecurityRoleAnalyzer-Viewer-Setup-*.exe`, không bao giờ nhận bản Full); phiên bản lớn hơn bản đang chạy (bỏ qua prerelease/draft); khớp SHA256 (digest của GitHub hoặc `SHA256SUMS.txt`); và nếu bản đang chạy đã ký số thì bộ cài phải được ký hợp lệ bởi cùng nhà phát hành. Lưu ý: repo công khai nên ai cũng tải được các bộ cài trên Releases.

### Chế độ dòng lệnh (báo cáo định kỳ)

```powershell
SecurityRoleAnalyzer.exe --export-review C:\BaoCao\RaSoat.xlsx --profile PROD
SecurityRoleAnalyzer.exe --snapshot C:\Snapshots\prod.json --url https://org.crm5.dynamics.com `
                         --client-id <guid>        # secret lấy từ biến môi trường SRA_CLIENT_SECRET
SecurityRoleAnalyzer.exe --help
```

Chạy tự động cần Application User (đăng nhập tương tác không dùng được); mã thoát 0 là thành công.

## Quyền cần có

- Đọc: role, privilege, user, team, business unit, systemform, savedquery, appmodule, workflow, customapi,
  fieldsecurityprofile, teamtemplate, hierarchysecurityconfiguration, audit… (System Administrator hoặc System Customizer).
- Ghi (gán role, sửa privilege, tạo/xóa role, app/field security): System Administrator.
- Audit log chỉ có dữ liệu khi môi trường đã bật Auditing.

## Dữ liệu cục bộ (`%LOCALAPPDATA%\SecurityRoleAnalyzer`)

| Đường dẫn | Nội dung |
| --- | --- |
| `connections.json` | Hồ sơ kết nối (secret chỉ lưu khi chọn, đã mã hóa) |
| `settings.json` | Giao diện sáng/tối, kích thước cửa sổ |
| `policy.json` | Bộ quy tắc rà soát tùy chỉnh (tùy chọn) |
| `TokenCache\` | Token OAuth |
| `Cache\<môi trường>\` | Metadata entity & privilege, role của từng form |
| `Backups\<môi trường>\` | Sao lưu privilege trước mỗi lần sửa |
| `Snapshots\` | Snapshot môi trường |
| `history.jsonl` | Lịch sử thao tác |
| `errors.log` | Nhật ký lỗi kèm stack trace |

## Cấu trúc mã nguồn

```
src/SecurityRoleAnalyzer
├── Program.cs     Điểm vào: mở giao diện hoặc chạy chế độ dòng lệnh
├── Models/        Role, privilege, team, user, app, field security, BU, AccessIndex, snapshot, import, quyền trên record
├── Services/
│   ├── DataverseService*.cs   Truy vấn (FetchXML), chỉ mục phân quyền, thao tác ghi có log & hoàn tác,
│   │                          quyền trên bản ghi (Access), audit log
│   ├── RoleAnalyzer / TeamAnalyzer / Analyzers.cs   Phân tích & phát hiện rủi ro
│   ├── RecordAccessExplainer.cs  Vì sao user thấy / không thấy một bản ghi
│   ├── FormRoleAnalyzer.cs       Form/dashboard đang mở cho những role nào
│   ├── RoleOverlapAnalyzer.cs    Tìm role trùng lặp
│   ├── RoleDefinitionService.cs  Xuất/nhập định nghĩa role giữa môi trường
│   ├── SnapshotApplyService.cs   Áp diff snapshot
│   ├── SecurityPolicy.cs         Bộ quy tắc rà soát (policy.json)
│   ├── CommandLineRunner.cs      Chế độ dòng lệnh
│   ├── ToolServices.cs / ActionLog.cs / AppSettings.cs / Theme.cs
│   └── ExcelExporter.cs
├── Themes/        Light.xaml, Dark.xaml
├── ViewModels/    MainViewModel (+Shell, +Editing), Team/User/App/FieldSecurity/BusinessUnits, ToolViewModels
├── Views/         MainWindow, view từng chế độ, cửa sổ công cụ, hộp thoại
└── Controls/      DepthColumn (hiển thị & sửa mức quyền), SelectColumn, GridSelection
tests/SecurityRoleAnalyzer.Tests   xUnit (logic + UI smoke test)
```

## Giới hạn đã biết

- Quyền hiệu lực trong chế độ Roles/Teams/Users tính theo security role. Quyền đến từ **chia sẻ bản ghi,
  access team hoặc hierarchy security** chỉ thấy được ở công cụ *Vì sao user không thấy bản ghi này?*,
  vì những nguồn này gắn với từng bản ghi cụ thể.
- Quick View và Quick Create **không gán được security role** – D365 cho vào theo quyền Read entity,
  nên công cụ *Form này đang mở cho role nào?* liệt kê chúng ở nhóm riêng thay vì bỏ qua.
- Role gán cho form **không có bảng hay cột riêng** trong Dataverse – nó nằm trong node `DisplayConditions`
  bên trong `systemform.formxml`. Cột này rất lớn nên lần đầu đọc sẽ lâu; kết quả được **cache ra ổ đĩa 24 giờ**.
- Form có form XML hỏng được báo là **không đọc được**, không mặc định coi là *Everyone*.
- Snapshot và import khớp role theo **tên**; hai môi trường khác ngôn ngữ hiển thị sẽ cho kết quả so sánh sai lệch.
- Các chức năng cần chỉ mục toàn môi trường (tra cứu ngược, rà soát, snapshot, Apps, Business Units)
  phải tải toàn bộ phân quyền, nên lần đầu sẽ lâu với môi trường lớn.
