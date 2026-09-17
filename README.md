# D365 Security Role Analyzer

Ứng dụng desktop (WPF, .NET 10) để **phân tích và quản lý phân quyền** trong Dynamics 365 / Dataverse:
security role, team, user, Model-driven App, Field Security Profile và Business Unit.

## Chế độ làm việc (thanh điều hướng trên header)

| Chế độ | Phân tích | Quản lý |
| --- | --- | --- |
| **🛡 Roles** | Ma trận quyền entity (Create…Share × User/BU/Parent:Child/Org), quyền khác, user/team được gán, user nhận qua team, component (App, Form, Dashboard, View, Chart, BPF, Custom API), phát hiện rủi ro | Gán/gỡ nhiều user/team; **sửa privilege trực tiếp trên ma trận** (click trái tăng mức, click phải giảm, có sao lưu tự động); **sao chép role** |
| **👥 Teams** | Role của team, thành viên, **quyền hiệu lực** gộp từ các role (kèm "Từ role"), app | Gán/gỡ role, thêm/gỡ thành viên (Owner/Access team) |
| **👤 Users** | Role trực tiếp + qua team (đánh dấu trùng nguồn), team, quyền hiệu lực, app, Field Security Profile, cảnh báo (không có role, System Administrator, disabled còn role, application user) | Gán/gỡ role trực tiếp, thêm/gỡ khỏi team, **sao chép quyền sang user khác / lấy quyền từ user khác** (role, team, field security profile; tùy chọn đồng bộ hoàn toàn) |
| **📱 Apps** | Role được thêm vào app, user truy cập được (trực tiếp/qua team) | Thêm/gỡ role của app |
| **🔒 Field Security** | Cột bảo mật (Read/Create/Update), user/team, user hiệu lực | Thêm/gỡ user, team |
| **🏢 Business Units** | Cây BU, user/team/role đang dùng theo BU, **phạm vi dữ liệu** của từng mức quyền (BU / Parent:Child / Org) | – |

Double-click để điều hướng chéo: role ↔ team ↔ user ↔ app ↔ BU.

## Công cụ (menu **🧰 Công cụ**)

| Công cụ | Mô tả |
| --- | --- |
| 🔎 **Tra cứu ngược** | Chọn privilege + mức tối thiểu → role, team và toàn bộ user có quyền (kèm nguồn) |
| 📋 **Rà soát quyền** | Toàn bộ user & role, cờ cảnh báo, role không dùng; xuất Excel kèm **ma trận User × Role** (D = trực tiếp, T = qua team) |
| ⇄ **So sánh 2 role** | Khác biệt từng privilege |
| ⚙ **Áp quyền hàng loạt** | Chọn nhiều entity × quyền × mức → nhiều role, xem trước rồi áp dụng (sao lưu từng role) |
| ♻ **Khôi phục privilege** | Khôi phục role từ file sao lưu (khớp privilege theo Id hoặc theo tên nếu khác môi trường) |
| 📥 **Import Excel/CSV** | Gán/gỡ role, thêm/gỡ thành viên team hàng loạt; tạo file mẫu, kiểm tra trước, xuất kết quả |
| 📸 **Snapshot & so sánh môi trường** | Chụp role/privilege/gán quyền ra JSON; so sánh Dev ↔ UAT ↔ Prod hoặc giữa hai thời điểm |
| 🕘 **Lịch sử thao tác** | Mọi thay đổi (ai, lúc nào, môi trường nào, kết quả) và **hoàn tác** |

## An toàn khi thay đổi dữ liệu

- Mọi thao tác ghi đều hỏi xác nhận và được ghi vào `%LOCALAPPDATA%\SecurityRoleAnalyzer\history.jsonl`.
- Trước khi sửa privilege, privilege hiện tại được **sao lưu** vào `...\Backups\<môi trường>\`.
- Hoàn tác được: gán/gỡ role, thêm/gỡ thành viên, sửa privilege (khôi phục bản sao lưu), tạo role, role của app, field security profile.
- Gán role luôn dùng **bản sao role thuộc đúng Business Unit** của user/team (yêu cầu của Dataverse).

## Kết nối

1. **Đăng nhập tương tác (OAuth, hỗ trợ MFA)** – App Id mẫu của Microsoft, đổi được trong *Nâng cao*.
2. **Application User (Client Id + Secret)** – có thể lưu secret (mã hóa DPAPI theo tài khoản Windows).
3. **Connection string** tùy chỉnh (certificate…).

Các môi trường đã dùng hiện trong combobox trên header để **chuyển nhanh** (đặt *Tên hiển thị* như PROD/UAT cho dễ phân biệt).
Metadata entity/privilege được **cache ra ổ đĩa 24 giờ**; nút ⟳ trên header xóa cache và tải lại.

## Chạy

```powershell
cd SecurityRoleAnalyzer
dotnet run --project src/SecurityRoleAnalyzer            # kết nối môi trường thật
dotnet run --project src/SecurityRoleAnalyzer -- --demo  # xem giao diện với dữ liệu mẫu
dotnet test                                              # unit test + UI smoke test
dotnet publish src/SecurityRoleAnalyzer -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o publish
```

## Quyền cần có

- Đọc: role, privilege, user, team, business unit, systemform, savedquery, appmodule, workflow, customapi, fieldsecurityprofile… (System Administrator hoặc System Customizer).
- Ghi (gán role, sửa privilege, tạo role, app/field security): System Administrator.

## Dữ liệu cục bộ (`%LOCALAPPDATA%\SecurityRoleAnalyzer`)

| Đường dẫn | Nội dung |
| --- | --- |
| `connections.json` | Hồ sơ kết nối (secret chỉ lưu khi chọn, đã mã hóa) |
| `TokenCache\` | Token OAuth |
| `Cache\<môi trường>\` | Metadata entity & privilege |
| `Backups\<môi trường>\` | Sao lưu privilege trước mỗi lần sửa |
| `Snapshots\` | Snapshot môi trường |
| `history.jsonl` | Lịch sử thao tác |

## Cấu trúc mã nguồn

```
src/SecurityRoleAnalyzer
├── Models/        Role, privilege, team, user, app, field security, BU, AccessIndex, snapshot, import
├── Services/
│   ├── DataverseService*.cs   Truy vấn (FetchXML), chỉ mục phân quyền, thao tác ghi có log & hoàn tác
│   ├── RoleAnalyzer / TeamAnalyzer / Analyzers.cs   Phân tích & phát hiện rủi ro
│   ├── ToolServices.cs        Sao lưu privilege, snapshot, import
│   ├── ActionLog.cs           Lịch sử thao tác, cache ổ đĩa
│   └── ExcelExporter.cs
├── ViewModels/    MainViewModel (+Shell, +Editing), Team/User/App/FieldSecurity/BusinessUnits, ToolViewModels
├── Views/         MainWindow, view từng chế độ, cửa sổ công cụ, hộp thoại
└── Controls/      DepthColumn (hiển thị & sửa mức quyền), SelectColumn, GridSelection
tests/SecurityRoleAnalyzer.Tests   xUnit (logic + UI smoke test)
```
