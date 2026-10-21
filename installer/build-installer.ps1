# Build bộ cài: publish bản self-contained (user không cần cài .NET) rồi đóng gói bằng Inno Setup.
#   Full   : đầy đủ chức năng, dành cho admin.
#   Viewer : chỉ xem, khóa mọi thao tác ghi lên Dataverse ngay lúc biên dịch, dành cho user.
# Kết quả trong dist\: bộ cài .exe và bản portable .zip cho từng edition.
#
# Ký số (để Windows SmartScreen / UAC hiện tên nhà phát hành thay vì "Unknown publisher"):
#   -CertThumbprint <SHA1>  chứng chỉ ký code trong kho Windows (CurrentUser\My hoặc LocalMachine\My),
#                           kể cả chứng chỉ nằm trên USB token / HSM có cài driver.
#   -PfxPath <file.pfx>     file chứng chỉ; mật khẩu đọc từ biến môi trường SRA_PFX_PASSWORD
#                           để không lộ trong lịch sử lệnh.
#   Không truyền gì thì build không ký như trước.
#
# Phiên bản: -Bump Patch|Minor|Major tăng <Version> trong csproj trước khi build (3.0.0 → 3.0.1 / 3.1.0 / 4.0.0).
# App chỉ nhận bản cập nhật có phiên bản lớn hơn bản đang chạy, nên mỗi lần phát hành phải tăng phiên bản.
# Phát hành lên GitHub để app tự cập nhật: installer\publish-release.ps1.
param(
    [ValidateSet('All', 'Full', 'Viewer')]
    [string]$Edition = 'All',
    [ValidateSet('None', 'Patch', 'Minor', 'Major')]
    [string]$Bump = 'None',
    [switch]$SkipTests,
    [string]$CertThumbprint,
    [string]$PfxPath,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'src\SecurityRoleAnalyzer\SecurityRoleAnalyzer.csproj'
$distDir = Join-Path $root 'dist'

$iscc = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Không tìm thấy Inno Setup 6 (ISCC.exe). Cài bằng: winget install JRSoftware.InnoSetup' }

#region Ký số

$signArgs = $null
if ($CertThumbprint -and $PfxPath) { throw 'Chỉ dùng một trong hai: -CertThumbprint hoặc -PfxPath.' }
if ($CertThumbprint) {
    $CertThumbprint = $CertThumbprint -replace '\s', ''
    $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert |
        Where-Object Thumbprint -eq $CertThumbprint | Select-Object -First 1
    if (-not $cert) { throw "Không tìm thấy chứng chỉ ký code có thumbprint $CertThumbprint." }
    if ($cert.NotAfter -lt (Get-Date)) { throw "Chứng chỉ $($cert.Subject) đã hết hạn ngày $($cert.NotAfter.ToString('dd/MM/yyyy'))." }
    Write-Host "Ký bằng: $($cert.Subject) (hết hạn $($cert.NotAfter.ToString('dd/MM/yyyy')))"
    $signArgs = @('/sha1', $CertThumbprint)
}
elseif ($PfxPath) {
    if (-not (Test-Path $PfxPath)) { throw "Không thấy file $PfxPath." }
    if (-not $env:SRA_PFX_PASSWORD) { throw 'Đặt mật khẩu PFX vào biến môi trường SRA_PFX_PASSWORD.' }
    $signArgs = @('/f', (Resolve-Path $PfxPath).Path, '/p', $env:SRA_PFX_PASSWORD)
}

if ($signArgs) {
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object { [version]$_.Directory.Parent.Name } | Select-Object -Last 1 -ExpandProperty FullName
    if (-not $signtool) { throw 'Không tìm thấy signtool.exe. Cài Windows SDK (thành phần "Signing Tools").' }
}

function Invoke-Sign([string]$file, [string]$description) {
    if (-not $signArgs) { return }
    # Timestamp giữ chữ ký hợp lệ cả sau khi chứng chỉ hết hạn. Không in lệnh ra vì có thể chứa mật khẩu PFX.
    & $signtool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /d $description @signArgs $file | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Ký thất bại: $file" }
    $status = (Get-AuthenticodeSignature $file).Status
    Write-Host "  Đã ký $(Split-Path $file -Leaf): $status"
}

#endregion

$version = ([xml](Get-Content $project)).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
if ($Bump -ne 'None') {
    $v = [version]$version
    $next = switch ($Bump) {
        'Patch' { '{0}.{1}.{2}' -f $v.Major, $v.Minor, ([math]::Max($v.Build, 0) + 1) }
        'Minor' { '{0}.{1}.0' -f $v.Major, ($v.Minor + 1) }
        'Major' { '{0}.0.0' -f ($v.Major + 1) }
    }
    # Sửa đúng thẻ <Version> dạng văn bản để giữ nguyên định dạng và chú thích của csproj.
    $text = [IO.File]::ReadAllText($project)
    $updated = $text -replace "<Version>$([regex]::Escape($version))</Version>", "<Version>$next</Version>"
    if ($updated -eq $text) { throw "Không tìm thấy <Version>$version</Version> trong csproj." }
    [IO.File]::WriteAllText($project, $updated, (New-Object Text.UTF8Encoding $true))
    Write-Host "Tăng phiên bản: $version → $next"
    $version = $next
}
Write-Host "Phiên bản: $version"

if (-not $SkipTests) {
    dotnet test $root -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Test thất bại, dừng build bộ cài.' }
}

$editions = if ($Edition -eq 'All') { 'Full', 'Viewer' } else { , $Edition }
New-Item -ItemType Directory -Force $distDir | Out-Null

foreach ($ed in $editions) {
    Write-Host "`n=== Edition: $ed ===" -ForegroundColor Cyan
    $publishDir = Join-Path $root "publish\$ed"
    if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }
    $appName = if ($ed -eq 'Viewer') { 'D365 Security Role Analyzer Viewer' } else { 'D365 Security Role Analyzer' }

    # Edition đổi DefineConstants; MSBuild băm giá trị này vào CoreCompileInputs.cache nên tự biên dịch lại.
    dotnet publish $project -c Release -r win-x64 --self-contained `
        -p:Edition=$ed -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:DebugType=None -o $publishDir
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish ($ed) thất bại." }

    # Ký exe của app trước khi đóng gói, để bản cài xong và bản portable đều mang chữ ký.
    Invoke-Sign (Join-Path $publishDir 'SecurityRoleAnalyzer.exe') $appName

    & $iscc /Q "/DAppVersion=$version" "/DPublishDir=$publishDir" "/DEdition=$ed" (Join-Path $PSScriptRoot 'SecurityRoleAnalyzer.iss')
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup ($ed) thất bại." }

    $suffix = if ($ed -eq 'Viewer') { '-Viewer' } else { '' }
    Invoke-Sign (Join-Path $distDir "SecurityRoleAnalyzer$suffix-Setup-$version.exe") "$appName Setup"
    Compress-Archive -Path "$publishDir\*" -DestinationPath (Join-Path $distDir "SecurityRoleAnalyzer$suffix-$version-portable.zip") -Force
}

# Định dạng sha256sum ("<hash>  <tên file>"); app dùng file này để kiểm tra bộ cài khi GitHub không trả digest.
$sums = Get-ChildItem $distDir -File | Where-Object { $_.Name -like "*-$version.exe" -or $_.Name -like "*-$version-portable.zip" } |
    Sort-Object Name | ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name }
[IO.File]::WriteAllText((Join-Path $distDir 'SHA256SUMS.txt'), (($sums -join "`n") + "`n"))

Get-ChildItem $distDir | Select-Object Name, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } }
