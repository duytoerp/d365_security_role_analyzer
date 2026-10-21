# Phát hành bản đã build trong dist\ lên GitHub Releases, để ứng dụng của user tự thấy và cập nhật.
#
#   1. .\installer\build-installer.ps1 -Bump Patch          (tăng phiên bản + build)
#   2. $env:GITHUB_TOKEN = '<token>'                        (fine-grained token, quyền Contents: Read and write cho repo này)
#   3. .\installer\publish-release.ps1 -Notes "Sửa lỗi ..., thêm ..."
#
# -Notes / -NotesFile là nội dung user thấy trong hộp thoại cập nhật. -Draft tạo bản nháp: app không thấy
# cho tới khi bạn bấm Publish trên GitHub.
param(
    [string]$Notes = '',
    [string]$NotesFile,
    [switch]$Draft
)

$ErrorActionPreference = 'Stop'
$repo = 'duytoerp/d365_security_role_analyzer'
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'src\SecurityRoleAnalyzer\SecurityRoleAnalyzer.csproj'
$distDir = Join-Path $root 'dist'

if (-not $env:GITHUB_TOKEN) {
    throw 'Đặt token GitHub vào biến môi trường GITHUB_TOKEN (fine-grained token, quyền Contents: Read and write cho repo này).'
}
if ($NotesFile) { $Notes = [IO.File]::ReadAllText((Resolve-Path $NotesFile)) }

$version = ([xml](Get-Content $project)).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
$tag = "v$version"

# App tìm đúng các tên này; thiếu bộ cài của edition nào thì user edition đó không cập nhật được.
$files = @(
    "SecurityRoleAnalyzer-Setup-$version.exe",
    "SecurityRoleAnalyzer-Viewer-Setup-$version.exe",
    "SecurityRoleAnalyzer-$version-portable.zip",
    "SecurityRoleAnalyzer-Viewer-$version-portable.zip",
    'SHA256SUMS.txt'
) | ForEach-Object { Join-Path $distDir $_ }
$missing = $files | Where-Object { -not (Test-Path $_) }
if ($missing) { throw "Thiếu file trong dist\ (chạy build-installer.ps1 trước):`n$($missing -join "`n")" }

# Kiểm tra SHA256SUMS.txt khớp với file thật, tránh phát hành nhầm bản build cũ.
$sums = Get-Content (Join-Path $distDir 'SHA256SUMS.txt') | Where-Object { $_ } | ForEach-Object { $h, $n = $_ -split '\s+', 2; @{ $n = $h } }
foreach ($f in $files | Where-Object { $_ -notlike '*SHA256SUMS.txt' }) {
    $name = Split-Path $f -Leaf
    $expected = ($sums | Where-Object { $_.ContainsKey($name) } | Select-Object -First 1).$name
    if ($expected -ne (Get-FileHash $f -Algorithm SHA256).Hash.ToLowerInvariant()) { throw "SHA256SUMS.txt không khớp với $name, hãy build lại." }
}

# Tag trỏ vào commit đang có trên GitHub; cảnh báo nếu bản build chứa code chưa commit / chưa push.
$target = 'main'
if (git -C $root status --porcelain) { Write-Warning 'Có thay đổi chưa commit: mã nguồn của bản phát hành sẽ không khớp với tag trên GitHub.' }
$head = git -C $root rev-parse HEAD
if (git -C $root branch -r --contains $head 2>$null | Select-String 'origin/main') { $target = $head }
else { Write-Warning 'Commit hiện tại chưa push lên origin/main, tag sẽ trỏ vào đầu nhánh main trên GitHub.' }

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$headers = @{
    Authorization          = "Bearer $env:GITHUB_TOKEN"
    Accept                 = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
}

try {
    Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/tags/$tag" -Headers $headers | Out-Null
    throw "Đã có bản phát hành $tag. Tăng phiên bản bằng build-installer.ps1 -Bump Patch rồi build lại."
}
catch [System.Net.WebException] {
    if ($_.Exception.Response.StatusCode -ne [System.Net.HttpStatusCode]::NotFound) { throw }
}

$body = @{
    tag_name         = $tag
    target_commitish = $target
    name             = "D365 Security Role Analyzer $version"
    body             = $Notes
    draft            = [bool]$Draft
    prerelease       = $false
} | ConvertTo-Json
$release = Invoke-RestMethod -Method Post -Uri "https://api.github.com/repos/$repo/releases" -Headers $headers `
    -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
Write-Host "Đã tạo bản phát hành $tag$(if ($Draft) { ' (nháp)' })"

$uploadUrl = $release.upload_url -replace '\{.*\}$', ''
foreach ($f in $files) {
    $name = Split-Path $f -Leaf
    Write-Host "  Upload $name ($([math]::Round((Get-Item $f).Length / 1MB, 1)) MB)..."
    Invoke-RestMethod -Method Post -Uri "$uploadUrl`?name=$([uri]::EscapeDataString($name))" -Headers $headers `
        -ContentType 'application/octet-stream' -InFile $f | Out-Null
}

Write-Host "`nXong: $($release.html_url)" -ForegroundColor Green
if ($Draft) { Write-Host 'Bản nháp: mở link trên và bấm "Publish release" để user nhận được cập nhật.' }
