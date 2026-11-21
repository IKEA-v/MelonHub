param(
    [string]$BaseUrl = 'http://127.0.0.1:8080',
    [Parameter(Mandatory = $true)][string]$UsersFile,
    [string]$DepartmentName = '课程项目管理',
    [string]$DepartmentCode = 'course',
    [string]$ApplicationName = '课程项目管理系统',
    [string]$ApplicationCode = 'course-project-management'
)

$ErrorActionPreference = 'Stop'

function Read-RootConfiguration {
    $path = Join-Path $PSScriptRoot '..\.env'
    if (-not (Test-Path -LiteralPath $path)) { throw '根目录 .env 不存在。' }
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $path -Encoding UTF8) {
        if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
        $pair = $line -split '=', 2
        $values[$pair[0]] = $pair[1]
    }
    return $values
}

function Invoke-MelonApi {
    param(
        [string]$Method,
        [string]$Path,
        [string]$Token,
        [object]$Body,
        [hashtable]$Query
    )
    $uri = $BaseUrl.TrimEnd('/') + $Path
    if ($Query) {
        $items = foreach ($entry in $Query.GetEnumerator()) {
            if ($null -ne $entry.Value -and "$($entry.Value)" -ne '') {
                [Uri]::EscapeDataString([string]$entry.Key) + '=' + [Uri]::EscapeDataString([string]$entry.Value)
            }
        }
        if ($items.Count -gt 0) { $uri += '?' + ($items -join '&') }
    }
    $headers = @{ 'Accept' = 'application/json' }
    if ($Token) { $headers.Authorization = 'Bearer ' + $Token }
    $params = @{ Method = $Method; Uri = $uri; Headers = $headers; ErrorAction = 'Stop' }
    if ($null -ne $Body) {
        $params.ContentType = 'application/json'
        $params.Body = $Body | ConvertTo-Json -Depth 20 -Compress
    }
    return Invoke-RestMethod @params
}

function Get-OrCreateDepartment {
    param([string]$Token)
    $rows = @(Invoke-MelonApi -Method GET -Path '/api/admin/departments' -Token $Token)
    $existing = $rows | Where-Object { $_.code -eq $DepartmentCode } | Select-Object -First 1
    if ($existing) { return [long]$existing.id }
    $created = Invoke-MelonApi -Method POST -Path '/api/admin/departments' -Token $Token -Body @{ name = $DepartmentName; code = $DepartmentCode }
    return [long]$created.id
}

function Get-OrCreateApplication {
    param([string]$Token)
    $rows = @(Invoke-MelonApi -Method GET -Path '/api/admin/applications' -Token $Token)
    $existing = $rows | Where-Object { $_.code -eq $ApplicationCode } | Select-Object -First 1
    if ($existing) { return [long]$existing.id }
    $created = Invoke-MelonApi -Method POST -Path '/api/admin/applications' -Token $Token -Body @{
        name = $ApplicationName
        code = $ApplicationCode
        description = '课程项目管理系统统一身份与权限'
        owner = 'course-project'
    }
    return [long]$created.id
}

function Ensure-Permissions {
    param([string]$Token, [long]$DepartmentId, [long]$ApplicationId)
    $definitions = @(
        @('课程查看', 'CV', 'course', 'view'), @('课程审核', 'CR', 'course', 'review'), @('课程恢复申请', 'CRS', 'course', 'reset'),
        @('课程编辑', 'CE', 'course', 'edit'), @('课程删除', 'CD', 'course', 'delete'), @('课程拷贝', 'CC', 'course', 'copy'),
        @('课程团队管理', 'CTM', 'course', 'team'), @('学期创建', 'TC', 'term', 'create'), @('学期编辑', 'TE', 'term', 'edit'),
        @('学期删除', 'TD', 'term', 'delete'), @('当前学期管理', 'TCM', 'term', 'current'), @('教师查看', 'TV', 'teacher', 'view'),
        @('教师创建', 'TEC', 'teacher', 'create'), @('教师编辑', 'TEE', 'teacher', 'edit'), @('教师删除', 'TED', 'teacher', 'delete'),
        @('审计查看', 'AV', 'audit', 'view'), @('用户查询', 'UL', 'user', 'lookup'), @('组织查看', 'ORG_VIEW', 'organization', 'view'),
        @('课程菜单', 'MCO', 'menu', 'course'), @('学期菜单', 'MTR', 'menu', 'term'), @('教师菜单', 'MTE', 'menu', 'teacher'),
        @('审计菜单', 'MLG', 'menu', 'audit'), @('课程审核按钮', 'MCOR', 'button', 'course-review'),
        @('课程编辑按钮', 'MCOE', 'button', 'course-edit'), @('课程删除按钮', 'MCOD', 'button', 'course-delete'),
        @('课程团队按钮', 'MCOT', 'button', 'course-team'), @('学期创建按钮', 'MTRC', 'button', 'term-create'),
        @('学期编辑按钮', 'MTRE', 'button', 'term-edit'), @('学期删除按钮', 'MTRD', 'button', 'term-delete'),
        @('当前学期按钮', 'MTRM', 'button', 'term-current'), @('教师创建按钮', 'MTEC', 'button', 'teacher-create'),
        @('教师编辑按钮', 'MTEE', 'button', 'teacher-edit'), @('教师删除按钮', 'MTED', 'button', 'teacher-delete'),
        @('用户查询按钮', 'MTEL', 'button', 'user-lookup')
    )
    $rows = @(Invoke-MelonApi -Method GET -Path '/api/admin/permissions' -Token $Token -Query @{ departmentId = $DepartmentId; applicationId = $ApplicationId })
    $map = @{}
    foreach ($row in $rows) { $map[$row.code] = [long]$row.id }
    foreach ($definition in $definitions) {
        if (-not $map.ContainsKey($definition[1])) {
            $created = Invoke-MelonApi -Method POST -Path '/api/admin/permissions' -Token $Token -Query @{ departmentId = $DepartmentId; applicationId = $ApplicationId } -Body @{
                name = $definition[0]; code = $definition[1]; resource = $definition[2]; action = $definition[3]
            }
            $map[$definition[1]] = [long]$created.id
        }
    }
    return $map
}

function Ensure-Role {
    param([string]$Token, [long]$DepartmentId, [long]$ApplicationId, [hashtable]$PermissionIds, [string]$Code, [string]$Name, [string[]]$PermissionCodes)
    $rows = @(Invoke-MelonApi -Method GET -Path '/api/admin/roles' -Token $Token -Query @{ departmentId = $DepartmentId; applicationId = $ApplicationId })
    $role = $rows | Where-Object { $_.code -eq $Code } | Select-Object -First 1
    if (-not $role) {
        $role = Invoke-MelonApi -Method POST -Path '/api/admin/roles' -Token $Token -Query @{ departmentId = $DepartmentId; applicationId = $ApplicationId } -Body @{ name = $Name; code = $Code; description = $Name }
        $roleId = [long]$role.id
    } else {
        $roleId = [long]$role.id
    }
    $ids = @($PermissionCodes | ForEach-Object { [long]$PermissionIds[$_] })
    Invoke-MelonApi -Method PUT -Path ("/api/admin/roles/{0}/permissions" -f $roleId) -Token $Token -Query @{ departmentId = $DepartmentId; applicationId = $ApplicationId } -Body @{ ids = $ids }
    return $roleId
}

$configuration = Read-RootConfiguration
$login = Invoke-MelonApi -Method POST -Path '/api/auth/login' -Body @{ username = $configuration.ADMIN_USERNAME; password = $configuration.ADMIN_PASSWORD }
$token = [string]$login.token
$departmentId = Get-OrCreateDepartment -Token $token
$applicationId = Get-OrCreateApplication -Token $token
$permissionIds = Ensure-Permissions -Token $token -DepartmentId $departmentId -ApplicationId $applicationId
$allCodes = @($permissionIds.Keys)
$adminRole = Ensure-Role -Token $token -DepartmentId $departmentId -ApplicationId $applicationId -PermissionIds $permissionIds -Code 'admin' -Name '课程管理员' -PermissionCodes $allCodes
$teacherRole = Ensure-Role -Token $token -DepartmentId $departmentId -ApplicationId $applicationId -PermissionIds $permissionIds -Code 'teacher' -Name '教师' -PermissionCodes @('CV','CE','CC','CTM','ORG_VIEW','UL')
$studentRole = Ensure-Role -Token $token -DepartmentId $departmentId -ApplicationId $applicationId -PermissionIds $permissionIds -Code 'student' -Name '学生' -PermissionCodes @('CV','ORG_VIEW')

$rows = Import-Csv -LiteralPath $UsersFile
foreach ($batch in ($rows | ForEach-Object -Begin { $buffer = @() } -Process { $buffer += $_; if ($buffer.Count -ge 500) { ,$buffer; $buffer = @() } } -End { if ($buffer.Count -gt 0) { ,$buffer } })) {
    $payload = @{
        users = @($batch | ForEach-Object {
            @{ name = $_.name; username = $_.username; password = $_.password; email = $_.email; departmentIds = @($departmentId) }
        })
    }
    Invoke-MelonApi -Method POST -Path '/api/admin/identity/users/import' -Token $token -Body $payload | Out-Null
}

$imported = @(Invoke-MelonApi -Method GET -Path '/api/admin/users' -Token $token -Query @{ departmentId = $departmentId; page = 1; size = 200 })
foreach ($user in $imported.items) {
    $source = $rows | Where-Object { $_.username -eq $user.externalId } | Select-Object -First 1
    if (-not $source) { continue }
    $roleId = if ($source.role -eq 'admin') { $adminRole } elseif ($source.role -eq 'teacher') { $teacherRole } else { $studentRole }
    Invoke-MelonApi -Method PUT -Path ("/api/admin/users/{0}/roles" -f $user.id) -Token $token -Query @{ departmentId = $departmentId; applicationId = $applicationId } -Body @{ ids = @($roleId) } | Out-Null
}

Write-Output ('课程系统联调权限已准备。departmentId={0}, applicationId={1}, importedUsers={2}' -f $departmentId, $applicationId, $rows.Count)
