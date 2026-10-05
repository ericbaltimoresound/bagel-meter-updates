<#
  Bagel Meter share helper for Windows.

  Sends your Claude Code and Codex usage (percentages, plan names, reset times and which
  account each one is, encrypted) to a friend's Bagel Meter. It never sends your logins.
  Add -HideEmails when setting up to leave the account emails out.

  Set up:   right-click this file > Run with PowerShell, then paste the invite code.
  Stop:     run it again and choose "Stop sharing".
  Runs every 10 minutes in the background while you're signed in to Windows.
#>
param(
    [string]$Name,         # set up without prompts: your name ...
    [string]$Code,         # ... and the invite code
    [switch]$Run,          # quiet background run (used by the scheduled task)
    [switch]$Once,         # one run with output, for checking
    [switch]$Stop,         # turn sharing off
    [switch]$HideEmails,   # set up without sending account emails
    [string]$SelfTest      # path to a test folder (development only)
)

$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

$Version  = '1.3.4'
$TaskName = 'Bagel Meter Share'
$HomeDir  = [Environment]::GetFolderPath('UserProfile')
if ($env:BAGEL_HOME) { $HomeDir = $env:BAGEL_HOME }
if ($env:APPDATA) { $AppDir = Join-Path $env:APPDATA 'BagelMeter' } else { $AppDir = Join-Path $HomeDir '.bagelmeter' }
$ConfigFile = Join-Path $AppDir 'config.json'
$StateFile  = Join-Path $AppDir 'last-sent.json'
$LogFile    = Join-Path $AppDir 'log.txt'
$Utf8NoBom  = New-Object System.Text.UTF8Encoding($false)

function Write-Log($text) {
    try {
        if (-not (Test-Path $AppDir)) { New-Item -ItemType Directory -Path $AppDir | Out-Null }
        $line = (Get-Date).ToString('yyyy-MM-dd HH:mm') + '  ' + $text
        Add-Content -Path $LogFile -Value $line
        $all = Get-Content $LogFile
        if ($all.Count -gt 300) { $all | Select-Object -Last 200 | Set-Content $LogFile }
    } catch { }
}

function Now-Seconds { [double][DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

# ---------- invite code and encryption ----------

function From-Base64Url([string]$text) {
    $t = $text.Replace('-', '+').Replace('_', '/')
    while ($t.Length % 4 -ne 0) { $t += '=' }
    return [Convert]::FromBase64String($t)
}

function Read-Invite([string]$code) {
    $parts = $code.Trim().Split('.')
    if ($parts.Count -ne 3 -or $parts[0] -ne 'bagel1') { return $null }
    try { $key = From-Base64Url $parts[2] } catch { return $null }
    if ($key.Length -ne 32) { return $null }
    return @{ Topic = $parts[1]; Key = $key }
}

function Get-Hmac([byte[]]$key, [byte[]]$data) {
    $h = New-Object System.Security.Cryptography.HMACSHA256 (, $key)
    try { return $h.ComputeHash($data) } finally { $h.Dispose() }
}

# Windows PowerShell has no AES-GCM, so this uses AES-256-CBC plus an HMAC-SHA256 check
# ("b2:" format). Bagel Meter on the Mac reads both formats.
function Protect-Text([byte[]]$key, [string]$plain) {
    $encKey = Get-Hmac $key ([Text.Encoding]::UTF8.GetBytes('bagel-enc'))
    $macKey = Get-Hmac $key ([Text.Encoding]::UTF8.GetBytes('bagel-mac'))
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $encKey
    $aes.GenerateIV()
    $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
    $enc = $aes.CreateEncryptor()
    $cipher = $enc.TransformFinalBlock($bytes, 0, $bytes.Length)
    $signed = New-Object byte[] ($aes.IV.Length + $cipher.Length)
    [Array]::Copy($aes.IV, 0, $signed, 0, $aes.IV.Length)
    [Array]::Copy($cipher, 0, $signed, $aes.IV.Length, $cipher.Length)
    $tag = Get-Hmac $macKey $signed
    $all = New-Object byte[] ($signed.Length + $tag.Length)
    [Array]::Copy($signed, 0, $all, 0, $signed.Length)
    [Array]::Copy($tag, 0, $all, $signed.Length, $tag.Length)
    $aes.Dispose()
    return 'b2:' + [Convert]::ToBase64String($all)
}

# ---------- small helpers ----------

function Read-JsonFile($path) {
    if (-not (Test-Path $path)) { return $null }
    try { return (Get-Content -Raw -Path $path -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

function Save-JsonFile($path, $object) {
    $json = $object | ConvertTo-Json -Depth 20
    $temp = $path + '.bagel-tmp'
    [IO.File]::WriteAllText($temp, $json, $Utf8NoBom)
    Move-Item -Force -Path $temp -Destination $path
}

function Get-JwtClaims([string]$token) {
    if (-not $token) { return $null }
    $parts = $token.Split('.')
    if ($parts.Count -lt 2) { return $null }
    try { return ([Text.Encoding]::UTF8.GetString((From-Base64Url $parts[1])) | ConvertFrom-Json) } catch { return $null }
}

function Get-Prop($object, [string]$name) {
    if ($null -eq $object) { return $null }
    $p = $object.PSObject.Properties[$name]
    if ($p) { return $p.Value } else { return $null }
}

function Pretty-Plan($raw) {
    if (-not $raw) { return $null }
    $words = ([string]$raw).Replace('_', ' ').Split(' ') | Where-Object { $_ } | ForEach-Object { $_.Substring(0,1).ToUpper() + $_.Substring(1) }
    return ($words -join ' ')
}

function To-Epoch($iso) {
    if (-not $iso) { return $null }
    try { return [double][DateTimeOffset]::Parse([string]$iso, [Globalization.CultureInfo]::InvariantCulture).ToUnixTimeSeconds() } catch { return $null }
}

function Post-Json([string]$url, $body) {
    $json = $body | ConvertTo-Json -Depth 5 -Compress
    return Invoke-RestMethod -UseBasicParsing -Method Post -Uri $url -ContentType 'application/json' -Body $json -TimeoutSec 30
}

# True when the Claude Code / Codex command-line tool is running. The Claude and ChatGPT
# desktop apps use the same program names, so anything installed as an app is ignored.
function Is-Running([string]$name) {
    $found = Get-Process -Name $name -ErrorAction SilentlyContinue | Where-Object {
        $p = ''
        try { $p = [string]$_.Path } catch { }
        -not ($p -like '*\AnthropicClaude\*' -or $p -like '*\WindowsApps\*' -or $p -like '*\Programs\Claude\*' -or $p -like '*\ChatGPT\*' -or $p -like '*\OpenAI\*')
    }
    return [bool]$found
}

# ---------- usage parsing (same rules as the Mac app) ----------

function Parse-ClaudeLimits($body) {
    $out = New-Object System.Collections.ArrayList
    $items = Get-Prop $body 'limits'
    if ($items) {
        foreach ($item in $items) {
            $kind = [string](Get-Prop $item 'kind')
            $scope = Get-Prop $item 'scope'
            $scopeName = Get-Prop (Get-Prop $scope 'model') 'display_name'
            if (-not $scopeName) { $scopeName = Get-Prop (Get-Prop $scope 'surface') 'display_name' }
            switch ($kind) {
                'session'       { $label = '5-hour' }
                'weekly_all'    { $label = '7-day' }
                'weekly_scoped' { if ($scopeName) { $label = '7-day ' + $scopeName } else { $label = '7-day model' } }
                default         { $label = $kind.Replace('_', ' ') }
            }
            $used = Get-Prop $item 'percent'; if ($null -eq $used) { $used = 0 }
            [void]$out.Add([ordered]@{ label = $label; used = [double]$used; resetsAt = (To-Epoch (Get-Prop $item 'resets_at')); wide = ($kind -ne 'weekly_scoped') })
        }
        return ,$out
    }
    $older = @(@('five_hour','5-hour',$true), @('seven_day','7-day',$true), @('seven_day_opus','7-day Opus',$false), @('seven_day_sonnet','7-day Sonnet',$false))
    foreach ($o in $older) {
        $w = Get-Prop $body $o[0]
        if ($w) {
            $used = Get-Prop $w 'utilization'; if ($null -eq $used) { $used = 0 }
            [void]$out.Add([ordered]@{ label = $o[1]; used = [double]$used; resetsAt = (To-Epoch (Get-Prop $w 'resets_at')); wide = $o[2] })
        }
    }
    return ,$out
}

function Window-Name([double]$seconds) {
    $hours = [int][Math]::Round($seconds / 3600)
    if ($hours -le 0) { return 'Limit' }
    if ($hours % 24 -eq 0) { return ([string]($hours / 24)) + '-day' }
    return ([string]$hours) + '-hour'
}

function Parse-CodexLimits($body) {
    $out = New-Object System.Collections.ArrayList
    foreach ($group in @(@('rate_limit', $null, $true), @('code_review_rate_limit', 'Code review', $false))) {
        $g = Get-Prop $body $group[0]
        if (-not $g) { continue }
        foreach ($key in @('primary_window', 'secondary_window')) {
            $w = Get-Prop $g $key
            if (-not $w) { continue }
            $name = Window-Name ([double](Get-Prop $w 'limit_window_seconds'))
            if ($group[1]) { $name = $group[1] + ' ' + $name }
            $reset = Get-Prop $w 'reset_at'
            if ($null -eq $reset) {
                $after = Get-Prop $w 'reset_after_seconds'
                if ($null -ne $after) { $reset = (Now-Seconds) + [double]$after }
            }
            $used = Get-Prop $w 'used_percent'; if ($null -eq $used) { $used = 0 }
            if ($null -ne $reset) { $reset = [double]$reset }
            [void]$out.Add([ordered]@{ label = $name; used = [double]$used; resetsAt = $reset; wide = $group[2] })
        }
    }
    return ,$out
}

# ---------- reading each account ----------

# Which account Claude Code on this PC is signed in as. The command-line tool keeps it in
# %USERPROFILE%\.claude.json, the Claude desktop app in .claude\.claude.json; an old copy of
# one can linger after switching accounts, so the most recently changed file wins.
function Get-ClaudeEmail([string]$dir) {
    $files = @((Join-Path $dir '.claude.json'))
    if ($dir -eq (Join-Path $HomeDir '.claude')) { $files += (Join-Path $HomeDir '.claude.json') }
    $best = $null; $bestTime = [DateTime]::MinValue
    foreach ($f in $files) {
        if (-not (Test-Path $f)) { continue }
        $email = Get-Prop (Get-Prop (Read-JsonFile $f) 'oauthAccount') 'emailAddress'
        $time = (Get-Item -Force $f).LastWriteTimeUtc
        if ($email -and $time -gt $bestTime) { $best = $email; $bestTime = $time }
    }
    return $best
}

function Get-ClaudeAccount([string]$dir) {
    $file = Join-Path $dir '.credentials.json'
    $creds = Read-JsonFile $file
    $oauth = Get-Prop $creds 'claudeAiOauth'
    if (-not $oauth -or -not (Get-Prop $oauth 'accessToken')) {
        # Signed in only through the Claude desktop app. Its login can't (and shouldn't) be read,
        # but which account it is and when it was last used here can, so My devices still shows it.
        $email = Get-ClaudeEmail $dir
        if ($email -or (Last-Used $dir 'projects')) {
            return [ordered]@{ plan = 'Claude app'; error = $null; limits = (New-Object System.Collections.ArrayList); email = $email }
        }
        return $null
    }
    $result = [ordered]@{ plan = (Pretty-Plan (Get-Prop $oauth 'subscriptionType')); error = $null; limits = (New-Object System.Collections.ArrayList); email = $null }
    $result.email = Get-ClaudeEmail $dir

    $expires = [double](Get-Prop $oauth 'expiresAt')
    $nowMs = (Now-Seconds) * 1000
    if ($expires -lt $nowMs + 300000) {
        if (Is-Running 'claude') {
            if ($expires -lt $nowMs) { $result.error = 'Claude Code is open; waiting for it to refresh'; return $result }
        } else {
            # Renew the same way Claude Code does, and save it back for Claude Code to use.
            $body = @{ grant_type = 'refresh_token'; refresh_token = (Get-Prop $oauth 'refreshToken'); client_id = '9d1c250a-e61b-44d9-88ed-5944d1962f5e' }
            $scopes = Get-Prop $oauth 'scopes'
            if ($scopes) { $body.scope = ($scopes -join ' ') }
            try {
                $r = Post-Json 'https://platform.claude.com/v1/oauth/token' $body
            } catch {
                $result.error = 'Signed out. Open Claude Code and run /login'; return $result
            }
            $oauth.accessToken = $r.access_token
            if ($r.refresh_token) { $oauth.refreshToken = $r.refresh_token }
            $life = 3600; if ($r.expires_in) { $life = [double]$r.expires_in }
            $oauth.expiresAt = [int64]($nowMs + $life * 1000)
            Save-JsonFile $file $creds
        }
    }

    try {
        $headers = @{ Authorization = 'Bearer ' + $oauth.accessToken; 'anthropic-beta' = 'oauth-2025-04-20' }
        $usage = Invoke-RestMethod -UseBasicParsing -Uri 'https://api.anthropic.com/api/oauth/usage' -Headers $headers -TimeoutSec 30
        $result.limits = Parse-ClaudeLimits $usage
    } catch {
        $result.error = 'Usage check failed'
    }
    return $result
}

function Get-CodexAccount([string]$dir) {
    $file = Join-Path $dir 'auth.json'
    $auth = Read-JsonFile $file
    $tokens = Get-Prop $auth 'tokens'
    if (-not $tokens -or -not (Get-Prop $tokens 'access_token')) { return $null }
    $result = [ordered]@{ plan = $null; error = $null; limits = (New-Object System.Collections.ArrayList); email = $null }
    $result.email = Get-Prop (Get-JwtClaims (Get-Prop $tokens 'id_token')) 'email'

    $exp = Get-Prop (Get-JwtClaims $tokens.access_token) 'exp'
    if ($exp -and [double]$exp -lt (Now-Seconds) + 300) {
        if (Is-Running 'codex') {
            if ([double]$exp -lt (Now-Seconds)) { $result.error = 'Codex is open; waiting for it to refresh'; return $result }
        } else {
            $body = @{ client_id = 'app_EMoamEEZ73f0CkXaXp7hrann'; grant_type = 'refresh_token'; refresh_token = $tokens.refresh_token; scope = 'openid profile email' }
            try {
                $r = Post-Json 'https://auth.openai.com/oauth/token' $body
            } catch {
                $result.error = 'Signed out. Run: codex login'; return $result
            }
            $tokens.access_token = $r.access_token
            if ($r.id_token) { $tokens.id_token = $r.id_token }
            if ($r.refresh_token) { $tokens.refresh_token = $r.refresh_token }
            if ($auth.PSObject.Properties['last_refresh']) { $auth.last_refresh = [DateTime]::UtcNow.ToString('o') }
            Save-JsonFile $file $auth
        }
    }

    try {
        $headers = @{ Authorization = 'Bearer ' + $tokens.access_token }
        if (Get-Prop $tokens 'account_id') { $headers['ChatGPT-Account-Id'] = $tokens.account_id }
        $usage = Invoke-RestMethod -UseBasicParsing -Uri 'https://chatgpt.com/backend-api/wham/usage' -Headers $headers -UserAgent 'codex-cli' -TimeoutSec 30
        $result.plan = Pretty-Plan (Get-Prop $usage 'plan_type')
        if (-not $result.email) { $result.email = Get-Prop $usage 'email' }
        $result.limits = Parse-CodexLimits $usage
    } catch {
        $result.error = 'Usage check failed'
    }
    return $result
}

function Get-AccountFolders([string]$stem) {
    $found = New-Object System.Collections.ArrayList
    $main = Join-Path $HomeDir $stem
    if (Test-Path $main) { [void]$found.Add($main) }
    Get-ChildItem -Path $HomeDir -Directory -Force -Filter ($stem + '-*') -ErrorAction SilentlyContinue |
        Sort-Object Name | ForEach-Object { [void]$found.Add($_.FullName) }
    return ,$found
}

# When this account was last used on this PC: the newest session log, rounded to 5 minutes.
# Claude Code writes <folder>\projects\...\*.jsonl, Codex writes <folder>\sessions\...\*.jsonl.
function Last-Used([string]$dir, [string]$sub) {
    $root = Join-Path $dir $sub
    if (-not (Test-Path $root)) { return $null }
    $f = Get-ChildItem -Path $root -Recurse -File -Filter '*.jsonl' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if (-not $f) { return $null }
    $t = [double]([DateTimeOffset]$f.LastWriteTimeUtc).ToUnixTimeSeconds()
    return [Math]::Floor($t / 300) * 300
}

function Build-Snapshot([string]$name, [bool]$hideEmails) {
    $accounts = New-Object System.Collections.ArrayList
    # "Open now" can only be told apart per account when there's one folder for that tool.
    $claudeDirs = Get-AccountFolders '.claude'
    $claudeOpen = $null; if ($claudeDirs.Count -eq 1) { $claudeOpen = [bool](Is-Running 'claude') }
    $n = 0
    foreach ($dir in $claudeDirs) {
        $a = Get-ClaudeAccount $dir
        if ($null -eq $a) { continue }
        $n++
        $email = $a.email; if ($hideEmails) { $email = $null }
        [void]$accounts.Add([ordered]@{ id = 'win-claude-' + (Split-Path $dir -Leaf); provider = 'claude'; title = 'Claude ' + $n; plan = $a.plan; error = $a.error; limits = $a.limits; email = $email; openNow = $claudeOpen; lastUsed = (Last-Used $dir 'projects') })
    }
    $codexDirs = Get-AccountFolders '.codex'
    $codexOpen = $null; if ($codexDirs.Count -eq 1) { $codexOpen = [bool](Is-Running 'codex') }
    $n = 0
    foreach ($dir in $codexDirs) {
        $a = Get-CodexAccount $dir
        if ($null -eq $a) { continue }
        $n++
        $email = $a.email; if ($hideEmails) { $email = $null }
        [void]$accounts.Add([ordered]@{ id = 'win-codex-' + (Split-Path $dir -Leaf); provider = 'codex'; title = 'Codex ' + $n; plan = $a.plan; error = $a.error; limits = $a.limits; email = $email; openNow = $codexOpen; lastUsed = (Last-Used $dir 'sessions') })
    }
    return [ordered]@{ v = 1; name = $name; sentAt = 0; accounts = $accounts }
}

# ---------- sending ----------

function Send-Usage([switch]$Force, [switch]$Loud) {
    $config = Read-JsonFile $ConfigFile
    if (-not $config) { if ($Loud) { Write-Host 'Sharing is not set up yet.' }; return }
    $invite = Read-Invite $config.code
    if (-not $invite) { Write-Log 'Invite code in config is not valid.'; return }

    $snap = Build-Snapshot $config.name ([bool](Get-Prop $config 'hideEmails'))
    if ($snap.accounts.Count -eq 0) {
        Write-Log 'No Claude Code or Codex sign-in found.'
        if ($Loud) { Write-Host 'No Claude Code or Codex sign-in found on this PC.' -ForegroundColor Yellow }
        return
    }
    $fingerprint = ($snap | ConvertTo-Json -Depth 10 -Compress)
    $last = Read-JsonFile $StateFile
    $age = 1e9
    if ($last) { $age = (Now-Seconds) - [double]$last.at }
    $changed = (-not $last) -or ($last.fingerprint -ne $fingerprint)
    if (-not $Force -and -not (($changed -and $age -ge 600) -or $age -ge 3600)) { return }

    $snap.sentAt = Now-Seconds
    $payload = Protect-Text $invite.Key ($snap | ConvertTo-Json -Depth 10 -Compress)
    Invoke-WebRequest -UseBasicParsing -Method Post -Uri ('https://ntfy.sh/' + $invite.Topic) -Body $payload -TimeoutSec 30 | Out-Null
    Save-JsonFile $StateFile ([ordered]@{ at = (Now-Seconds); fingerprint = $fingerprint })
    Write-Log ('Sent ' + $snap.accounts.Count + ' account(s).')

    if ($Loud) {
        foreach ($a in $snap.accounts) {
            $line = '  ' + $a.title
            if ($a.email) { $line += ' ' + $a.email }
            if ($a.plan) { $line += ' (' + $a.plan + ')' }
            if ($a.error) { $line += ': ' + $a.error }
            foreach ($l in $a.limits) { $line += '  ' + $l.label + ' ' + [int][Math]::Round(100 - $l.used) + '% left' }
            Write-Host $line
        }
    }
}

# ---------- background task ----------

function Install-Task([string]$scriptPath) {
    $taskArgs = '--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '" -Run'
    $action = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument $taskArgs
    try {
        $every = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 10)
    } catch {
        $every = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 3650)
    }
    $logon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($every, $logon) -Settings $settings -Description 'Sends your Claude/Codex usage to a friend''s Bagel Meter.' -Force | Out-Null
}

function Remove-Task {
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop } catch { }
}

# ---------- entry points ----------

if ($SelfTest) {
    # Development check: parse saved API answers and encrypt a sample for the Mac to read.
    $claude = Parse-ClaudeLimits (Read-JsonFile (Join-Path $SelfTest 'claude-usage.json'))
    $codex = Parse-CodexLimits (Read-JsonFile (Join-Path $SelfTest 'codex-usage.json'))
    $invite = Read-Invite (Get-Content -Raw (Join-Path $SelfTest 'invite.txt'))
    $snap = [ordered]@{ v = 1; name = 'Windows Test'; sentAt = 1791200000; accounts = @(
        [ordered]@{ id = 'win-claude-.claude'; provider = 'claude'; title = 'Claude 1'; plan = 'Max'; error = $null; limits = $claude },
        [ordered]@{ id = 'win-codex-.codex'; provider = 'codex'; title = 'Codex 1'; plan = 'Pro'; error = $null; limits = $codex }) }
    $json = $snap | ConvertTo-Json -Depth 10 -Compress
    [IO.File]::WriteAllText((Join-Path $SelfTest 'snapshot.json'), $json, $Utf8NoBom)
    [IO.File]::WriteAllText((Join-Path $SelfTest 'payload.txt'), (Protect-Text $invite.Key $json), $Utf8NoBom)
    Write-Host 'self-test files written'
    exit 0
}

if ($Run) {
    try { Send-Usage } catch { Write-Log ('Error: ' + $_.Exception.Message) }
    exit 0
}

if ($Once) {
    Send-Usage -Force -Loud
    exit 0
}

if ($Stop) {
    Remove-Task
    if (Test-Path $ConfigFile) { Remove-Item $ConfigFile -Force }
    Write-Host 'Sharing is off.'
    exit 0
}

# Interactive setup (what "Run with PowerShell" does).
Write-Host ''
Write-Host '  Bagel Meter: share my usage' -ForegroundColor Yellow
Write-Host '  Sends your usage numbers and account emails, encrypted. Never your logins.'
Write-Host ''

$existing = Read-JsonFile $ConfigFile
if ($existing -and -not $Code) {
    Write-Host ('  You are already sharing as ' + $existing.name + '.')
    $choice = Read-Host '  Type S to stop sharing, N to set up a new code, or press Enter to send an update now'
    if ($choice -match '^[sS]') { Remove-Task; Remove-Item $ConfigFile -Force; Write-Host '  Sharing is off.'; Read-Host '  Press Enter to close'; exit 0 }
    if ($choice -notmatch '^[nN]') { Send-Usage -Force -Loud; Read-Host '  Done. Press Enter to close'; exit 0 }
}

$name = ''
if ($Name) { $name = $Name.Trim() }
while (-not $name) { $name = (Read-Host '  Your name').Trim() }
$invite = $null
if ($Code) { $code = $Code; $invite = Read-Invite $code }
while (-not $invite) {
    $code = Read-Host '  Paste the invite code (starts with bagel1.)'
    $invite = Read-Invite $code
    if (-not $invite) { Write-Host '  That code does not look right. Copy the whole line from the message.' -ForegroundColor Red }
}

if (-not (Test-Path $AppDir)) { New-Item -ItemType Directory -Path $AppDir | Out-Null }
$dest = Join-Path $AppDir 'bagel-share.ps1'
if ($PSCommandPath -and ($PSCommandPath -ne $dest)) { Copy-Item -Force -Path $PSCommandPath -Destination $dest }
try { Unblock-File -Path $dest } catch { }
Save-JsonFile $ConfigFile ([ordered]@{ name = $name; code = $code.Trim(); version = $Version; hideEmails = [bool]$HideEmails })
if (Test-Path $StateFile) { Remove-Item $StateFile -Force }

Write-Host ''
Write-Host '  Checking your accounts...'
try {
    Send-Usage -Force -Loud
    Install-Task $dest
    Write-Host ''
    Write-Host '  All set. Your usage now updates every 10 minutes while this PC is on.' -ForegroundColor Green
    Write-Host '  To stop, run this file again and type S.'
} catch {
    Write-Host ('  Something went wrong: ' + $_.Exception.Message) -ForegroundColor Red
    Write-Log ('Setup error: ' + $_.Exception.Message)
}
Write-Host ''
Read-Host '  Press Enter to close'
