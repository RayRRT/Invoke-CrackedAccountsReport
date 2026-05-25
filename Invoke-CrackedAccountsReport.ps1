<#
.SYNOPSIS
    Correlates cracked NTLM hashes with AD group memberships to highlight
    compromised privileged accounts.

.PARAMETER NtdsFile
    Path to the NTDS dump (secretsdump.py format: user:RID:LM:NTLM:::)

.PARAMETER PotFile
    Path to the hashcat potfile (format: hash:password)

.PARAMETER GroupsFile
    Path to the users-groups CSV (columns: SamAccountName, Groups)
    Groups should be semicolon-separated.

.PARAMETER OutputFile
    Path for the final CSV report. Defaults to .\report_cracked.csv

.EXAMPLE
    .\Invoke-CrackedAccountsReport.ps1 -NtdsFile .\ntds.txt -PotFile .\hashcat.potfile -GroupsFile .\users_groups.csv
#>

param(
    [Parameter(Mandatory)][string]$NtdsFile,
    [Parameter(Mandatory)][string]$PotFile,
    [Parameter(Mandatory)][string]$GroupsFile,
    [string]$OutputFile = ".\report_cracked.csv"
)

# High-value groups (edit to fit the target environment)
$highValueGroups = @(
    'Domain Admins', 'Enterprise Admins', 'Schema Admins',
    'Administrators', 'Account Operators', 'Backup Operators',
    'Server Operators', 'Print Operators', 'DnsAdmins',
    'Group Policy Creator Owners', 'Protected Users',
    'Cert Publishers', 'Key Admins', 'Enterprise Key Admins'
)

# === 1. Load potfile ===
Write-Host "[*] Loading potfile..." -ForegroundColor Cyan
$pot = @{}
$reader = [System.IO.StreamReader]::new($PotFile)
while (($line = $reader.ReadLine()) -ne $null) {
    $idx = $line.IndexOf(':')
    if ($idx -gt 0) {
        $pot[$line.Substring(0, $idx).ToLower()] = $line.Substring($idx + 1)
    }
}
$reader.Close()
Write-Host "    $($pot.Count) hashes in potfile" -ForegroundColor Green

# === 2. Load groups ===
Write-Host "[*] Loading groups..." -ForegroundColor Cyan
$userGroups = @{}
Import-Csv $GroupsFile | ForEach-Object {
    if ($_.SamAccountName) {
        $userGroups[$_.SamAccountName.ToLower()] = ($_.Groups -split ';') | Where-Object { $_ }
    }
}
Write-Host "    $($userGroups.Count) users with group memberships" -ForegroundColor Green

# === 3. Process NTDS ===
Write-Host "[*] Correlating NTDS..." -ForegroundColor Cyan
$results = New-Object System.Collections.Generic.List[object]
$reader = [System.IO.StreamReader]::new($NtdsFile)
while (($line = $reader.ReadLine()) -ne $null) {
    $parts = $line -split ':'
    if ($parts.Count -lt 4) { continue }

    $userRaw = $parts[0]
    $ntlm    = $parts[3].ToLower()
    $user    = ($userRaw -split '\\')[-1].ToLower()

    if ($user -like '*$') { continue }
    if (-not $ntlm)        { continue }

    $password   = if ($pot.ContainsKey($ntlm)) { $pot[$ntlm] } else { $null }
    $groups     = if ($userGroups.ContainsKey($user)) { $userGroups[$user] } else { @() }
    $highValue  = $groups | Where-Object { $highValueGroups -contains $_ }
    $isService  = $userRaw -match '(?i)svc|service|srv_|_svc|admin'

    $results.Add([PSCustomObject]@{
        User        = $userRaw
        Cracked     = [bool]$password
        Password    = $password
        IsHighValue = [bool]$highValue
        IsService   = [bool]$isService
        PrivGroups  = ($highValue -join '; ')
        AllGroups   = ($groups -join '; ')
        NTLM        = $ntlm
    })
}
$reader.Close()

# === 4. Summary ===
$crackedHigh = $results | Where-Object { $_.Cracked -and $_.IsHighValue }
$crackedSvc  = $results | Where-Object { $_.Cracked -and $_.IsService -and -not $_.IsHighValue }
$total       = $results.Count
$cracked     = ($results | Where-Object Cracked).Count
$highTotal   = ($results | Where-Object IsHighValue).Count

Write-Host ""
Write-Host "================ SUMMARY ================" -ForegroundColor Yellow
Write-Host "Total users:            $total"
if ($total -gt 0) {
    Write-Host "Cracked:                $cracked ($([math]::Round($cracked/$total*100,1))%)"
}
Write-Host "High-value users:       $highTotal"
Write-Host "High-value cracked:     $($crackedHigh.Count)" -ForegroundColor Red
Write-Host "========================================="
Write-Host ""

if ($crackedHigh.Count -gt 0) {
    Write-Host "[!] PRIVILEGED ACCOUNTS CRACKED:" -ForegroundColor Red
    $crackedHigh | Select-Object User, Password, PrivGroups | Format-Table -AutoSize -Wrap
}

if ($crackedSvc.Count -gt 0) {
    Write-Host "[!] SERVICE/ADMIN ACCOUNTS (name heuristic):" -ForegroundColor Yellow
    $crackedSvc | Select-Object User, Password, AllGroups | Format-Table -AutoSize -Wrap
}

# === 5. Password reuse ===
Write-Host "[*] Detecting password reuse..." -ForegroundColor Cyan
$reused = $results | Where-Object { $_.NTLM } | Group-Object NTLM | Where-Object { $_.Count -gt 1 }
if ($reused) {
    Write-Host "[!] Hashes shared by multiple users:" -ForegroundColor Yellow
    foreach ($g in $reused | Sort-Object Count -Descending | Select-Object -First 20) {
        $users = ($g.Group.User) -join ', '
        $pwd   = ($g.Group | Where-Object Cracked | Select-Object -First 1).Password
        $extra = if ($pwd) { " -> '$pwd'" } else { "" }
        Write-Host "  ($($g.Count)) $users$extra"
    }
}

# === 6. Export ===
$results | Sort-Object IsHighValue, Cracked -Descending | Export-Csv $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "[+] Full report saved: $OutputFile" -ForegroundColor Green
