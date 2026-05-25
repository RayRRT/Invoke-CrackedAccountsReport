# Cracked Accounts Report

PowerShell script for **authorized** internal pentests and AD password audits.
Correlates a hashcat potfile, an NTDS dump and an AD users-groups export to
highlight which privileged accounts ended up with their password in clear text.

## Inputs

| File              | Description                                                       |
| ----------------- | ----------------------------------------------------------------- |
| NTDS dump         | secretsdump.py format: `user:RID:LM:NTLM:::`                      |
| Hashcat potfile   | `hash:password` (NTLM)                                            |
| Users/Groups CSV  | Columns: `SamAccountName`, `Groups` (semicolon-separated)         |

The users/groups CSV can be generated without RSAT via ADSI:

```powershell
$s = New-Object DirectoryServices.DirectorySearcher
$s.Filter = "(&(objectCategory=user)(objectClass=user))"
$s.PropertiesToLoad.AddRange(@('samaccountname','memberof'))
$s.PageSize = 1000
$s.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        SamAccountName = $_.Properties['samaccountname'][0]
        Groups = (($_.Properties['memberof']) |
            ForEach-Object { ($_ -split ',')[0] -replace 'CN=','' }) -join ';'
    }
} | Export-Csv users_groups.csv -NoTypeInformation -Encoding UTF8
```

## Usage

```powershell
.\Invoke-CrackedAccountsReport.ps1 `
    -NtdsFile      .\ntds.txt `
    -PotFile       .\hashcat.potfile `
    -GroupsFile    .\users_groups.csv `
    -OutputFile    .\report_cracked.csv
```

## Output

- Console summary with crack rate and privileged accounts compromised.
- Service/admin accounts detected by name heuristic.
- Password reuse (hash shared by multiple users).
- Full CSV report sorted with high-value cracked accounts first.

## Legal

Use only on systems you own or have **explicit written authorization** to test.
The author assumes no liability for misuse.

## License

MIT
