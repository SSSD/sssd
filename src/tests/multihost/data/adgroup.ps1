#Following Powershell script will add the group in AD server
#and set GroupScope as Global and GroupCtegory as Security and
#also set MemberOf BuiltIn group as Administrator

Import-Module ActiveDirectory

$grname = -join ((65..90) + (97..122) | Get-Random -Count 7 | % {[char]$_})

Write-Host $grname

New-ADGroup -Name $grname -GroupScope Global -GroupCategory Security

Add-ADPrincipalGroupMembership -MemberOf Administrators -Identity $grname
