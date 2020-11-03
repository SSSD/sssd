#add-users.ps1
#Author: mrniranjan@redhat.com
#This script creates Windows AD users.
#user information is read from users.csv file
#Users in csv file are defined in below format:
#FirstName,LastName,SamAccountName
#idm_perf_user1,perf_user1,idm_perf_user1
#Add the Active Directory module
Import-Module ActiveDirectory

#set default password
$defpassword = (ConvertTo-SecureString "Secret123" -AsPlainText -force)


$dnsroot = '@'+(Get-ADDomain).dnsroot

$users = Import-Csv .\users.csv

foreach ($user in $users) {
	try
	{
		New-ADUser -SamAccountName $user.SamAccountName -Name ($user.FirstName + " " + $user.LastName) `
		-DisplayName ($user.FirstName + " " + $user.LastName) -GivenName $user.FirstName -SurName $user.LastName `
		-EmailAddress ($user.SamAccountName + $dnsroot) -userPrincipalName ($user.SamAccountName + $dnsroot) `
		-Title $user.title -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true `
		-AccountPassword $defpassword -PassThru `
	}
	catch [System.Object]
	{
		Write-Output "Could not create user $($user.SamAccountName), $_"
	}

}
