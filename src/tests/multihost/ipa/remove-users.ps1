#Add the Active Directory module
Import-Module ActiveDirectory

#set default password
$defpassword = (ConvertTo-SecureString "pass@word1" -AsPlainText -force)


$users = Import-Csv .\users.csv

foreach ($user in $users) {
	try
	{
		Write-Output "We are removing $($user.SamAccountName)"
		Remove-ADUser -Identity -Confirm:$false $user.SamAccountName
	}
	catch [System.Object]
	{
		Write-Output "Could not delete users $($user.SamAccountName), $_"
	}
}
