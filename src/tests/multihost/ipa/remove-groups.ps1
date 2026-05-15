#Add the Active Directory module
Import-Module ActiveDirectory

#set default password
$groups = Import-Csv .\groups.csv
$nestedgroups = Import-Csv .\nestedgroups.csv

foreach ($group in $groups) {
	try
	{
		Write-Output "Remove Group $($group.GroupName)"
		Remove-ADGroup -Identity $group.GroupName -Confirm:$false
	}
	catch [System.Object]
	{
		Write-Output "Could not delete group $($group.GroupName)"
	}
}

foreach ($nestedgroup in $nestedgroups) {
	try
	{
		Write-Output "Remove NestedGroup $($nestedgroup.NestedGroupName)"
		Remove-ADGroup -Identity $nestedgroup.NestedGroupName -Confirm:$false
	}
	catch [System.Object]
	{
		Write-Output "Could not delete group $($group.GroupName)"
	}
}
