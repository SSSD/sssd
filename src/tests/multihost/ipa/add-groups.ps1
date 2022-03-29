#add-groups.ps1
#Author: mrniranjan@redhat.com
#This program Creates Global Groups in Windows Active Directory
#It reads groups.csv file containing list of groups. Currently
#groups.csv file contains 20 Groups
#
#To add members to the groups, this script reads users.csv
#file and adds all the users to all the 20 Groups.
#Add the Active Directory module
Import-Module ActiveDirectory

#set default password
$groups = Import-Csv .\groups.csv
$users = Import-Csv .\users.csv
$nestedgroups = Import-Csv .\nestedgroups.csv

foreach ($group in $groups) {
	try
	{
		Write-Output "Add Group $($group.GroupName)"
		New-ADGroup -Name $group.GroupName -GroupScope Global
	}
	catch [System.Object]
	{
		Write-Output "Could not create group $($group.GroupName)"
	}

}

foreach ($nestedgroup in $nestedgroups) {
        try
        {
                Write-Output "Add Group $($nestedgroup.NestedGroupName)"
                New-ADGroup -Name $nestedgroup.NestedGroupName -GroupScope Global
        }
        catch [System.Object]
        {
                Write-Output "Could not create Nested Group $($nestedgroup.NestedGroupName)"
        }
}

foreach ($group in $groups) {
	foreach ($user in $users) {
		try
		{
			Write-Output "Adding $($user.SamAccountName) as member to $($group.GroupName)"
			Add-ADGroupMember -Identity $group.GroupName -Members $user.SamAccountName
		}
		catch [System.Object]
		{
			Write-Output "Could not add $($user.SamAccountName) as a member to $($group.GroupName)"
		}
	}
}

foreach ($nestedgroup in $nestedgroups) {
        foreach ($group in $groups) {
                try
                {
                        Write-Output "Add $($group.GroupName) as member of $($nestedgroup.NestedGroupName)"
                        Add-ADGroupMember -Identity $nestedgroup.NestedGroupName -Members $group.GroupName
                }
                catch [System.Object]
                {
                        Write-Output "Could not add $($group.GroupName) as a member to $($nestedgroup.NestedGroupName)"
                }
        }
}
