 # JAMF-Migrating_AD_mobile_accounts_to_local_user_accounts

This Script will Migrate an Active Directory mobile account to a local account
by the following process:

1. Detect if the Mac is bound to AD and if it is remove the Bind to AD
2. Display a list of the accounts with a UID greater than 1000
3. Get the JIM Server Name from JAMF with API Call and perform an LDAP Request 
	to the JAMF JIM Server and verify the User Account is in LDAP. If account is not 
	in LDAP then delete to clean up.
4. Remove the following attributes from the specified account:

	cached_groups
	cached_auth_policy
	CopyTimestamp - This attribute is used by the OS to determine if the account is a mobile account
	SMBPrimaryGroupSID
	OriginalAuthenticationAuthority
	OriginalNodeName
	SMBSID
	SMBScriptPath
	SMBPasswordLastSet
	SMBGroupRID
	PrimaryNTDomain
	AppleMetaRecordName
	MCXSettings
	MCXFlags

5. Selectively modify the account's AuthenticationAuthority attribute to remove AD-specific attributes.
6. Restart the directory services process
7. Check to see if the conversion process succeeded by checking the OriginalNodeName attribute for the value "Active Directory"
8. If the conversion process succeeded, update the permissions on the account's home folder.
9. Perform an AuthOnly on the MacMDAdmin account and make sure the password is correct with the hash.
	Delete the old admin accounts.

	
## Jamf Variable Label Names

Parameter 4 -eq JAMF Instance URL (e.g. https://<YourJamf>.jamfcloud.com)
Parameter 5 -eq Your JAMF API Username
Parameter 6 -eq Your JAMF API Password
Parameter 7 -eq Your log file path. (Recommended "/Library/Logs/<Company Name>")
Parameter 8 -eq Your log file name. (Recommended "<scriptName>.log")
Parameter 9 -eq Your Company Name for the Log