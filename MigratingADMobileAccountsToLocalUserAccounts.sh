#!/bin/bash

##########################################################################################
# General Information
##########################################################################################
#
#	Script created By William Grzybowski February 22, 2022
#
	version="1.0.0" # Initial Creation of Script.
#
#	This Script will Migrate an Active Directory mobile account to a local account
#	by the following process:
#
#	1. Detect if the Mac is bound to AD and if it is remove the Bind to AD
#	2. Display a list of the accounts with a UID greater than 1000
#	3. Get the JIM Server Name from JAMF with API Call and perform an LDAP Request 
#	   to the JAMF JIM Server and verify the User Account is in LDAP. If account is not 
#	   in LDAP then delete to clean up.
#	4. Remove the following attributes from the specified account:
#	
#		cached_groups
#		cached_auth_policy
#		CopyTimestamp - This attribute is used by the OS to determine if the account is a mobile account
#		SMBPrimaryGroupSID
#		OriginalAuthenticationAuthority
#		OriginalNodeName
#		SMBSID
#		SMBScriptPath
#		SMBPasswordLastSet
#		SMBGroupRID
#		PrimaryNTDomain
#		AppleMetaRecordName
#		MCXSettings
#		MCXFlags
#
#	5. Selectively modify the account's AuthenticationAuthority attribute to remove AD-specific attributes.
#	6. Restart the directory services process
#	7. Check to see if the conversion process succeeded by checking the OriginalNodeName attribute for the value "Active Directory"
#	8. If the conversion process succeeded, update the permissions on the account's home folder.
#	9. Perform an AuthOnly on the MacMDAdmin account and make sure the password is correct with the hash.
#	   Delete the old admin accounts.
#
#
#	Jamf Variable Label Names
#
#	Parameter 4 -eq JAMF Instance URL (e.g. https://<YourJamf>.jamfcloud.com)
#	Parameter 5 -eq Your JAMF API Username
#	Parameter 6 -eq Your JAMF API Password
#	Parameter 7 -eq Your log file path. (Recommended "/Library/Logs/<Company Name>")
#	Parameter 8 -eq Your log file name. (Recommended "<scriptName>.log")
#	Parameter 9 -eq Your Company Name for the Log
#
##########################################################################################


##########################################################################################
# License information
##########################################################################################
#
#	Copyright (c) 2022 William Grzybowski
#
#	Permission is hereby granted, free of charge, to any person obtaining a copy
#	of this software and associated documentation files (the "Software"), to deal
#	in the Software without restriction, including without limitation the rights
#	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#	copies of the Software, and to permit persons to whom the Software is
#	furnished to do so, subject to the following conditions:
#
#	The above copyright notice and this permission notice shall be included in all
#	copies or substantial portions of the Software.
#
#	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#	SOFTWARE.
#
##########################################################################################


#########################################################################################
# Logging Information
#########################################################################################
#Build Logging for script
logFilePath="${7}"
logFile="${logFilePath}/${8}"
companyName="${9}"
logFileDate=`date +"%Y-%b-%d %T"`

# Check if log path exists
if [ ! -d "$logFilePath" ]; then
	mkdir $logFilePath
fi


# Logging Script
function readCommandOutputToLog(){
	if [ -n "$1" ];	then
		IN="$1"
	else
		while read IN 
		do
			echo "$(date +"%Y-%b-%d %T") : $IN" | tee -a "$logFile"
		done
	fi
}

( # To Capture output into Date and Time log file
	
	# Get Local Info
	logBannerDate=`date +"%Y-%b-%d %T"`
	
	echo " "
	echo "##########################################################################################"
	echo "#                                                                                        #"
	echo "#             Starting the AD Migration on the Mac - $logBannerDate                #"
	echo "#                                                                                        #"
	echo "##########################################################################################"
	echo "${companyName} AD Migration ${version} process on the Mac has Started..."
	
	
	##########################################################################################
	# JAMF API information
	##########################################################################################
	
	URL="${4}"
	username="${5}"
	password="${6}"
	
	# Get JIM Server Name
	JIMServerName=(`/usr/bin/curl "$URL/JSSResource/ldapservers" \
								--silent \
								--request GET \
								--user "$username:$password" \
								| /usr/bin/xpath -e "//ldap_servers/ldap_server/name/text()" 2> /dev/null`)
	
	
	##########################################################################################
	# Variables
	##########################################################################################
	
	# Get list of the accounts with a UID greater than 1000
	listUsers="$(/usr/bin/dscl . list /Users UniqueID | awk '$2 > 1000 {print $1}') FINISHED"
	check4AD=$(/usr/bin/dscl localhost -list . | grep "Active Directory")
	osvers=$(sw_vers -productVersion | awk -F. '{print $2}')
	
	
	##########################################################################################
	# Functions
	##########################################################################################
		
	# Remove Mac from AD
	RemoveAD(){
		
		echo "Starting the process to Remove AD now."
	
		# This function force-unbinds the Mac from the existing Active Directory domain
		# and updates the search path settings to remove references to Active Directory 
	
		echo getting current search path
		searchPath=$(/usr/bin/dscl /Search -read . CSPSearchPath | grep Active\ Directory | sed 's/^ //')
	
		# Force unbind from Active Directory
		echo "Forcing unbinding from Active Directory"
		/usr/sbin/dsconfigad -remove -force -u none -p none
		
		# Deletes the Active Directory domain from the custom /Search
		# and /Search/Contacts paths
		echo "Deleting AD Domain from all custom search paths"
		/usr/bin/dscl /Search/Contacts -delete . CSPSearchPath "$searchPath"
		/usr/bin/dscl /Search -delete . CSPSearchPath "$searchPath"
		
		# Changes the /Search and /Search/Contacts path type from Custom to Automatic
		echo "Changing the custom search path back to automatic"
		/usr/bin/dscl /Search -change . SearchPolicy dsAttrTypeStandard:CSPSearchPath dsAttrTypeStandard:NSPSearchPath
		/usr/bin/dscl /Search/Contacts -change . SearchPolicy dsAttrTypeStandard:CSPSearchPath dsAttrTypeStandard:NSPSearchPath
		
		echo "Unbind from Active Directory Domain Complete"
	}
	
	
	# Migrate Password from Mobile Account 
	PasswordMigration(){
	
		echo "Migrating User Password"
		# macOS 10.14.4 will remove the the actual ShadowHashData key immediately 
		# if the AuthenticationAuthority array value which references the ShadowHash
		# is removed from the AuthenticationAuthority array. To address this, the
		# existing AuthenticationAuthority array will be modified to remove the Kerberos
		# and LocalCachedUser user values.
	
	
		AuthenticationAuthority=$(/usr/bin/dscl -plist . -read /Users/${netname} AuthenticationAuthority)
		Kerberosv5=$(echo "${AuthenticationAuthority}" | xmllint --xpath 'string(//string[contains(text(),"Kerberosv5")])' -)
		LocalCachedUser=$(echo "${AuthenticationAuthority}" | xmllint --xpath 'string(//string[contains(text(),"LocalCachedUser")])' -)
		
		# Remove Kerberosv5 and LocalCachedUser
		echo "Removing Kerberosv5 and LocalCachedUser"
		if [[ ! -z "${Kerberosv5}" ]]; then
			/usr/bin/dscl -plist . -delete /Users/${netname} AuthenticationAuthority "${Kerberosv5}"
		fi
		
		if [[ ! -z "${LocalCachedUser}" ]]; then
			/usr/bin/dscl -plist . -delete /Users/${netname} AuthenticationAuthority "${LocalCachedUser}"
		fi
		
		echo "Password Migration Complete"
	}
	
	
	
	##########################################################################################
	# Core Script
	##########################################################################################
	
	# Check if the mac is in AD and if it is then start unbinding the mac.
	echo "Checking if Mac is bound to Active Directory"
	if [[ "${check4AD}" = "Active Directory" ]]; then
		
		echo "This machine is bound to Active Directory."
		RemoveAD
			
	fi
	
	
	# Check the list of users against LDAP and JIM to veryify the user is an AD account and if not delete the account. If it is an AD account then we process to delete.
	# Accounts on the Mac should be MacMDAdmin and the Users AD account. For admin account we will verify the current password hash and reset password if auth only fails.
	# We need to check local admin and make sure it is MacMDAdmin only.
	until [ "$user" == "FINISHED" ]; do
	
		for netname in $listUsers; do
		
			if [ "${netname}" = "FINISHED" ]; then
				
				echo "Finished checking Users in List of Users on Mac."
				exit 0
				
			fi
			
			# Set up Function to process LDAP Request
			echo "Checking to verify if ${netname} is an ${companyName} LDAP User before we process."
			verifyUserFromLDAP=(`/usr/bin/curl "$URL/JSSResource/ldapservers/name/${JIMServerName}/user/${netname}" \
								--silent \
								--request GET \
								--user "$username:$password" \
								| /usr/bin/xpath -e "//ldap_users/ldap_user/username/text()" 2> /dev/null`)
			
			if [[ ${verifyUserFromLDAP} != "" ]]; then
				
				echo "We found ${netname} in LDAP!"
				echo " Now Processing the Mobile Account for user ${netname}"
				
				# Get Account Type and migrate AD Mobile Accounts
				echo "Getting Account Type for ${netname} and check if it needs to be migrated."
				accounttype=$(/usr/bin/dscl . -read /Users/"${netname}" AuthenticationAuthority | head -2 | awk -F'/' '{print $2}' | tr -d '\n')
				
				echo "Account Type for ${netname} is ${accounttype}."
				if [[ "$accounttype" = "Active Directory" ]]; then
					
					echo "Checking if ${netname} is a mobile user."
					mobileusercheck=$(/usr/bin/dscl . -read /Users/"${netname}" AuthenticationAuthority | head -2 | awk -F'/' '{print $1}' | tr -d '\n' | sed 's/^[^:]*: //' | sed s/\;/""/g)
					
					if [[ "$mobileusercheck" = "LocalCachedUser" ]]; then
						echo "${netname} has an AD mobile account."
						echo "Converting ${netname} to a local account with the same username and UID."
						
					else
						
						echo "The ${netname} account is not a AD mobile account"
						break
						
					fi
					
				else
					
					echo "The ${netname} account is not a AD mobile account"
					break
					
				fi
				
				# Remove the account attributes that identify it as an Active Directory mobile account
				
				echo "Remove the account attributes that identify it as an Active Directory mobile account"
				/usr/bin/dscl . -delete /users/${netname} cached_groups
				/usr/bin/dscl . -delete /users/${netname} cached_auth_policy
				/usr/bin/dscl . -delete /users/${netname} CopyTimestamp
				/usr/bin/dscl . -delete /users/${netname} AltSecurityIdentities
				/usr/bin/dscl . -delete /users/${netname} SMBPrimaryGroupSID
				/usr/bin/dscl . -delete /users/${netname} OriginalAuthenticationAuthority
				/usr/bin/dscl . -delete /users/${netname} OriginalNodeName
				/usr/bin/dscl . -delete /users/${netname} SMBSID
				/usr/bin/dscl . -delete /users/${netname} SMBScriptPath
				/usr/bin/dscl . -delete /users/${netname} SMBPasswordLastSet
				/usr/bin/dscl . -delete /users/${netname} SMBGroupRID
				/usr/bin/dscl . -delete /users/${netname} PrimaryNTDomain
				/usr/bin/dscl . -delete /users/${netname} AppleMetaRecordName
				/usr/bin/dscl . -delete /users/${netname} PrimaryNTDomain
				/usr/bin/dscl . -delete /users/${netname} MCXSettings
				/usr/bin/dscl . -delete /users/${netname} MCXFlags
				
				echo "Account attributes that identify it as an Active Directory mobile account have been removed"
				
				# Migrate password and remove AD-related attributes
				PasswordMigration
				
				# Refresh Directory Services
				echo "Refreshing Directory Services"
				if [[ ${osvers} -ge 7 ]]; then
					/usr/bin/killall opendirectoryd
				else
					/usr/bin/killall DirectoryService
				fi
				
				sleep 20
				
				
				# Checking that migration went well
				echo "Checking that the AD Migration was Successful now."
				accounttype=$(/usr/bin/dscl . -read /Users/"${netname}" AuthenticationAuthority | head -2 | awk -F'/' '{print $2}' | tr -d '\n')
				
				echo "Getting Account Type for ${netname} to make sure it is removed from AD."
				if [[ "$accounttype" = "Active Directory" ]]; then
					
					echo "Something went wrong with the conversion process. The ${netname} account is still an AD mobile account."
					exit 1
					
				else
					
					echo "Conversion process was successful. The ${netname} account is now a local account."
					
				fi
				
				# Setting home Directory permissions
				echo "Setting Home Directory Permissions to AD Migrated User ${netname}"
				homedir=$(/usr/bin/dscl . -read /Users/"${netname}" NFSHomeDirectory  | awk '{print $2}')
				
				if [[ "$homedir" != "" ]]; then
					echo "Home directory location: ${homedir}"
					echo "Updating home folder permissions for the ${netname} account"
					/usr/sbin/chown -R "${netname}" "${homedir}"
				fi
				
				# Add user to the staff group on the Mac
				echo "Adding ${netname} to the staff group on this Mac."
				/usr/sbin/dseditgroup -o edit -a "${netname}" -t user staff
				
				
				/bin/echo "Displaying user and group information for the ${netname} account"
				/usr/bin/id ${netname}
				
			else
				
				# Delete the accounts with a UID greater than 1000 not found in LDAP
				echo "User ${netname} in not in LDAP! Deleting Account Now."
				sysadminctl -deleteUser ${netname}
				echo "User Account ${netname} has been deleted."
				
			fi
		
		done
		
	done
	
) 2>&1 | readCommandOutputToLog # To Capture output into Date and Time log file