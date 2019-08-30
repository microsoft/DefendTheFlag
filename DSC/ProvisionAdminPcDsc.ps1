####
#
#  Things we can't do:
#  SQL Express; too difficult to stage install (700+MB)
#      Needs to be installed for AIP as AIP Service account
###

Configuration SetupAdminPc
{
    param(
        # COE: Domain's name
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainName,
        
        # COE: Domain's NetBios
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$NetBiosName,

        # COE: ensures DNS properly set by OS before domain join
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DnsServer,

        # COE: used to domain join
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [PSCredential]$AdminCred,

        # AATP: used to do Scheduled Task
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [PsCredential]$SamiraACred,

        # AIP: used to install SqlServer in context of AIP Admin
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [PsCredential]$AipServiceCred

    )
    #region COE
    Import-DscResource -ModuleName PSDesiredStateConfiguration, xDefender, ComputerManagementDsc, NetworkingDsc, `
        xSystemSecurity, SqlServerDsc, cChoco, xPendingReboot, xSmbShare

    [PSCredential]$Creds = New-Object System.Management.Automation.PSCredential ("${NetBiosName}\$($AdminCred.UserName)", $AdminCred.Password)
    
    #region ScheduledTask-AATP
    $SamiraASmbScriptLocation = [string]'C:\ScheduledTasks\SamiraASmbSimulation.ps1'
    [PSCredential]$SamiraADomainCred = New-Object System.Management.Automation.PSCredential ("${NetBiosName}\$($SamiraACred.UserName)", $SamiraACred.Password)
    #endregion
    #endregion

    #TODO: Not used yet as installing SQLExpress is one thing we need to do manually until we figure this out...
    #[PSCredential]$AipDomainAccount = New-Object System.Management.Automation.PSCredential ("${NetBiosName}\$($AipServiceCred.UserName)", $AipServiceCred.Password)
    #end region

    Node localhost
    {
		LocalConfigurationManager
		{
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
            AllowModuleOverwrite = $true
            ActionAfterReboot = 'ContinueConfiguration'
        }

        #region COE
        Service DisableWindowsUpdate
        {
            Name = 'wuauserv'
            State = 'Stopped'
            StartupType = 'Disabled'
        }

        Computer JoinDomain
        {
            Name = 'AdminPC'
            DomainName = $DomainName
            Credential = $Creds
        }

        xIEEsc DisableAdminIeEsc
        {
            UserRole = 'Administrators'
            IsEnabled = $false
            DependsOn = "[Computer]JoinDomain"
        }

        xIEEsc DisableUserIeEsc
        {
            UserRole = 'Users'
            IsEnabled = $false
            DependsOn = "[Computer]JoinDomain"

        }

        xUAC DisableUac
        {
            Setting = "NeverNotifyAndDisableAll"
            DependsOn = "[Computer]JoinDomain"
        }

        Group AddAdmins
        {
            GroupName = 'Administrators'
            MembersToInclude = @("$NetBiosName\Helpdesk", "$NetBiosName\$($AipServiceCred.UserName)")
            Ensure = 'Present'
            DependsOn = '[Computer]JoinDomain'
        }

        Group AddRemoteDesktopUsers
        {
            GroupName = 'Remote Desktop Users'
            MembersToInclude = @("$NetBiosName\SamiraA", "$NetBiosName\Helpdesk")
            Ensure = 'Present'
            DependsOn = '[Computer]JoinDomain'
        }

        Registry HideServerManager
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\ServerManager'
            ValueName = 'DoNotOpenServerManagerAtLogon'
            ValueType = 'Dword'
            ValueData = '1'
            Force = $true
            Ensure = 'Present'
            DependsOn = '[Computer]JoinDomain'
        }

        Registry HideInitialServerManager
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\ServerManager\Oobe'
            ValueName = 'DoNotOpenInitialConfigurationTasksAtLogon'
            ValueType = 'Dword'
            ValueData = '1'
            Force = $true
            Ensure = 'Present'
            DependsOn = '[Computer]JoinDomain'
        }

        Registry DisableSmartScreen
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
            ValueName = 'SmartScreenEnable'
            ValueType = 'String'
            ValueData = 'Off'
            Ensure = 'Present'
            DependsOn = '[Computer]JoinDomain'
        }

        #region Modify IE Zone 3 Settings
        # needed to download files via IE from GitHub and other sources
        # can't just modify regkeys, need to export/import reg
        # ref: https://support.microsoft.com/en-us/help/182569/internet-explorer-security-zones-registry-entries-for-advanced-users
        Script DownloadRegkeyZone3Workaround
        {
            SetScript = 
            {
                if ((Test-Path -PathType Container -LiteralPath 'C:\LabTools\') -ne $true){
					New-Item -Path 'C:\LabTools\' -ItemType Directory
				}
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $ProgressPreference = 'SilentlyContinue' # used to speed this up from 30s to 100ms
                Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/ciberesponce/AatpAttackSimulationPlaybook/master/Downloads/Zone3.reg' -Outfile 'C:\LabTools\RegkeyZone3.reg'
            }
			GetScript = 
            {
				if (Test-Path -Path 'C:\LabTools\RegkeyZone3.reg' -PathType Leaf){
					return @{
						result = $true
					}
				}
				else {
					return @{
						result = $false
					}
				}
            }
            TestScript = 
            {
				if (Test-Path -Path 'C:\LabTools\RegkeyZone3.reg' -PathType Leaf){
					return $true
				}
				else {
					return $false
				}
            }
            DependsOn = '[Registry]DisableSmartScreen'
        }

        Script ExecuteZone3Override
        {
            SetScript = 
            {
                reg import "C:\LabTools\RegkeyZone3.reg" > $null 2>&1
            }
			GetScript = 
            {
				# this should be set to 0; if its 3, its default value still
				if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' -Name 'DisplayName') -eq 'Internet Zone - Modified (@ciberesponce)'){
					return @{ result = $true }
				}
				else{
					return @{ result = $false }
				}
            }
            TestScript = 
            {
				if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' -Name 'DisplayName') -eq 'Internet Zone - Modified (@ciberesponce)'){
					return $true
				}
				else{
					return $false
				}
            }
            DependsOn = '[Script]DownloadRegkeyZone3Workaround'
        }
        #endregion

        Script MSSqlFirewall
        {
            SetScript = 
            {
                New-NetFirewallRule -DisplayName 'MSSQL ENGINE TCP' -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow
            }
            GetScript = 
            {
                $firewallStuff = Get-NetFirewallRule -DisplayName "MSSQL ENGINE TCP" -ErrorAction SilentlyContinue
                # if null, no rule exists with the Display Name
                if ($null -ne $firewallStuff){
                    return @{ result = $true}
                }
                else {
                    return @{ result = $false }
                }
            }
            TestScript = 
            {
                $firewallStuff = Get-NetFirewallRule -DisplayName "MSSQL ENGINE TCP" -ErrorAction SilentlyContinue
                # if null, no rule exists with the Display Name
                if ($null -ne $firewallStuff){
                    return $true
                }
                else {
                    return $false
                }
            }
            DependsOn = '[Computer]JoinDomain'
        }
        #endregion

        #region AATP
        Script TurnOnNetworkDiscovery
        {
            SetScript = 
            {
                Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Set-NetFirewallRule -Profile 'Any' -Enabled true
            }
            GetScript = 
            {
                $fwRules = Get-NetFirewallRule -DisplayGroup 'Network Discovery' 
                $result = $true
                foreach ($rule in $fwRules){
                    if ($rule.Enabled -eq 'False'){
                        $result = $false
                        break
                    }
                }
                return @{
                    result = $result
                }
            }
            TestScript = 
            {
                $fwRules = Get-NetFirewallRule -DisplayGroup 'Network Discovery'
                $result = $true
                foreach ($rule in $fwRules){
                    if ($rule.Enabled -eq 'False'){
                        $result = $false
                        break
                    }
                }
                return $result
            }
            DependsOn = '[Computer]JoinDomain'
        }

        Script TurnOnFileSharing
        {
            SetScript = 
            {
                Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Set-NetFirewallRule -Profile 'Any' -Enabled true
            }
            GetScript = 
            {
                $fwRules = Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing'
                $result = $true
                foreach ($rule in $fwRules){
                    if ($rule.Enabled -eq 'False'){
                        $result = $false
                        break
                    }
                }
                return @{
                    result = $result
                }
            }
            TestScript = 
            {
                $fwRules = Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing'
                $result = $true
                foreach ($rule in $fwRules){
                    if ($rule.Enabled -eq 'False'){
                        $result = $false
                        break
                    }
                }
                return $result
            }
            DependsOn = '[Computer]JoinDomain'
        }

        Script EnsureTempFolder
        {
            SetScript = 
            {
                New-Item -Path 'C:\Temp\' -ItemType Directory
            }
            GetScript = 
            {
                if (Test-Path -PathType Container -LiteralPath 'C:\Temp'){
					return @{
						result = $true
					}
				}
				else {
					return @{
						result = $false
					}
				}
            }
            TestScript = {
                if(Test-Path -PathType Container -LiteralPath 'C:\Temp'){
                    return $true
                }
                else {
                    return $false
                }
            }
        }

        #region Choco
        cChocoInstaller InstallChoco
        {
            InstallDir = "C:\choco"
            DependsOn = '[Computer]JoinDomain'
        }

        cChocoPackageInstaller InstallSysInternals
        {
            Name = 'sysinternals'
            Ensure = 'Present'
            AutoUpgrade = $false
            DependsOn = '[cChocoInstaller]InstallChoco'
        }

        cChocoPackageInstaller Chrome
        {
            Name = 'googlechrome'
            Ensure = 'Present'
            AutoUpgrade = $true
            DependsOn = '[cChocoInstaller]InstallChoco'
        }

        cChocoPackageInstaller InstallOffice365
        {
            Name = 'microsoft-office-deployment'
            Ensure = 'Present'
            AutoUpgrade = $false
            Params = '/Product=O365ProPlusRetail'
            DependsOn = '[cChocoInstaller]InstallChoco'
        }
        #endregion

        Script DownloadBginfo
        {
            SetScript =
            {
                if ((Test-Path -PathType Container -LiteralPath 'C:\BgInfo\') -ne $true){
					New-Item -Path 'C:\BgInfo\' -ItemType Directory
				}
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $ProgressPreference = 'SilentlyContinue' # used to speed this up from 30s to 100ms
                Invoke-WebRequest -Uri 'https://github.com/ciberesponce/AatpAttackSimulationPlaybook/blob/master/Downloads/BgInfo/adminpc.bgi?raw=true' -Outfile 'C:\BgInfo\BgInfoConfig.bgi'
			}
            GetScript =
            {
                if (Test-Path -LiteralPath 'C:\BgInfo\BgInfoConfig.bgi' -PathType Leaf){
                    return @{
                        result = $true
                    }
                }
                else {
                    return @{
                        result = $false
                    }
                }
            }
            TestScript = 
            {
                if (Test-Path -LiteralPath 'C:\BgInfo\BgInfoConfig.bgi' -PathType Leaf){
                    return $true
                }
                else {
                    return $false
                }
			}
            DependsOn = '[cChocoPackageInstaller]InstallSysInternals'
        }
        
        Script MakeShortcutForBgInfo
		{
			SetScript = 
			{
				$s=(New-Object -COM WScript.Shell).CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BgInfo.lnk')
				$s.TargetPath='bginfo64.exe'
				$s.Arguments = 'c:\BgInfo\BgInfoConfig.bgi /accepteula /timer:0'
				$s.Description = 'Ensure BgInfo starts at every logon, in context of the user signing in (only way for stable use!)'
				$s.Save()
			}
			GetScript = 
            {
                if (Test-Path -LiteralPath 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BgInfo.lnk'){
					return @{
						result = $true
					}
				}
				else {
					return @{
						result = $false
					}
				}
			}
            
            TestScript = 
            {
                if (Test-Path -LiteralPath 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BgInfo.lnk'){
					return $true
				}
				else {
					return $false
				}
            }
            DependsOn = @('[Script]DownloadBginfo','[cChocoPackageInstaller]InstallSysInternals')
		}

        Registry AuditModeSamr
        {
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RestrictRemoteSamAuditOnlyMode'
            ValueType = 'Dword'
            ValueData = '1'
            Force = $true
            Ensure = 'Present'
            DependsOn = '[Computer]JoinDomain'
        }

        xMpPreference DefenderSettings
        {
            Name = 'DefenderSettings'
            ExclusionPath = 'C:\Tools'
            DisableRealtimeMonitoring = $true
        }

        File ScheduledTaskFile
        {
            DestinationPath = $SamiraASmbScriptLocation
            Ensure = 'Present'
            Contents = 
@'
Get-ChildItem '\\contosodc\c$'; exit(0)
'@
            Type = 'File'
        }

        ScheduledTask ScheduleTaskSamiraA
        {
            TaskName = 'SimulateDomainAdminTraffic'
            ScheduleType = 'Once'
            Description = 'Simulates Domain Admin traffic from Admin workstation. Useful for SMB Session Enumeration and other items'
            Ensure = 'Present'
            Enable = $true
            TaskPath = '\M365Security\Aatp'
            ActionExecutable   = "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe"
            ActionArguments = "-File `"$SamiraASmbScriptLocation`""
            ExecuteAsCredential = $SamiraADomainCred
            Hidden = $true
            Priority = 6
            RepeatInterval = '00:05:00'
            RepetitionDuration = 'Indefinitely'
            StartWhenAvailable = $true
            DependsOn = @('[Computer]JoinDomain','[File]ScheduledTaskFile')
        }
        #endregion

        #region AIP
        Script DownloadAipMsi
		{
			SetScript = 
            {
                if ((Test-Path -PathType Container -LiteralPath 'C:\LabTools\') -ne $true){
					New-Item -Path 'C:\LabTools\' -ItemType Directory
				}
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $ProgressPreference = 'SilentlyContinue' # used to speed this up from 30s to 100ms
                Invoke-WebRequest -Uri 'https://github.com/ciberesponce/AatpAttackSimulationPlaybook/blob/master/Downloads/AzInfoProtection_MSI_for_central_deployment.msi?raw=true' -Outfile 'C:\LabTools\aip_installer.msi'
            }
			GetScript = 
            {
				if ((Test-Path 'C:\LabTools\aip_installer.msi') -eq $true){
					return @{
						result = $true
					}
				}
				else {
					return @{
						result = $false
					}
				}
            }
            TestScript = 
            {
				if ((Test-Path 'C:\LabTools\aip_installer.msi') -eq $true){
					return $true
				}
				else {
					return $false
				}
            }
            DependsOn = @('[Registry]DisableSmartScreen','[Computer]JoinDomain', '[Script]ExecuteZone3Override')
		}

		Package InstallAipClient
		{
			Name = 'Microsoft Azure Information Protection'
			Ensure = 'Present'
			Path = 'C:\LabTools\aip_installer.msi'
			ProductId = '{48A06F18-951C-42CA-86F1-3046AF06D15E}'
			Arguments = '/quiet'
			DependsOn = '[Script]DownloadAipMsi'
        }

        # need customer script do to issue with SmbShare
        Script SharePublicDocuments
        {
            SetScript = 
            {
                New-SmbShare -Name 'Documents' -Path 'C:\Users\Public\Documents' `
                    -FullAccess 'Everyone'

                Set-SmbPathAcl -ShareName 'Documents'
            }
            GetScript = 
            {
                $share = Get-SmbShare -Name 'Documents' -ErrorAction SilentlyContinue
                if ($null -ne $share) {
                    # now that share exists, make sure ACL for everyone is set
                    $acls = Get-Acl -Path C:\Users\Public\Documents 
                    $acl = $acls.Access | Where-Object {$_.IdentityReference -eq 'Everyone'}
                    if ($null -eq $acl){
                        # if no ACL has an 'Everyone' IdentityReference, return false
                        return @{
                            result = $false
                        }
                    }
                    else{
                        if (($acl.AccessControlType -eq 'Allow') -and ($acl.FileSystemRights -eq 'FullControl')) {
                            return @{
                                result = $true
                            } 
                        }
                        # if ACL isn't right, return false
                        else {
                            return @{
                                result = $false
                            }
                        }
                    }
                    
                }
                # if not a share, return false
                else {
                    return @{
                        result = $false
                    }
                }
            }
            TestScript = 
            {
                $share = Get-SmbShare -Name 'Documents' -ErrorAction SilentlyContinue
                if ($null -ne $share) {
                    # now that share exists, make sure ACL for everyone is set
                    $acls = Get-Acl -Path C:\Users\Public\Documents 
                    $acl = $acls.Access | Where-Object {$_.IdentityReference -eq 'Everyone'}
                    if ($null -eq $acl){
                        # if no ACL has an 'Everyone' IdentityReference, return false
                        return $false
                    }
                    else{
                        if (($acl.AccessControlType -eq 'Allow') -and ($acl.FileSystemRights -eq 'FullControl')) {
                            return $true
                        }
                        # if ACL isn't right, return false
                        else {
                            return $false
                        }
                    }
                    
                }
                # if not a share, return false
                else {
                    return $false
                }
            }
            DependsOn = '[Computer]JoinDomain'
        }
        
        # Stage AIP data
        Script DownloadAipData
        {
            SetScript = 
            {
                if ((Test-Path -PathType Container -LiteralPath 'C:\PII\') -ne $true){
					New-Item -Path 'C:\PII\' -ItemType Directory
                }
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $ProgressPreference = 'SilentlyContinue' # used to speed this up from 30s to 100ms
                Invoke-WebRequest -Uri 'https://github.com/InfoProtectionTeam/Files/blob/master/Scripts/AIPScanner/docs.zip?raw=true' -Outfile 'C:\PII\data.zip'
            }
            TestScript =
            {
                if ((Test-Path -PathType Leaf -LiteralPath 'C:\PII\data.zip') -eq $true){
                    return $true
                } 
                else { 
                    return $false
                }
            }
            
            GetScript = 
            {
                if ((Test-Path -PathType Leaf -LiteralPath 'C:\PII\data.zip') -eq $true){
                    return @{result = $true} 
                }
                else { 
                    return @{result = $false}
                }
                
            }
            DependsOn = @('[Computer]JoinDomain','[Script]ExecuteZone3Override')
        }

        # Stage AIP Scripts
        Script DownloadAipScripts
        {
            SetScript = 
            {
                if ((Test-Path -PathType Container -LiteralPath 'C:\Scripts\') -ne $true){
					New-Item -Path 'C:\Scripts\' -ItemType Directory
                }
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $ProgressPreference = 'SilentlyContinue' # used to speed this up from 30s to 100ms
                Invoke-WebRequest -Uri 'https://github.com/InfoProtectionTeam/Files/blob/master/Scripts/Scripts.zip?raw=true' -Outfile 'C:\Scripts\Scripts.zip'
            }
            TestScript =
            {
                if ((Test-Path -PathType Leaf -LiteralPath 'C:\Scripts\Scripts.zip') -eq $true){
                    return $true
                } 
                else { 
                    return $false
                }
            }
            
            GetScript = 
            {
                if ((Test-Path -PathType Leaf -LiteralPath 'C:\Scripts\Scripts.zip') -eq $true){
                    return @{result = $true} 
                }
                else { 
                    return @{result = $false}
                }
                
            }
            DependsOn = @('[Script]ExecuteZone3Override','[Computer]JoinDomain')
        }

        Archive AipDataToPii
        {
            Path = 'C:\PII\data.zip'
            Destination = 'C:\PII'
            Ensure = 'Present'
            Force = $true
            DependsOn = @('[Script]DownloadAipData')
        }

        Archive AipDataToPublicDocuments
        {
            Path = 'C:\PII\data.zip'
            Destination = 'C:\Users\Public\Documents'
            Ensure = 'Present'
            Force = $true
            DependsOn = '[Script]DownloadAipData'
        }

        Archive AipScriptsToScripts
        {
            Path = 'C:\Scripts\Scripts.zip'
            Destination = 'C:\Scripts'
            Ensure = 'Present'
            Force = $true
            DependsOn = @('[Script]DownloadAipScripts')
        }
        #endregion
    }
}
