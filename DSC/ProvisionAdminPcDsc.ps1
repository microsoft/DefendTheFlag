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
    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion 8.10.0.0
    Import-DscResource -ModuleName xDefender -ModuleVersion 0.2.0.0
    Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion 6.5.0.0
    Import-DscResource -ModuleName NetworkingDsc -ModuleVersion 7.4.0.0
    Import-DscResource -ModuleName xSystemSecurity -ModuleVersion 1.4.0.0
    Import-DscResource -ModuleName cChoco -ModuleVersion 2.4.0.0
    Import-DscResource -ModuleName xPendingReboot -ModuleVersion 0.4.0.0
    Import-DscResource -ModuleName SqlServerDsc -ModuleVersion 13.2.0.0
    Import-DscResource -ModuleName xSmbShare -ModuleVersion 2.2.0.0

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
            DependsOn = @('[Registry]EnableTls12WinHttp64','[Registry]EnableTls12WinHttp',
                '[Registry]EnableTlsInternetExplorerLM','[Registry]EnableTls12ServerEnabled',
                '[Registry]SchUseStrongCrypto64', '[Registry]SchUseStrongCrypto')
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

        #region Enable TLS1.2
        # REF: https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-wi
        # Enable TLS 1.2 SChannel
        Registry EnableTls12ServerEnabled
        {
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            ValueName = 'DisabledByDefault'
            ValueType = 'Dword'
            ValueData = 0
            Ensure = 'Present'
        }
        # Enable Internet Settings
        Registry EnableTlsInternetExplorerLM
        {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'SecureProtocols'
            ValueType = 'Dword'
            ValueData = '0xA80'
            Ensure = 'Present'
            Hex = $true
        }
        #enable for WinHTTP
        Registry EnableTls12WinHttp
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
            ValueName = 'DefaultSecureProtocols'
            ValueType = 'Dword'
            ValueData = '0x00000800'
            Ensure = 'Present'
            Hex = $true
        }
        Registry EnableTls12WinHttp64
        {
            Key = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
            ValueName = 'DefaultSecureProtocols'
            ValueType = 'Dword'
            ValueData = '0x00000800'
            Hex = $true
            Ensure = 'Present'
        }
        #powershell defaults
        Registry SchUseStrongCrypto
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueType = 'Dword'
            ValueData =  '1'
            Ensure = 'Present'
        }

        Registry SchUseStrongCrypto64
        {
            Key = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueType = 'Dword'
            ValueData =  '1'
            Ensure = 'Present'
        }
        #endregion

        #region SQL
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

        xRemoteFile StageSqlServer2017Dev
        {
            DestinationPath = 'C:\SQL\SQLServer2017.exe'
            Uri = 'https://go.microsoft.com/fwlink/?linkid=853016'
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
        #endregion

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

        xRemoteFile GetBgInfo
        {
            DestinationPath = 'C:\BgInfo\BgInfoConfig.bgi'
            Uri = 'https://github.com/microsoft/DefendTheFlag/blob/master/Downloads/BgInfo/adminpc.bgi?raw=true'
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
            DependsOn = @('[xRemoteFile]GetBgInfo','[cChocoPackageInstaller]InstallSysInternals')
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

        #region AipClient
        xRemoteFile AipClient
        {
            DestinationPath = 'C:\LabTools\aip_ul_installer.msi'
            Uri = 'https://github.com/microsoft/DefendTheFlag/blob/v1.0/Downloads/AIP/Client/AzInfoProtection_UL_Preview_MSI_for_central_deployment.msi?raw=true'
            DependsOn = '[Computer]JoinDomain'
            TimeoutSec = 120
        }
		xMsiPackage InstallAipClient
		{
            Ensure = 'Present'
			Path = 'C:\LabTools\aip_ul_installer.msi'
            ProductId = '{B6328B23-18FD-4475-902E-C1971E318F8B}'
            Arguments = '/quiet'
            DependsOn = '[xRemoteFile]AipClient'
        }
        #endregion

        xRemoteFile GetAipData
        {
            DestinationPath = 'C:\PII\data.zip'
            Uri = 'https://github.com/InfoProtectionTeam/Files/blob/master/Scripts/AIPScanner/docs.zip?raw=true'
            DependsOn = '[Computer]JoinDomain'
        }
        
        xRemoteFile GetAipScripts
        {
            DestinationPath = 'C:\Scripts\Scripts.zip'
            Uri = 'https://github.com/InfoProtectionTeam/Files/blob/master/Scripts/Scripts.zip?raw=true'
            DependsOn = '[Computer]JoinDomain'
        }

        
        Archive AipDataToPii
        {
            Path = 'C:\PII\data.zip'
            Destination = 'C:\PII'
            Ensure = 'Present'
            Force = $true
            DependsOn = @('[xRemoteFile]GetAipData')
        }

        Archive AipDataToPublicDocuments
        {
            Path = 'C:\PII\data.zip'
            Destination = 'C:\Users\Public\Documents'
            Ensure = 'Present'
            Force = $true
            DependsOn = '[xRemoteFile]GetAipData'
        }

        Archive AipScriptsToScripts
        {
            Path = 'C:\Scripts\Scripts.zip'
            Destination = 'C:\Scripts'
            Ensure = 'Present'
            Force = $true
            DependsOn = @('[xRemoteFile]GetAipScripts')
        }
        #endregion
    }
}
