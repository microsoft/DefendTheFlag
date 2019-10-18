Configuration SetupAipScannerCore
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$NetBiosName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DnsServer,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [PSCredential]$AdminCred,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [PsCredential]$LisaVCred
    )
    
    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion 8.10.0.0
    Import-DscResource -ModuleName xDefender -ModuleVersion 0.2.0.0
    Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion 6.5.0.0
    Import-DscResource -ModuleName NetworkingDsc -ModuleVersion 7.4.0.0
    Import-DscResource -ModuleName xSystemSecurity -ModuleVersion 1.4.0.0
    Import-DscResource -ModuleName cChoco -ModuleVersion 2.4.0.0
    Import-DscResource -ModuleName xPendingReboot -ModuleVersion 0.4.0.0

	[PSCredential]$Creds = New-Object System.Management.Automation.PSCredential ("${NetBiosName}\$($AdminCred.UserName)", $AdminCred.Password)

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
        xIEEsc DisableAdminIeEsc
        {
            UserRole = 'Administrators'
            IsEnabled = $false
        }

        xIEEsc DisableUserIeEsc
        {
            UserRole = 'Users'
            IsEnabled = $false
        }

        Service DisableWindowsUpdate
        {
            Name = 'wuauserv'
            State = 'Stopped'
            StartupType = 'Disabled'
        }

        Computer JoinDomain
        {
            Name = 'Client01'
            DomainName = $DomainName
            Credential = $Creds
        }

        Group AddAdmins
        {
            GroupName = 'Administrators'
            MembersToInclude = "$NetBiosName\$($LisaVCred.UserName)"
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
                Invoke-WebRequest -Uri 'https://github.com/microsoft/DefendTheFlag/blob/master/Downloads/BgInfo/aippc.bgi?raw=true' -Outfile 'C:\BgInfo\BgInfoConfig.bgi'
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
        
        Script MakeCmdShortcut
		{
			SetScript = 
			{
				$s=(New-Object -COM WScript.Shell).CreateShortcut('C:\Users\Public\Desktop\Cmd.lnk')
				$s.TargetPath='cmd.exe'
				$s.Description = 'Cmd.exe shortcut on everyones desktop'
				$s.Save()
			}
			GetScript = 
            {
                if (Test-Path -LiteralPath 'C:\Users\Public\Desktop\Cmd.lnk'){
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
                if (Test-Path -LiteralPath 'C:\Users\Public\Desktop\Cmd.lnk'){
					return $true
				}
				else {
					return $false
				}
            }
            DependsOn = '[Computer]JoinDomain'
        }

        Script TurnOnNetworkDiscovery
        {
            SetScript = 
            {
                Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Set-NetFirewallRule -Profile 'Any' -Enabled true
            }
            GetScript = 
            {
                $fwRules = Get-NetFirewallRule -DisplayGroup 'Network Discovery'
                if ($null -eq $fwRules)
                {
                    return @{result = $false}
                }
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
                if ($null -eq $fwRules)
                {
                    return $false
                }
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
        #endregion

        Registry DisableSmartScreen
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
            ValueName = 'SmartScreenEnable'
            ValueType = 'String'
            ValueData = 'Off'
            Ensure = 'Present'
            DependsOn = '[Computer]JoinDomain'
        }

        Script DownloadMcasData
        {
            SetScript = 
            {
                if ((Test-Path -PathType Container -LiteralPath 'C:\LabData\') -ne $true){
					New-Item -Path 'C:\LabData\' -ItemType Directory
                }
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $ProgressPreference = 'SilentlyContinue' # used to speed this up from 30s to 100ms
                Invoke-WebRequest -Uri 'https://github.com/microsoft/DefendTheFlag/blob/master/Downloads/MCAS/Demo%20files.zip?raw=true' -Outfile 'C:\LabData\McasData.zip'
            }      
            GetScript = 
            {
                if ((Test-Path -PathType Leaf -LiteralPath 'C:\LabData\McasData.zip') -eq $true){
                    return @{result = $true} 
                }
                else { 
                    return @{result = $false}
                }
            }
            TestScript =
            {
                if ((Test-Path -PathType Leaf -LiteralPath 'C:\LabData\McasData.zip') -eq $true){
                    return $true
                } 
                else { 
                    return $false
                }
            }
            DependsOn = @('[Computer]JoinDomain')
        }

        # Place on all Users Desktops; can't put in LisaV's else her profile changes since she never logged in yet...
        Archive McasDataTop
        {
            Path = 'C:\LabData\McasData.zip'
            Destination = 'C:\Users\Public\Desktop\DemoFiles'
            Ensure = 'Present'
            DependsOn = @('[Script]DownloadMcasData','[Computer]JoinDomain')
            Force = $true
        }
    }
}