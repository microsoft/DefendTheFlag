Configuration CreateADForest
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
		[PSCredential]$AdminCreds,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$UserPrincipalName,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[PSCredential]$JeffLCreds,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[PSCredential]$SamiraACreds,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[PSCredential]$RonHdCreds,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[PSCredential]$LisaVCreds,

		# AATP: used for AATP Service
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[PsCredential]$AatpServiceCreds,

		[Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [PsCredential]$AipServiceCreds,

		[int]$RetryCount=20,
		[int]$RetryIntervalSec=30,

		# Branch
        ## Useful when have multiple for testing
        [Parameter(Mandatory=$false)]
        [String]$Branch
	)
	
	Import-DscResource -ModuleName xActiveDirectory -ModuleVersion 3.0.0.0
	Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion 8.10.0.0
    Import-DscResource -ModuleName xDefender -ModuleVersion 0.2.0.0
    Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion 6.5.0.0
    Import-DscResource -ModuleName NetworkingDsc -ModuleVersion 7.4.0.0
    Import-DscResource -ModuleName xSystemSecurity -ModuleVersion 1.4.0.0
    Import-DscResource -ModuleName cChoco -ModuleVersion 2.4.0.0
	Import-DscResource -ModuleName xPendingReboot -ModuleVersion 0.4.0.0

	$Interface=Get-NetAdapter | Where-Object Name -Like "Ethernet*"|Select-Object -First 1
	$InterfaceAlias=$($Interface.Name)

	[PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${NetBiosName}\$($AdminCreds.UserName)", $AdminCreds.Password)
	
	Node localhost
	{
		LocalConfigurationManager
		{
			RebootNodeIfNeeded = $true
		}

        Service DisableWindowsUpdate
        {
            Name = 'wuauserv'
            State = 'Stopped'
            StartupType = 'Disabled'
            Ensure = 'Present'
        }

        Service WmiMgt
        {
            Name = 'WinRM'
            State = 'Running'
            StartupType = 'Automatic'
            Ensure = 'Present'
        }
		
		WindowsFeature DNS
		{
			Ensure = 'Present'
			Name = 'DNS'
		}
		
		DnsServerAddress DnsServerAddress 
		{ 
			Address        = '127.0.0.1'
			InterfaceAlias = $InterfaceAlias
			AddressFamily  = 'IPv4'
			DependsOn = "[WindowsFeature]DNS"
		}

		WindowsFeature DnsTools
		{
			Ensure = "Present"
			Name = "RSAT-DNS-Server"
			DependsOn = "[WindowsFeature]DNS"
		}

		WindowsFeature ADDSInstall
		{
			Ensure = 'Present'
			Name = 'AD-Domain-Services'
		}

		WindowsFeature ADDSTools
		{
			Ensure = "Present"
			Name = "RSAT-ADDS-Tools"
			DependsOn = "[WindowsFeature]ADDSInstall"
		}

		WindowsFeature ADAdminCenter
		{
			Ensure = "Present"
			Name = "RSAT-AD-AdminCenter"
			DependsOn = "[WindowsFeature]ADDSInstall"
		}

		xADDomain ContosoDC
		{
			DomainName = $DomainName
			DomainNetbiosName = $NetBiosName
			DomainAdministratorCredential = $DomainCreds
			SafemodeAdministratorPassword = $DomainCreds
			ForestMode = 'Win2012R2'
			DatabasePath = 'C:\Windows\NTDS'
			LogPath = 'C:\Windows\NTDS'
			SysvolPath = 'C:\Windows\SYSVOL'
			DependsOn = '[WindowsFeature]ADDSInstall'
		}
	
		xADForestProperties ForestProps
		{
			ForestName = $DomainName
			UserPrincipalNameSuffixToAdd = $UserPrincipalName
			DependsOn = @('[xADDomain]ContosoDC')
		}

		xWaitForADDomain DscForestWait
		{
				DomainName = $DomainName
				DomainUserCredential = $DomainCreds
				RetryCount = $RetryCount
				RetryIntervalSec = $RetryIntervalSec
				DependsOn = @('[xADDomain]ContosoDC','[xADDomain]ContosoDC','[Registry]EnableTls12WinHttp64','[Registry]EnableTls12WinHttp',
					'[Registry]EnableTlsInternetExplorerLM','[Registry]EnableTls12ServerEnabled',
					'[Registry]SchUseStrongCrypto64', '[Registry]SchUseStrongCrypto', '[xIEEsc]DisableAdminIeEsc',
					'[xIEEsc]DisableUserIeEsc')
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

        xUac DisableUac
        {
            Setting = 'NeverNotifyAndDisableAll'
		}
		#endregion
    

		Registry HideServerManager
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\ServerManager'
            ValueName = 'DoNotOpenServerManagerAtLogon'
            ValueType = 'Dword'
            ValueData = '1'
            Ensure = 'Present'
            Force = $true
			DependsOn = @("[xADForestProperties]ForestProps", "[xWaitForADDomain]DscForestWait")
		}

        Registry HideInitialServerManager
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\ServerManager\Oobe'
            ValueName = 'DoNotOpenInitialConfigurationTasksAtLogon'
            ValueType = 'Dword'
            ValueData = '1'
            Ensure = 'Present'
            Force = $true
			DependsOn = @("[xADForestProperties]ForestProps", "[xWaitForADDomain]DscForestWait")
		}

		#region cChoco

		cChocoInstaller InstallChoco
        {
			InstallDir = 'C:\choco'
			DependsOn = @('[xADForestProperties]ForestProps', '[xWaitForADDomain]DscForestWait')
		}
		
        cChocoPackageInstaller EdgeBrowser
        {
            Name = 'microsoft-edge'
            Ensure = 'Present'
            AutoUpgrade = $true
            DependsOn = '[cChocoInstaller]InstallChoco'
        }
		
		cChocoPackageInstaller WindowsTerminal
        {
            Name = 'microsoft-windows-terminal'
            Ensure = 'Present'
            AutoUpgrade = $true
            DependsOn = '[cChocoInstaller]InstallChoco'
        }

        cChocoPackageInstaller InstallSysInternals
        {
            Name = 'sysinternals'
			Ensure = 'Present'
			AutoUpgrade = $false
            DependsOn = '[cChocoInstaller]InstallChoco'
		}
		#endegion
	
		xRemoteFile DownloadBginfo
		{
			DestinationPath = 'C:\BgInfo\BgInfoConfig.bgi'
			Uri = 'https://github.com/humestc/DefendTheFlag/blob/master/Downloads/BgInfo/contosodc.bgi?raw=true'
			DependsOn = '[xWaitForADDomain]DscForestWait'
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
            DependsOn = @('[xRemoteFile]DownloadBginfo','[cChocoPackageInstaller]InstallSysInternals')
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
			DependsOn = @("[xADForestProperties]ForestProps", "[xWaitForADDomain]DscForestWait")
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
			DependsOn = @("[xADForestProperties]ForestProps", "[xWaitForADDomain]DscForestWait")
        }

		xADUser SamiraA
		{
			DomainName = $DomainName
			UserName = 'SamiraA'
			Password = $SamiraACreds
			Ensure = 'Present'
			GivenName = 'Samira'
			Surname = 'A'
			PasswordNeverExpires = $true
			DependsOn = @("[xADForestProperties]ForestProps", "[xWaitForADDomain]DscForestWait")
		}

		xADUser AipService
		{
			DomainName = $DomainName
			UserName = $AipServiceCreds.UserName
			Password = $AipServiceCreds
			Ensure = 'Present'
			GivenName = 'AipService'
			Surname = 'Account'
			PasswordNeverExpires = $true
			DependsOn = @("[xADForestProperties]ForestProps", "[xWaitForADDomain]DscForestWait")
		}

		xADUser RonHD
		{
			DomainName = $DomainName
			UserName = 'RonHD'
			Password = $RonHdCreds
			Ensure = 'Present'
			GivenName = 'Ron'
			Surname = 'HD'
			PasswordNeverExpires = $true
			DisplayName = 'RonHD'
			DependsOn = @("[xADForestProperties]ForestProps", "[xWaitForADDomain]DscForestWait")
		}

		xADUser AatpService
		{
			DomainName = $DomainName
			UserName = $AatpServiceCreds.UserName
			Password = $AatpServiceCreds
			Ensure = 'Present'
			GivenName = 'AATP'
			Surname = 'Service'
			PasswordNeverExpires = $true
			DisplayName = 'AATPService'
			DependsOn = @("[xADForestProperties]ForestProps", "[xWaitForADDomain]DscForestWait")
		}

		xADUser JeffL
		{
			DomainName = $DomainName
			UserName = 'JeffL'
			GivenName = 'Jeff'
			Surname = 'Leatherman'
			Password = $JeffLCreds
			Ensure = 'Present'
			PasswordNeverExpires = $true
			DisplayName = 'JeffL'
			DependsOn = @("[xADForestProperties]ForestProps", "[xWaitForADDomain]DscForestWait")
		}

		xADUser LisaV
		{
			DomainName = $DomainName
			UserName = 'LisaV'
			GivenName = 'Lisa'
			Surname = 'Valentine'
			Password =  $LisaVCreds
			Ensure = 'Present'
			PasswordNeverExpires = $true
			DependsOn = @("[xADForestProperties]ForestProps", "[xWaitForADDomain]DscForestWait")
		}

		xADGroup DomainAdmins
		{
			GroupName = 'Domain Admins'
			Category = 'Security'
			GroupScope = 'Global'
			MembershipAttribute = 'SamAccountName'
			MembersToInclude = "SamiraA"
			Ensure = 'Present'
			DependsOn = @("[xADUser]SamiraA", "[xWaitForADDomain]DscForestWait")
		}

		xADGroup Helpdesk
		{
			GroupName = 'Helpdesk'
			Category = 'Security'
			GroupScope = 'Global'
			Description = 'Tier-2 (desktop) Helpdesk for this domain'
			DisplayName = 'Helpdesk'
			MembershipAttribute = 'SamAccountName'
			MembersToInclude = "RonHD"
			Ensure = 'Present'
			DependsOn = @("[xADUser]RonHD","[xWaitForADDomain]DscForestWait")
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
			Force = $true
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
			Force = $true
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
			Force = $true
        }
        Registry EnableTls12WinHttp64
        {
            Key = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
            ValueName = 'DefaultSecureProtocols'
            ValueType = 'Dword'
            ValueData = '0x00000800'
            Hex = $true
			Ensure = 'Present'
			Force = $true
        }
        #powershell defaults
        Registry SchUseStrongCrypto
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueType = 'Dword'
            ValueData =  '1'
			Ensure = 'Present'
			Force = $true
        }
        Registry SchUseStrongCrypto64
        {
            Key = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueType = 'Dword'
            ValueData =  '1'
			Ensure = 'Present'
			Force = $true
        }
        #endregion


		#region COE
		Registry DisableSmartScreen
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
            ValueName = 'SmartScreenEnable'
            ValueType = 'String'
            ValueData = 'Off'
            Ensure = 'Present'
			Force = $true
			DependsOn = '[xWaitForADDomain]DscForestWait'
        }

		xMpPreference DefenderSettings
		{
			Name = 'DefenderProperties'
			DisableRealtimeMonitoring = $true
			ExclusionPath = 'c:\Temp'
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
            DependsOn = '[xWaitForADDomain]DscForestWait'
		}
	} #end of node
} #end of configuration