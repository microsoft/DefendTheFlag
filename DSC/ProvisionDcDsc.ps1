Configuration CreateADForest
{
	param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$DomainName='Contoso.Azure',

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$NetBiosName='Contoso',

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[PSCredential]$AdminCreds,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$UserPrincipalName = "seccxp.ninja",

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
		[int]$RetryIntervalSec=30
	)
	Import-DscResource -ModuleName xActiveDirectory
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
			DependsOn = '[xADDomain]ContosoDC'
		}

		xWaitForADDomain DscForestWait
		{
				DomainName = $DomainName
				DomainUserCredential = $DomainCreds
				RetryCount = $RetryCount
				RetryIntervalSec = $RetryIntervalSec
				DependsOn = "[xADDomain]ContosoDC"
		}

		Registry HideServerManager
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\ServerManager'
            ValueName = 'DoNotOpenServerManagerAtLogon'
            ValueType = 'Dword'
            ValueData = '1'
            Force = $true
            Ensure = 'Present'
			DependsOn = @("[xADForestProperties]ForestProps", "[xWaitForADDomain]DscForestWait")
		}

        Registry HideInitialServerManager
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\ServerManager\Oobe'
            ValueName = 'DoNotOpenInitialConfigurationTasksAtLogon'
            ValueType = 'Dword'
            ValueData = '1'
            Force = $true
            Ensure = 'Present'
			DependsOn = @("[xADForestProperties]ForestProps", "[xWaitForADDomain]DscForestWait")
		}

		#region cChoco

		cChocoInstaller InstallChoco
        {
			InstallDir = 'C:\choco'
			DependsOn = @('[xADForestProperties]ForestProps', '[xWaitForADDomain]DscForestWait')
        }

        cChocoPackageInstaller InstallSysInternals
        {
            Name = 'sysinternals'
			Ensure = 'Present'
			AutoUpgrade = $false
            DependsOn = '[cChocoInstaller]InstallChoco'
		}
		#endegion
	
        Script DownloadBginfo
        {
            SetScript =
            {
                if ((Test-Path -PathType Container -LiteralPath 'C:\BgInfo\') -ne $true){
					New-Item -Path 'C:\BgInfo\' -ItemType Directory
				}
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $ProgressPreference = 'SilentlyContinue' # used to speed this up from 30s to 100ms
                Invoke-WebRequest -Uri 'https://github.com/microsoft/DefendTheFlag/blob/master/Downloads/BgInfo/contosodc.bgi?raw=true' -Outfile 'C:\BgInfo\BgInfoConfig.bgi'
			}
            GetScript =
            {
                if ((Test-Path -LiteralPath 'C:\BgInfo\BgInfoConfig.bgi' -PathType Leaf) -eq $true){
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
                if ((Test-Path -LiteralPath 'C:\BgInfo\BgInfoConfig.bgi' -PathType Leaf) -eq $true){
                    return $true
                }
                else {
                    return $false
                }
			}
			DependsOn = @('[xWaitForADDomain]DscForestWait','[cChocoPackageInstaller]InstallSysInternals')
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

		Registry DisableSmartScreen
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
            ValueName = 'SmartScreenEnable'
            ValueType = 'String'
            ValueData = 'Off'
            Ensure = 'Present'
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
				$s=(New-Object -COM WScript.Shell).CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Cmd.lnk')
				$s.TargetPath='cmd.exe'
				$s.Description = 'Cmd.exe shortcut on everyones desktop'
				$s.Save()
			}
			GetScript = 
            {
                if (Test-Path -LiteralPath 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Cmd.lnk'){
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
                if (Test-Path -LiteralPath 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Cmd.lnk'){
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