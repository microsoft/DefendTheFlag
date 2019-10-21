Configuration SetupVictimPc
{
    param(
        # COE
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainName = "Contoso.Azure",
            
        # COE
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$NetBiosName = "Contoso",

        # COE
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DnsServer,

        # COE
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCredential]$AdminCred,

        # AATP: Used to expose RonHD cred to machine
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [PSCredential]$RonHdCred,

        # Branch
        ## Useful when have multiple for testing
        [Parameter(Mandatory=$false)]
        [String]$Branch='master'
    )
    #region COE
    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion 8.10.0.0
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xDefender -ModuleVersion 0.2.0.0
    Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion 6.5.0.0
    Import-DscResource -ModuleName NetworkingDsc -ModuleVersion 7.4.0.0
    Import-DscResource -ModuleName xSystemSecurity -ModuleVersion 1.4.0.0
    Import-DscResource -ModuleName cChoco -ModuleVersion 2.4.0.0
    Import-DscResource -ModuleName xPendingReboot -ModuleVersion 0.4.0.0

    [PSCredential]$Creds = New-Object System.Management.Automation.PSCredential ("${NetBiosName}\$($AdminCred.UserName)", $AdminCred.Password)
    #endregion

    #region AATP stuff
    [PSCredential]$RonHdDomainCred = New-Object System.Management.Automation.PSCredential ("${NetBiosName}\$($RonHdCred.UserName)", $RonHdCred.Password)
    #endregion

    Node localhost
    {
        LocalConfigurationManager
        {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
            ActionAfterReboot = 'ContinueConfiguration'
        }

        #region COE
        xService DisableWindowsUpdate
        {
            Name = 'wuauserv'
            State = 'Stopped'
            StartupType = 'Disabled'
        }

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

        # Set settings for TLS first so we domain join and then can reboot
        Computer JoinDomain
        {
            Name = 'VictimPC'
            DomainName = $DomainName
            Credential = $Creds
        }

        xGroup AddAdmins
        {
            GroupName = 'Administrators'
            MembersToInclude = @("$NetBiosName\Helpdesk", "$NetBiosName\JeffL")
            Ensure = 'Present'
            DependsOn = '[Computer]JoinDomain'
        }

        xRegistry HideServerManager
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\ServerManager'
            ValueName = 'DoNotOpenServerManagerAtLogon'
            ValueType = 'Dword'
            ValueData = '1'
            Force = $true
            Ensure = 'Present'
            DependsOn = '[Computer]JoinDomain'
        }

        xRegistry HideInitialServerManager
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\ServerManager\Oobe'
            ValueName = 'DoNotOpenInitialConfigurationTasksAtLogon'
            ValueType = 'Dword'
            ValueData = '1'
            Force = $true
            Ensure = 'Present'
            DependsOn = '[Computer]JoinDomain'
        }
        #endregion

        #region AATP
        # every 10 minutes open up a new CMD.exe as RonHD
        ScheduledTask RonHd
        {
            TaskName = 'SimulateRonHdProcess'
            ScheduleType = 'Once'
            Description = 'Simulates RonHD exposing his account via an interactive or scheduled task manner.  In this case, we use scheduled task. This mimics the machine being managed.'
            Ensure = 'Present'
            Enable = $true
            TaskPath = '\AatpScheduledTasks'
            ExecuteAsCredential = $RonHdDomainCred
            ActionExecutable = 'cmd.exe'
            Priority = 7
            DisallowHardTerminate = $false
            RepeatInterval = '00:10:00'
            RepetitionDuration = 'Indefinitely'
            StartWhenAvailable = $true
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

        cChocoPackageInstaller InstallTorBrowser
        {
            Name = 'tor-browser'
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
            Params = '/Product=O365ProPlusRetail /64Bit'
            DependsOn = '[cChocoInstaller]InstallChoco'
        }
        #endregion

        xRemoteFile DownloadBginfo
		{
			DestinationPath = 'C:\BgInfo\BgInfoConfig.bgi'
			Uri = "https://github.com/microsoft/DefendTheFlag/blob/$Branch/Downloads/BgInfo/victimpc.bgi?raw=true"
            DependsOn = '[Computer]JoinDomain'
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

        #endregion
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

        #region AttackScripts
        xRemoteFile GetCtfA
        {
            DestinationPath = 'C:\LabScripts\Backup\ctf-a.zip'
            Uri = 'https://github.com/microsoft/DefendTheFlag/blob/v1.0/Downloads/AATP/ctf-a.zip?raw=true'
            DependsOn = '[Computer]JoinDomain'
        }
        Archive UnzipCtfA
        {
            Path = 'C:\LabScripts\Backup\ctf-a.zip'
            Destination = 'C:\LabScripts\ctf-a'
            Ensure = 'Present'
            Force = $true
            DependsOn = '[xRemoteFile]GetCtfA'
        }

        xRemoteFile GetAatpSaPlaybook
        {
            DestinationPath = 'C:\LabScripts\Backup\aatpsaplaybook.zip'
            Uri = 'https://github.com/microsoft/DefendTheFlag/blob/v1.0/Downloads/AATP/aatpsaplaybook.zip?raw=true'
            DependsOn = '[Computer]JoinDomain'
        }

        Archive UnzipAatpSaPlaybook
        {
            Path = 'C:\LabScripts\Backup\aatpsaplaybook.zip'
            Destination = 'C:\LabScripts\AatpSaPlaybook'
            Ensure = 'Present'
            Force = $true
            DependsOn = '[xRemoteFile]GetAatpSaPlaybook'
        }
        #endregion
        
        xMpPreference DefenderSettings
        {
            Name = 'DefenderSettings'
            ExclusionPath = 'C:\Tools'
            DisableRealtimeMonitoring = $true
            DisableArchiveScanning = $true
        }
        #endregion

        #region AipClient
        xRemoteFile GetAipClient
        {
            Uri = 'https://github.com/microsoft/DefendTheFlag/blob/master/Downloads/AIP/Client/AzInfoProtection_UL_Preview_MSI_for_central_deployment.msi?raw=true'
            DestinationPath = 'C:\LabTools\AIP_UL_Preview.msi'
            DependsOn = '[Computer]JoinDomain'
        }

		xPackage InstallAipClient
		{
            Name = 'Microsoft Azure Information Protection'
            Ensure = 'Present'
            Path = 'C:\LabTools\AIP_UL_Preview.msi'
            ProductId = '{B6328B23-18FD-4475-902E-C1971E318F8B}'
            DependsOn = '[xRemoteFile]GetAipClient'
        }
        #endregion

        #region HackTools
        xRemoteFile GetMimikatz
        {
            DestinationPath = 'C:\Tools\Backup\Mimikatz.zip'
            Uri = 'https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20190512/mimikatz_trunk.zip'
            DependsOn = @('[xMpPreference]DefenderSettings', '[Registry]DisableSmartScreen', '[Computer]JoinDomain')
        }
        xRemoteFile GetPowerSploit
        {
            DestinationPath = 'C:\Tools\Backup\PowerSploit.zip'
            Uri = 'https://github.com/PowerShellMafia/PowerSploit/archive/master.zip'
            DependsOn = @('[xMpPreference]DefenderSettings', '[Registry]DisableSmartScreen', '[Registry]SchUseStrongCrypto64', '[Registry]SchUseStrongCrypto')
        }
        xRemoteFile GetKekeo
        {
            DestinationPath = 'C:\Tools\Backup\kekeo.zip'
            Uri = 'https://github.com/gentilkiwi/kekeo/releases/download/2.2.0-20190407/kekeo.zip'
            DependsOn = @('[xMpPreference]DefenderSettings', '[Registry]DisableSmartScreen', '[Registry]SchUseStrongCrypto64', '[Registry]SchUseStrongCrypto')
        }
        xRemoteFile GetNetSess
        {
            DestinationPath = 'C:\Tools\Backup\NetSess.zip'
            Uri = 'https://github.com/ciberesponce/AatpAttackSimulationPlaybook/blob/master/Downloads/NetSess.zip?raw=true'
            DependsOn = @('[xMpPreference]DefenderSettings', '[Registry]DisableSmartScreen', '[Registry]SchUseStrongCrypto64', '[Registry]SchUseStrongCrypto')
        }

        Archive UnzipMimikatz
        {
            Path = 'C:\Tools\Backup\Mimikatz.zip'
            Destination = 'C:\Tools\Mimikatz'
            Ensure = 'Present'
            Force = $true
            DependsOn = '[xRemoteFile]GetMimikatz'
        }

        Archive UnzipPowerSploit
        {
            Path = 'C:\Tools\Backup\PowerSploit.zip'
            Destination = 'C:\Tools\PowerSploit'
            Ensure = 'Present'
            Force = $true
            DependsOn = '[xRemoteFile]GetPowerSploit'
        }

        Archive UnzipKekeo
        {
            Path = 'C:\Tools\Backup\kekeo.zip'
            Destination = 'C:\Tools\Kekeo'
            Ensure = 'Present'
            Force = $true
            DependsOn = '[xRemoteFile]GetKekeo'
        }

        Archive UnzipNetSess
        {
            Path = 'C:\Tools\Backup\NetSess.zip'
            Destination = 'C:\Tools\NetSess'
            Ensure = 'Present'
            Force = $true
            DependsOn = '[xRemoteFile]GetNetSess'
        }
        #endregion
    }
}