## should be committed back to xSystemSecurity
Import-Module xDSCResourceDesigner

$properties = @(
    New-xDscResourceProperty -Name Setting -Type String -Attribute Key -ValidateSet "AlwaysNotify","NotifyChanges","NotifyChangesWithoutDimming","NeverNotify","NeverNotifyAndDisableAll"
    New-xDscResourceProperty -Name Force -Type Boolean -Attribute Write -ValidateSet $true,$false
)

New-xDscResource -Name ah_xSystemSecurity -Property $properties