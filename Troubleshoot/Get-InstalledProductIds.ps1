# used when trying to find productid; useful in DSC as official name and GUID need to pbne provided 
Get-WmiObject Win32_Product | Format-Table IdentifyingNumber, Name, Version