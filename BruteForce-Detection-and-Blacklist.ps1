<#
.Title
BruteForce Detection and Blacklisting
.Description
Detects bruteforce login attempts and blocks the source ip address
.How To Use
Must have failed logon auditing enabled and you must create a 'block' firewall rule called 'MY BLACKLIST'
Script identifies when 10 or more failed events have been detected, it then gathers the ip address and adds it to the scope tab of the windows fireall rule, 'MY BLACKLIST'
.Created By
Nathan Studebaker
#>

#Checks for IP addresses that used incorrect password more than 10 times
#within 1 hours and blocks them using a firewall rule 'MY BLACKLIST'

#Global variables
$logfile = "C:\support\blocked.txt"

#Check only last 1 hours
$DT = [DateTime]::Now.AddHours(-1) 

#Select Ip addresses that has audit failure $af
$af = Get-EventLog -LogName 'Security' -InstanceId 4625 -After $DT | Select-Object @{n='IpAddress';e={$_.ReplacementStrings[-2]} }

#Get ip adresses, that have more than 10 wrong logins
$g = $af | group-object -property IpAddress  | where {$_.Count -gt 10} | Select -property Name 

#Get firewall object
$fw = New-Object -ComObject hnetcfg.fwpolicy2 

#Get firewall rule named 'MY BLACKLIST' (must be created manually)
$ar = $fw.rules | where {$_.name -eq 'MY BLACKLIST'} 

#Split the existing IPs into an array so we can search it for existing IPs
$arRemote = $ar.RemoteAddresses -split(',') 

#Only collect IPs that aren't already in the firewall rule
$w = $g | where {$_.Name.Length -gt 1 -and !($arRemote -contains $_.Name + '/255.255.255.255') }

#Add the new IPs to firewall rule
$w| %{ 
  if ($ar.RemoteAddresses -eq '*') {
		$ar.remoteaddresses = $_.Name
	}else{
		$ar.remoteaddresses += ',' + $_.Name
	}
}

#Write to logfile
if ($w.length -gt 1) {
	$w| %{(Get-Date).ToString() + '	' + $_.Name >> $logfile} 
}