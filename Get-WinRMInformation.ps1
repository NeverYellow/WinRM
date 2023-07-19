
<#
 
    .SYNOPSIS
        Get WinRM HTTPS Information
 
    .DESCRIPTION
        Check on specified computer if WinRM is active and configured for
        HTTPS with Certificate
 
    .PARAMETER ComputerName
        Enter a computername
 
    .PARAMETER ShowListener
        Show the Listener Information
 
    .PARAMETER ShowHTTPSCertificate
        Show Active HTTPS Certificate
 
    .PARAMETER ShowFirewallRule
        Show Firewall Rules for port 5985/5986
 
    .PARAMETER Show8021xCertCandidate
        Show Certificates which can be used by 802.1x
 
    .EXAMPLE
        Get-WinRMInformation -ComputerName server.example.com
 
    .EXAMPLE
        Get-WinRMInformation -ComputerName localhost
 
    .EXAMPLE
        Get-WinRMInformation -ComputerName 127.0.0.1
 
    .NOTES
        Filename         : Get-WinRMInformation
        Creation Date    : 05-24-2023
        Author           : Paschal Bekke
        Copyright        : (c) 2023 - Paschal Bekke
        Purpose / Change : Get WinRM HTTPS Information
        Prerequisite     : None
        Version          : 0.2
 
 
#>
 
 
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)]
    [string]$ComputerName,
    [switch]$ShowListener,
    [switch]$ShowHTTPSCertificate,
    [switch]$ShowAllCertificates,
    [switch]$ShowFirewallRule,
    [switch]$Show8021xCertCandidate
)
function Main($ComputerName, $ShowListener, $ShowHTTPSCertificate, $ShowAllCertificates, $ShowFirewallRule, $Show8021xCertCandidate)
{
   
    $Global:SaveProgressPreference = $Global:ProgressPreference
    $Global:ProgressPreference = 'SilentlyContinue'
   
    if([string]::IsNullOrEmpty($ComputerName)) {
                    Write-Output "Geen ComputerName opgegeven."
                    LeaveScript -CimSession $CimSession
    }
    Write-Output "Opvragen computer gegevens : $ComputerName"
    if(IsValidIPv4Address -ip $ComputerName) {
        try {
            $HostInfo = [system.net.dns]::GetHostByAddress($ComputerName)
        }
        catch {
            Write-Output "Opgegeven ComputerName ($ComputerName) is een IP adres, maar kan niet resolved worden"
            LeaveScript -CimSession $CimSession
        }
    } else {
        try {
            $HostInfo = [system.net.dns]::GetHostByName($ComputerName)
        }
        catch {
            Write-Output "Kan geen computer met deze naam vinden."
            Write-Output "probeer het nog eens, maar nu met iets wat wel bestaat."
            LeaveScript -CimSession $CimSession
        }
 
    }
    $Hostname = ($HostInfo.Hostname -split "\.")[0]
    $FQDNHost = $HostInfo.Hostname
    $IPAddress = $HostInfo.AddressList.Ipaddresstostring
 
               
    Write-Output "`nAlgemene gegevens:"
    Write-Output "  Hostname  : $Hostname"
    Write-Output "  Host FQDN : $FQDNHost"
    Write-Output "  IPAddress : $IPAddress"
    Write-Output "`nControleren of de computer online is"
    try {
        if(Test-PortConnection $FQDNHost -Port 135) {
            Write-Output "  $FQDNHost is online (Port 135)"
        } else {
            Throw
        }

    }
    catch {
        Write-Output "  $FQDNHost is offline (volgens Port Test)"
        Write-Output "  Controle dmv ICMP.."
 
        #if (Test-NetConnection -ComputerName $FQDNHost -Port 135 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue) {
        if (Test-Connection -ComputerName $FQDNHost -Quiet -Count 1) {
            Write-Output "  $FQDNHost is online (ICMP)"
            if(Test-PortConnection -Address $FQDNHost -Port 22) {
                Write-Output "  $FQDNHost is waarschijnlijk een Linux computer (Port 22 is actief)"
                LeaveScript -CimSession $CimSession
            }
                    
        } else         {
            Write-Output "  $FQDNHost is offline (ICMP / Port test)"
            LeaveScript -CimSession $CimSession
        }
    }
 
    Write-Output "`nControleren of WinRM draait op de remote computer"
    Try {
        # Eerst met DCOM (Meestal actief op PC)
              
        # $CimSessionOption = New-CimSessionOption -Protocol Dcom -ErrorAction Stop
        # $CimSession = New-CimSession -ComputerName $FQDNHost -SessionOption $CimSessionOption
        $CimSession = New-CimSessionDown -ComputerName $FQDNHost -ErrorAction Stop
        Write-Verbose "Een CIM Sessie is gemaakt met $FQDNHost using $($CimSession.Protocol) protocol"
        $ServiceInfo = Get-CimInstance -ClassName Win32_Service -CimSession $CimSession -Filter 'Name="WinRM"'
    }
    catch {
        Write-Output "Connectie via WSMAN en DCOM niet gelukt, waarschijnlijk een firewall probleem."
        LeaveScript -CimSession $CimSession
    }      
    if ($ServiceInfo.count -eq 0) {
        Write-Output "  Het lijkt erop dat WinRM niet geinstalleerd is."
        LeaveScript -CimSession $CimSession
    }
 
 
    if(($ServiceInfo.Status -eq 'OK') -and ($ServiceInfo.State -eq 'Running')) {
        Write-Output "  WinRM is geinstalleerd en draait"
    }
    else {
        Write-Output "  WinRM is geinstalleerd maar heeft een probleem`nZie informatie hieronder:`n`n"
        $ServiceInfo
        LeaveScript -CimSession $CimSession
    }
 
    $VirtualMachine = (Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession).Model -Match 'vmware|virtual'
    
    if($VirtualMachine) { $MachineType = "Virtual" } else { $MachineType= "Physical" }
    Write-Output "`nMachine gegevens:  "
    Write-Output "  MachineType : $MachineType"
 
    Write-Output "`nOpvragen WinRM Listener Informatie (Registry)"
    $ListenerItems = Get-CimEnumRegKey -Hive HKLM -Key 'SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener' -CimSession $CimSession
    $NrOfListeners = $ListenerItems.sNames.Count
 
    if($NrOfListeners -gt 0) {
        Write-Output "  Aantal Listeners gedefineerd : $NrOfListeners"
    } else {
        Write-Output "  Geen Listeners gedefinieerd"
        LeaveScript -CimSession $CimSession
    }
 
    $HTTPEnabled = $false
    $HTTPSEnabled = $false
 
    if($ListenerItems.sNames -match "\bHTTP\b") {
        Write-Output "  - HTTP Enabled"
        $HTTPEnabled = $true
    }
    else {
        # poging 2 voor HTTP, als HTTP niet is gevonden in de Registry (is niet Okay!)
        $ProgressPreference = 'SilentlyContinue'
        if(Test-PortConnection -Address $FQDNHost -Port 5985) {
            Write-Output "  - HTTP Enabled (ontbreekt in Registry)"
            $HTTPEnabled = $true
        }
 
    }
    if($ListenerItems.sNames -match "\bHTTPS\b") {
        Write-Output "  - HTTPS Enabled"
        $HTTPSEnabled = $true
    }
 
    if($HTTPEnabled) {
            write-Verbose "HTTP Enabled - ophalen listener informatie via Get-WSManInstance"
            try {
                $ListenerInfo = Get-WSManInstance -ComputerName $FQDNHost -ResourceURI winrm/config/listener -Enumerate -ErrorAction stop
            }
            catch {
                Write-Output "  Get-WSManInstance Error"
            }
        }
 
        if(($HTTPSEnabled -eq $true) -and ($HTTPEnabled -eq $false)) { # HTTP Not enabled
            write-Verbose "HTTPS Enabled - ophalen listener informatie via Get-WSManInstance -UseSSL"
            try {
                $ListenerInfo = Get-WSManInstance -ComputerName $FQDNHost -ResourceURI winrm/config/listener -Enumerate -UseSSL -ErrorAction Stop
            }
            catch {
                Write-Output "  Het is niet mogelijk om de Listener informatie op te vragen."
                Write-output "  Waarschijnlijk is er geen certificaat aan de HTTPS Listener gekoppeld"
            }
        }
    if($ShowListener) {
        Write-Output "Listener Informatie van $FQDNHost`n"
        $ListenerInfo
    }
  
    Write-Output "`nInlezen remote certificates"
  
    # Lijst met certificaten van remote computer
    if($HTTPEnabled) {
        try {
            $certificates = Invoke-Command -ComputerName $FQDNhost -ScriptBlock { Get-ChildItem Cert:\LocalMachine\My } -ErrorAction Stop
        }
        catch {
            Write-Output "  Kan geen Invoke-Command uitvoeren via HTTP"
        }
    } elseif($HTTPsEnabled) {
        try {
            $certificates = Invoke-Command -ComputerName $FQDNhost -ScriptBlock { Get-ChildItem Cert:\LocalMachine\My } -UseSSL -ErrorAction Stop
        }
        catch {
            Write-Output "  Kan geen Invoke-Command uitvoeren via HTTPS"
        }
    }
    
    if($ShowAllCertificates) {
        Write-Output ""
        $certificates
        Write-Output ""
    }
    # Controleer of er WinRM Certificaat is
    $WinRMCertificate = $certificates | where { $_.EnhancedKeyUsageList.objectid -match  '1.3.6.1.4.1.311.21.8' }  # WinRM OID
    $WinRMCertificateFlag = $WinRMCertificate.count -gt 0
    if($WinRMCertificateFlag) {
        Write-Output "  Er is een WinRM Certifictaat in de Remote Certificate Store van : $FQDNhost"
       if($WinRMCertificate.EnhancedKeyUsageList.objectID -match  '1.3.6.1.5.5.7.3.1') { # ServerAuthentication OID
            Write-Output "  De EnhancedKeyUsageList van het WinRM certificaat bevat een 'KeyUsage' voor 'Server Authentication'"
        }
        Write-Output "  WinRM Certificaat ThumbPrint : $($WinRMCertificate.ThumbPrint)"
    }
    else {
        Write-Output "  Geen WinRM Certificaat gevonden in de Remote Certificate Store van : $FQDNhost"
    }
    if($HTTPSEnabled) {
        $ThumbPrint = ($ListenerInfo | Where { $_.transport -eq 'HTTPS'}).CertificateThumbprint -replace ' '
        if([string]::IsNullOrEmpty($ThumbPrint)) {
            Write-Output "  HTTPS is enabled, maar heeft geen certificaat."
        }
        else {
            Write-Output "  HTTPS Certificaat ThumbPrint : $ThumbPrint"
            if($certificates.Thumbprint -match $Thumbprint) {
                Write-Output "  Voor HTTPS is een overeenkomstig certificaat aanwezig"
            } else {
                Write-Output "  De HTTPS listener ThumbPrint is niet valide, geen overeenkomstig certificaat aanwezig"
            }
 
            Write-Verbose "HTTPS certificaat zoeken in CertStore"
            $HTTPSCert = $certificates | where { $_.Thumbprint -match $ThumbPrint } # Zoek naar certificaat in de CertStore
            if($HTTPSCert.count -gt 0) { # dan is er dus een ThumbPrint gekoppeld.
                if($WinRMCertificateFlag) { # verifieer of WinRM Certifcate bestaat
                    if($HTTPSCert.Thumbprint -eq $WinRMCertificate.ThumbPrint) {
                        Write-Output "  HTTPS gebruikt het WinRM certificaat"
                    }
                    else {
                        if($HTTPSCert.EnhancedKeyUsageList.objectID -match  '1.3.6.1.5.5.7.3.1') { # ServerAuthentication OID
                            Write-Output "  Er is dus een WinRM certificaat, maar HTTPS gebruikt een ander certificaat voor 'Server Authentication'"
                        }
                      
                    }
                }
            }
        }
    }
    if($HTTPScert.count -gt 0) {
        if($ShowHTTPSCertificate) {
            $HTTPSCert | Format-List * -Force
        }
    } else {
        if($ShowHTTPSCertificate) {
            Write-Output "  Er is geen certificaat om te laten zien."
        }
      
    }
    Write-Output "`nOpvragen Firewall rules"
  
    $HTTPFirewallRules = Get-NetFirewallPortFilter -Protocol TCP -PolicyStore ActiveStore -CimSession $cimsession | where { $_.LocalPort -eq 5985 } | Get-NetFirewallRule
    $HTTPSFirewallRules = Get-NetFirewallPortFilter -Protocol TCP -PolicyStore ActiveStore -CimSession $cimsession | where { $_.LocalPort -eq 5986 } | Get-NetFirewallRule
 
    if(@($HTTPFirewallRules).count -gt 0) {
        Write-output "  Aantal Firewall Rules voor HTTP : $(@($HTTPFirewallRules).count) - Port 5985"
        foreach($Rule in $HTTPFirewallRules) {
            Write-output "    Name: $($Rule.DisplayName) Profile: $($Rule.Profile) Enabled: $($Rule.Enabled)"
        }
        Write-Output ""
    }
    if(@($HTTPSFirewallRules).count -gt 0) {
        Write-output "  Aantal Firewall Rules voor HTTPS : $(@($HTTPSFirewallRules).count) - Port 5986"
        foreach($Rule in $HTTPSFirewallRules) {
            Write-output "    Name: $($Rule.DisplayName) Profile: $($Rule.Profile) Enabled: $($Rule.Enabled)"
        }
    }
 
    if($ShowFirewallRule){
        Write-Output "`nFirewall Rules van $FQDNHost"
        $HTTPFirewallRules | Format-Table -AutoSize
        
        Write-Output ""
        $HTTPSFirewallRules | Format-Table -AutoSize
    }
 
    write-output "`nOpvragen lijst van 802.1x kandidaat Certificaten"
    $ComputerList = Find-LDAPObject -LDAPObjectName $FQDNHost.Split(".")[0] -SearchTrustedDomain -ObjectClass Computer
  
    $CandidateCerts = $Certificates | where {$_.EnhancedKeyUsageList -match '1.3.6.1.5.5.7.3.2' -and $_.subject -eq ($ComputerList.Properties.distinguishedname -replace ',',', ')}
    $DomainName = RetrieveDomainFromDN -Distinguishedname $($ComputerList.Properties.distinguishedname)
 
    Write-Output "  Computer $FQDNHost gevonden via LDAPSearch in ActiveDirectory Domain: $DomainName"
    Write-Output "  Computer $FQDNHost DistinguishedName (DN) : $($ComputerList.Properties.distinguishedname)"
   
    if(@($CandidateCerts).count -gt 0) {
        Write-Output "`n  Aantal overeenkomstige certificaten gevonden : $($CandidateCerts.count)"
       
        foreach($Cert in $CandidateCerts) {
            Write-Output "    ThumbPrint: $($Cert.ThumbPrint)"
            Write-Output "    Subject   : $($Cert.subject)"
            Write-Output "    Created   : $($Cert.NotBefore)"
            Write-Output ""
        }
       
        $CertToBeUsed = ($CandidateCerts | Sort-Object -Unique -Culture 'nl-NL' -Descending -Property NotBefore) | Select-Object -First 1
        $CertDate = get-date($CertToBeUsed.NotBefore) -f "dd-MM-yyyy"
        Write-output "  Certificaat welke gebruikt wordt : ThumbPrint : $($CertToBeUsed.ThumbPrint) met meest recente datum $CertDate (nl-NL) "
    } else {
        Write-Output "`n  Geen overeenkomstige certificaten gevonden voor gebruik van 802.1x"
    }
       
    Write-Output ""
       
    if($Show8021xCertCandidate) {
        Write-Output "`nClient certificaten lijst van $FQDNHost met DN definitie"
 
        $CandidateCerts | Format-Table -AutoSize
    }
   
 
    Write-Output ""
    LeaveScript -CimSession $CimSession          
               
}
 
function RetrieveDomainFromDN($Distinguishedname)
{
    $DomainName = (ForEach-Object{ $Distinguishedname.Split(",") | where { $_.substring(0,2) -eq "DC" } }) -join "." -replace "DC=",""
    return($DomainName)
}
 
function LeaveScript($CimSession)
{
    # opruimen eventuele CimSessies
    Write-Verbose "Opruimen CimSessie"
    if(![string]::IsNullOrEmpty($CimSession)) {
        Get-CimSession | Remove-CimSession
    }
    # restore ProgressPreference
    $Global:ProgressPreference = $Global:SaveProgressPreference
    Exit;
}
 
function New-CimSessionDown {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [Alias("Name")]
            [ValidateNotNullorEmpty()]
            [string[]] $ComputerName = $env:COMPUTERNAME,
            [PSCredential] $Credential,
            $OperationTimeoutSec = 5
        )
   
        begin {
            $IDS_FUNCTIONNAME = 'New-CimSessionDown'
           
            $sessionOption = New-CimSessionOption -Protocol Dcom
   
            $sessionSplat = @{
                Verbose = $false
                OperationTimeoutSec = $OperationTimeoutSec
            }
           
            if ($Credential) {
                $sessionSplat.Credential = $Credential
            }
        }
   
        Process {
            foreach ($computer in $ComputerName) {
                if ($cimSession = Get-CimSession -ComputerName $computer -ErrorAction:SilentlyContinue | Select-Object -First 1) {
                    Write-Verbose "${IDS_FUNCTIONNAME}: Used existing connection to $computer using the $($cimSession.Protocol) protocol."
                }
               
                try {
                    if (!$cimSession) {
                        if ((Test-WSMan -ComputerName $computer).productversion -match 'Stack: ([3-9]|[1-9][0-9]+)\.[0-9]+') {
                            $cimSession = New-CimSession -ComputerName $computer @sessionSplat
                            Write-Verbose "${IDS_FUNCTIONNAME}: Connected to $computer using the WSMAN protocol."
                        }
                    }
                } catch {
                    Write-Verbose "${IDS_FUNCTIONNAME}: Failed to connect to $computer with WSMAN protocol: $_"
                }
   
                try {
                    if (!$cimSession) {
                        New-CimSession -ComputerName $computer @sessionSplat -SessionOption $sessionOption
                        Write-Verbose "${IDS_FUNCTIONNAME}: Connected to $computer using the DCOM protocol."
                    }
                } catch {
                    Write-Error "${IDS_FUNCTIONNAME}: Failed to connect to $computer with DCOM protocol: $_"
                }
   
                if ($cimSession) {
                    $cimSession
                }
            }
        }
   
        end {
        }
}
 
function IsValidIPv4Address ($ip) {
    return ($ip -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" -and [bool]($ip -as [ipaddress]))
}
function Get-CimEnumRegKey {
    param (
        [parameter(Mandatory=$true)]           
        [ValidateSet("HKCR", "HKCU", "HKLM", "HKUS", "HKCC")]           
        [string]$Hive,     
 
        [Parameter(Mandatory)]
        [String]$Key,
   
        [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]           
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )
 
    switch ($Hive){           
        "HKCR" { [uint32]$hdkey = 2147483648 } #HKEY_CLASSES_ROOT           
        "HKCU" { [uint32]$hdkey = 2147483649 } #HKEY_CURRENT_USER            
        "HKLM" { [uint32]$hdkey = 2147483650 } #HKEY_LOCAL_MACHINE           
        "HKUS" { [uint32]$hdkey = 2147483651 } #HKEY_USERS           
        "HKCC" { [uint32]$hdkey = 2147483653 } #HKEY_CURRENT_CONFIG           
    }           
 
    $argList = @{hDefKey = $hdkey; sSubKeyName = $Key} # ; sValueName = $value}           
 
    $Result = Invoke-CimMethod -ClassName StdRegProv -MethodName EnumKey -Arguments $argList -CimSession $CimSession
   
    return($Result)
 
}
 
function right {
   [CmdletBinding()]
   Param (
      [Parameter(Position=0, Mandatory=$True,HelpMessage="Enter a string of text")]
      [String]$text,
      [Parameter(Mandatory=$True)]
      [Int]$Length
   )
    $startchar = [math]::min($text.length - $Length,$text.length)
    $startchar = [math]::max(0, $startchar)
    $right = $text.SubString($startchar ,[math]::min($text.length, $Length))
   
    return($right)
}
 
Function Find-LDAPObject
{
    <#
 
        .SYNOPSIS
            Find LDAP computer object
 
        .DESCRIPTION
            Find all specified computer objects by searching in LDAP
 
        .PARAMETER LDAPObjectName
            Enter a objectname to search for
 
        .PARAMETER ObjectClass
            Select an ObjectClass like Computer, Person or TrustedDomain
 
        .PARAMETER SearchTrustedDomain
            Search also in TrustedDomains (if available)
 
        .EXAMPLE
            $Information = FindLDAPObject -LDAPObjectName $LDAPObjectName.split('.')[0] -ObjectClass Computer -SearchTrustedDomain:$SearchTrustedDomain
 
        .NOTES
            Filename         : Find-LDAPComputerObject
            Creation Date    : 05-24-2023
            Author           : Paschal Bekke
            Copyright        : (c) 2023 - Paschal Bekke
            Purpose / Change : Find LDAP computer object
            Prerequisite     : None
            Version          : 0.2
 
 
    #>
 
 
    [CmdletBinding()]
    Param (
   
      [Parameter(Mandatory=$true)]
      [String]$LDAPObjectName,
 
      [parameter(Mandatory=$true)]           
      [ValidateSet("Computer", "Person", "TrustedDomain")]           
      [string]$ObjectClass,
 
      [switch]$SearchTrustedDomain
 
 
    )
    $AllResults = @()
 
    Write-Verbose "SearchTrustedDomain : $SearchTrustedDomain"
 
    $mySearcher = New-Object System.DirectoryServices.DirectorySearcher # get current domain
 
    $mySearcher.Filter = "(& (ObjectClass=$ObjectClass) (name=$LDAPObjectName))"
    Write-Verbose "Zoeken in domain: $($MySearcher.SearchRoot.name)"
    $Info = $mySearcher.FindAll()
 
    # nu opzoek naar eventuele sub domains
    if($SearchTrustedDomain) {
        Write-Verbose "Zoeken in TrustedDomain geselecteerd"
        $MySearcher.Filter = "(& (ObjectClass=TrustedDomain))"
        $Domains = $mySearcher.FindAll()
        if(@($Domains).count -gt 0) {
            Write-Verbose "Trusted Domains gevonden: $(@($Domains).count)"
            foreach($Domain in @($Domains)) {
                Write-Verbose "Bezig met zoeken in domain: $($Domain.properties.name)"
                $SubDomainSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $SubDomainSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($domain.properties.name)")
                $SubDomainSearcher.Filter = "(& (ObjectClass=$ObjectClass) (name=$LDAPObjectName))"
                $result = $SubDomainSearcher.FindAll()
                if(![string]::IsNullOrEmpty($result)) {
                    Write-Verbose "Object Gevonden!"
                    $AllResults+=$result
                }
 
            }
        }
 
    }
  
    $AllResults += $Info   
    Return($AllResults)
   
}

Function Test-PortConnection
{
    Param (
      [Parameter(Mandatory=$true)]
      [String]$Address,
      [parameter(Mandatory=$true)]           
      [Int]$Port,
      [Int]$Timeout=100
    )

     [System.Net.Sockets.TcpClient]::new().ConnectAsync($Address, $Port).Wait($Timeout)

}

main -ComputerName $ComputerName -ShowListener $ShowListener -ShowHTTPSCertificate $ShowHTTPSCertificate -ShowAllCertificates $ShowAllCertificates -ShowFirewallRule $ShowFirewallRule -Show8021xCertCandidate $Show8021xCertCandidate
