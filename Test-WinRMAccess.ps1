
<#
 
    .SYNOPSIS
        Test WinRM Access Configuration
 
    .DESCRIPTION
        Check on a specified computer which certificate can or should be used
        for the WinRM HTTPS Listener, and test access to the WinRM service
 
    .PARAMETER ComputerName
        Specify a computername
 
    .PARAMETER ShowListener
        Show the listener Information
 
    .PARAMETER ShowHTTPSCertificate
        Show the active listener HTTPS Certificate
 
    .PARAMETER ShowAllCertificates
        Show all available certificates
 
    .PARAMETER Summary
        Show only summary information
 
    .PARAMETER TestPSSessionSSL
        Test if the computer can handle a PSSession with an SSL connection
 
    .EXAMPLE
        Test-WinRMAccess -ComputerName server.example.com
 
    .EXAMPLE
        Test-WinRMAccess -ComputerName localhost
 
    .EXAMPLE
        Test-WinRMAccess -ComputerName 127.0.0.1
 
    .NOTES
        Filename         : Test-WinRMAccess
        Creation Date    : 06-29-2023
        Author           : Paschal Bekke
        Copyright        : (c) 2023 - Paschal Bekke
        Purpose / Change : Test WinRM Access Configuration
        Prerequisite     : None
        Version          : 0.2
 
 
#>
 
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias("Name")]
    [string]$ComputerName,
    [switch]$ShowListener,
    [switch]$ShowHTTPSCertificate,
    [switch]$ShowAllCertificates,
	[switch]$Summary,
	[switch]$TestPSSessionSSL
)

begin {

	$Global:SaveProgressPreference = $Global:ProgressPreference
	$Global:ProgressPreference = 'SilentlyContinue'

    function Write-ToScreen($Message,$ShowOnScreen)
    {
        if($ShowOnScreen) { Write-Output "$Message" }
    }
    
    function Get-CertificateToUse($Certificates, $FQDN)
    {
        $ServerCerts = $certificates | where { $_.EnhancedKeyUsageList.objectId -match '1.3.6.1.5.5.7.3.1' }
        $DNSServerCerts  = $ServerCerts | where { ($_.Subject -replace 'CN=')  -eq $FQDN }
        $ValidCerts = $DNSServerCerts | where { $_.NotAfter -gt (Get-Date)}
        $CertToUse = ($validcerts | Sort-Object -Unique -Culture 'nl-NL' -Descending -Property NotBefore) | Select-Object -First 1
        return($CertToUse)
                
    }
    
    function RetrieveDomainFromDN($Distinguishedname)
    {
        $DomainName = (ForEach-Object{ $Distinguishedname.Split(",") | where { $_.substring(0,2) -eq "DC" } }) -join "." -replace "DC=",""
        return($DomainName)
    }
    
    function Clean-CimSession($CimSession)
    {

        # opruimen eventuele CimSessies
        Write-Verbose "Opruimen CimSessie"
        if(![string]::IsNullOrEmpty($CimSession)) {
            Get-CimSession | Remove-CimSession
        }

    }
    function LeaveScript($CimSession)
    {
        Clean-CimSession -CimSession $CimSession
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
    

    function Get-DomainRole($DomainRoleNumber)
    {
        Switch ($DomainRoleNumber) {
            0 { $role = "Standalone Workstation" }
            1 { $role = "Member Workstation" }
            2 { $role = "Standalone Server" }
            3 { $role = "Member Server" }
            4 { $role = "Backup Domain Controller" }
            5 { $role = "Primary Domain Controller" }
            default { $role = "Something not defined!"}
        }
        return($role)

    }

    function Right {
        [CmdletBinding()]
        
        Param (
            [Parameter(Position=0, Mandatory=$True,HelpMessage="Whatever you like!")]
            [String]$text,
            [Parameter(Mandatory=$True)]
            [Int]$Length
        )
        $startchar = [math]::min($text.length - $Length,$text.length)
        $startchar = [math]::max(0, $startchar)
        $Right = $text.SubString($startchar ,[math]::min($text.length, $Length))
    
        return($Right)
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

        $mySearcher = New-Object System.DirectoryServices.DirectorySearcher
        # get current domain

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
                    $SubDomainSearcher.Filter = "(&(ObjectClass=$ObjectClass) (name=$LDAPObjectName))"
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
    
    function Test-SSLPSSessionConnection($FQDNHostname) {
                
        $SSLSessionPossible = $False
                
        Try {
            $Test = New-PSSession -ComputerName $FQDNHostname -UseSSL -ErrorAction Stop
            if ([string]::IsNullOrEmpty($test)) {
                $SSLSessionPossible = $false
            } else {
                $SSLSessionPossible = $true
                Remove-PSSession -Id $test.Id }
        }
        catch {
            $SSLSessionPossible = $false
        }
        return($SSLSessionPossible)
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

        [System.Net.Sockets.TcpClient]::new().ConnectAsync($Address,$Port).Wait($Timeout)
    
    }


}

Process {
 
    Write-Verbose "Number of Computers in Pipeline: $($computername.count)"
    
    foreach($Computer in $computername) {

        $WinRMStateOK = $False # We gaan ervan uit dat WinRM NIET goed werkt.
    
        $WinRMStateInfo = "" | Select-Object FQDN, RealName, IPAddress, HTTP, HTTPS, Certificate, CorrectCert, ThumbPrint, CandidateTP, Connection, MachineType, SSLPSSession, GPODefined, Compatibility, DomainMember, Role
                
        $WinRMStateInfo.FQDN = "<empty>"
        $WinRMStateInfo.RealName = ""
        $WinRMStateInfo.IPAddress = "<empty>"
        $WinRMStateInfo.HTTPS = "Disabled"
        $WinRMStateInfo.HTTP = "Disabled"
        $WinRMStateInfo.Certificate = "No"
        $WinRMStateInfo.CorrectCert = "No"
        $WinRMStateInfo.ThumbPrint = "-"
        $WinRMStateInfo.CandidateTP = "-"
        $WinRMStateInfo.Connection = "Unknown"
        $WinRMStateInfo.MachineType = "Unknown"
        $WinRMStateInfo.SSLPSSession = "NotTested"
        $WinRMStateInfo.GPODefined = "No"
        $WinRMStateInfo.Compatibility = "No"
        $WinRMStateInfo.DomainMember = "-"
        $WinRMStateInfo.Role = "-"
                
        if($Summary) { $ShowMessage = $False } else { $ShowMessage = $True }
    
        if([string]::IsNullOrEmpty($ComputerName)) {
                    Write-ToScreen -Message "Geen ComputerName opgegeven." -ShowOnScreen $ShowMessage
                    Continue
                    # LeaveScript -CimSession $CimSession
        }
        Write-ToScreen -Message "Opvragen computer gegevens : $ComputerName" -ShowOnScreen $ShowMessage
        if(IsValidIPv4Address -ip $ComputerName) {
            try {
                $HostInfo = [system.net.dns]::GetHostByAddress($ComputerName)
            }
            catch {
                Write-ToScreen -Message "Opgegeven ComputerName ($ComputerName) is een IP adres, maar kan niet resolved worden" -ShowOnScreen $ShowMessage
                Continue
            }
        } else {
            try {
                $HostInfo = [system.net.dns]::GetHostByName($ComputerName)
            }
            catch {
                Write-ToScreen -Message "Kan geen computer met deze naam vinden." -ShowOnScreen $ShowMessage
                Write-ToScreen -Message "probeer het nog eens, maar nu met iets wat wel bestaat." -ShowOnScreen $ShowMessage
                Continue
            }
    
        }
    
        $Hostname = ($HostInfo.Hostname -split "\.")[0]
        $FQDNHost = $HostInfo.Hostname
        $IPAddress = $HostInfo.AddressList.Ipaddresstostring
    
        $WinRMStateInfo.FQDN = $FQDNHost
        $WinRMStateInfo.IPAddress = $IPAddress
    
        Write-ToScreen -Message "`nAlgemene gegevens:" -ShowOnScreen $ShowMessage
        Write-ToScreen -Message "  Hostname  : $Hostname" -ShowOnScreen $ShowMessage
        Write-ToScreen -Message "  Host FQDN : $FQDNHost" -ShowOnScreen $ShowMessage
        Write-ToScreen -Message "  IPAddress : $IPAddress" -ShowOnScreen $ShowMessage
        Write-ToScreen -Message "`nControleren of de computer online is" -ShowOnScreen $ShowMessage
                
        try {
            if(Test-PortConnection $FQDNHost -Port 135) {
                Write-ToScreen -Message "  $FQDNHost is online (Port 135)" -ShowOnScreen $ShowMessage
        } else {
            Throw
        }
    
        }
        catch {
            Write-ToScreen -Message "  $FQDNHost is offline (volgens Port Test)" -ShowOnScreen $ShowMessage
            Write-ToScreen -Message "  Controle dmv ICMP.." -ShowOnScreen $ShowMessage
    
            if (Test-Connection -ComputerName $FQDNHost -Quiet -Count 1) {
                Write-ToScreen -Message "  $FQDNHost is online (ICMP)" -ShowOnScreen $ShowMessage
                if(Test-PortConnection -Address $FQDNHost -Port 22) {
                    Write-ToScreen -Message "  $FQDNHost is waarschijnlijk een Linux computer (Port 22 is actief)" -ShowOnScreen $ShowMessage
                    Clean-CimSession -CimSession $CimSession
                    Continue
                }
            } else         {
                Write-ToScreen -Message "  $FQDNHost is offline (ICMP / Port test)" -ShowOnScreen $ShowMessage
                Clean-CimSession -CimSession $CimSession
                Continue
            }
        }
    
        Write-ToScreen -Message "`nControleren of WinRM draait op de remote computer" -ShowOnScreen $ShowMessage
        Try {
            # Eerst met DCOM (Meestal actief op PC), daarna met WSMAN
            $CimSession = New-CimSessionDown -ComputerName $FQDNHost -ErrorAction Stop
            Write-Verbose "Een CIM Sessie is gemaakt met $FQDNHost using $($CimSession.Protocol) protocol"
            $ServiceInfo = Get-CimInstance -ClassName Win32_Service -CimSession $CimSession -Filter 'Name="WinRM"'
        $WinRMStateInfo.Connection = $($CimSession.Protocol)
        }
        catch {
            Write-ToScreen -Message "Connectie via WSMAN en DCOM niet gelukt, waarschijnlijk een firewall probleem." -ShowOnScreen $ShowMessage
            Clean-CimSession -CimSession $CimSession
            Continue
        }
        if ($ServiceInfo.count -eq 0) {
            Write-ToScreen -Message "  Het lijkt erop dat WinRM niet geinstalleerd is." -ShowOnScreen $ShowMessage
            Clean-CimSession -CimSession $CimSession
            Continue
        }
    
        if(($ServiceInfo.Status -eq 'OK') -and ($ServiceInfo.State -eq 'Running')) {
            Write-ToScreen -Message "  WinRM is geinstalleerd en draait" -ShowOnScreen $ShowMessage
        } else {
            Write-ToScreen -Message "  WinRM is geinstalleerd maar heeft een probleem`nZie informatie hieronder:`n`n" -ShowOnScreen $ShowMessage
            $ServiceInfo
            Clean-CimSession -CimSession $CimSession
            Continue
        }
    
        $ComputerInformation = (Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession)

        $VirtualMachine = $ComputerInformation.Model -Match 'vmware|virtual'
        $isDomainMember = $ComputerInformation.PartOfDomain
        $DomainRole     = Get-DomainRole -DomainRoleNumber $($ComputerInformation.DomainRole)
        $CIMName        = $ComputerInformation.Name
        $CIMDomain      = $ComputerInformation.Domain
                
        $WinRMStateInfo.RealName = $CIMName+'.'+$CIMDomain
        $WinRMStateInfo.DomainMember = $isDomainMember
        $WinRMStateInfo.Role = $DomainRole

        $WinRMStateInfo.DomainMember 
    
        if($VirtualMachine) { $MachineType = "Virtual" } else { $MachineType= "Physical" }
        $WinRMStateInfo.MachineType = $MachineType
        Write-ToScreen -Message "`nMachine gegevens:  " -ShowOnScreen $ShowMessage
        Write-ToScreen -Message "  MachineType : $MachineType" -ShowOnScreen $ShowMessage
        Write-ToScreen -Message "  RealName    : $($WinRMStateInfo.RealName)" -ShowOnScreen $ShowMessage
    
        Write-ToScreen -Message "`nOpvragen WinRM Listener Informatie (Registry)" -ShowOnScreen $ShowMessage
        $ListenerItems = Get-CimEnumRegKey -Hive HKLM -Key 'SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener' -CimSession $CimSession
        $NrOfListeners = $ListenerItems.sNames.Count
    
        if($NrOfListeners -gt 0) {
            Write-ToScreen -Message "  Aantal Listeners gedefineerd : $NrOfListeners" -ShowOnScreen $ShowMessage
        } else {
            Write-ToScreen -Message "  Geen Listeners gedefinieerd" -ShowOnScreen $ShowMessage
            Clean-CimSession -CimSession $CimSession
            Continue
        }
    
        $HTTPEnabled = $false
        $HTTPSEnabled = $false
    
        if($ListenerItems.sNames -match "\bHTTP\b") {
            Write-ToScreen -Message "  - HTTP Enabled" -ShowOnScreen $ShowMessage
            $HTTPEnabled = $true
            $WinRMStateInfo.HTTP = "Enabled"
        }
        else {
            # poging 2 voor als HTTP niet is gevonden in de Registry (is NIET okay!)
            $ProgressPreference = 'SilentlyContinue'
            if(Test-PortConnection -Address $FQDNHost -Port 5985) {
                Write-ToScreen -Message "  - HTTP Enabled (ontbreekt in Registry)" -ShowOnScreen $ShowMessage
                $HTTPEnabled = $true
                $WinRMStateInfo.HTTP = "Enabled"
            }
    
        }
        if($ListenerItems.sNames -match "\bHTTPS\b") {
            Write-ToScreen -Message "  - HTTPS Enabled" -ShowOnScreen $ShowMessage
            $HTTPSEnabled = $true
            $WinRMStateInfo.HTTPS = "Enabled"
        }
    
        if($HTTPEnabled) {
                write-Verbose "HTTP Enabled - ophalen listener informatie via Get-WSManInstance"
                try {
                    $ListenerInfo = Get-WSManInstance -ComputerName $FQDNHost -ResourceURI winrm/config/listener -Enumerate -ErrorAction stop
                }
                catch {
                    Write-ToScreen -Message "  Get-WSManInstance Error" -ShowOnScreen $ShowMessage
                }
            }
    
            if(($HTTPSEnabled -eq $true) -and ($HTTPEnabled -eq $false)) { # HTTP Not enabled
                write-Verbose "HTTPS Enabled - ophalen listener informatie via Get-WSManInstance -UseSSL"
                try {
                    $ListenerInfo = Get-WSManInstance -ComputerName $FQDNHost -ResourceURI winrm/config/listener -Enumerate -UseSSL -ErrorAction Stop
                }
                catch {
                    Write-ToScreen -Message "  Het is niet mogelijk om de Listener informatie op te vragen." -ShowOnScreen $ShowMessage
                    Write-ToScreen -Message "  Waarschijnlijk is er geen certificaat aan de HTTPS Listener gekoppeld" -ShowOnScreen $ShowMessage
                }
            }
    
        if($ListenerInfo.count -gt 0){
            foreach($listener in $ListenerInfo) {
                if($listener.Source -match 'GPO') {
                    $WinRMStateInfo.GPODefined = 'Yes'
                }
                if($listener.Source -match 'Compatibility') {
                    $WinRMStateInfo.Compatibility = 'Yes'
                }

            }
        }
        

        if($ShowListener) {
            Write-ToScreen -Message "Listener Informatie van $FQDNHost`n" -ShowOnScreen $ShowMessage
            $ListenerInfo | Select-Object Transport, Port, Enabled, CertificateThumbprint, Address, ListeningOn, Hostname | Format-Table
        }
    
        Write-ToScreen -Message "`nInlezen remote certificates" -ShowOnScreen $ShowMessage
    
        # Ophalen lijst met certificaten van remote computer
        if($HTTPEnabled) {
            try {
                $certificates = Invoke-Command -ComputerName $FQDNhost -ScriptBlock { Get-ChildItem Cert:\LocalMachine\My } -ErrorAction Stop
            }
            catch {
                Write-ToScreen -Message "  Kan geen Invoke-Command uitvoeren via HTTP" -ShowOnScreen $ShowMessage
            }
        } elseif($HTTPsEnabled) {
            try {
                $certificates = Invoke-Command -ComputerName $FQDNhost -ScriptBlock { Get-ChildItem Cert:\LocalMachine\My } -UseSSL -ErrorAction Stop
            }
            catch {
                Write-ToScreen -Message "  Kan geen Invoke-Command uitvoeren via HTTPS" -ShowOnScreen $ShowMessage
            }
        }
    
        if($ShowAllCertificates) {
            Write-ToScreen -Message "" -ShowOnScreen $ShowMessage
            $certificates | Select-Object ThumbPrint, NotBefore, NotAfter, Subject, EnhancedKeyUsageList
            Write-ToScreen -Message "" -ShowOnScreen $ShowMessage
        }
        
        if($HTTPSEnabled) {
            if($WinRMStateInfo.GPODefined -eq 'Yes') {
                $ThumbPrint = ($ListenerInfo | Where { $_.transport -eq 'HTTPS'}).CertificateThumbprint -replace ' ' | Select-Object -First 1
            } else {
                $ThumbPrint = ($ListenerInfo | Where { $_.transport -eq 'HTTPS'}).CertificateThumbprint -replace ' '
            }

            if([string]::IsNullOrEmpty($ThumbPrint)) {
                Write-ToScreen -Message "  HTTPS listener is enabled, maar heeft geen certificaat." -ShowOnScreen $ShowMessage
                $WinRMStateInfo.Certificate = "No"
            }
            else {
                Write-ToScreen -Message "  HTTPS listener certificaat ThumbPrint : $ThumbPrint" -ShowOnScreen $ShowMessage
                $WinRMStateInfo.Certificate = "Yes"
                $WinRMStateInfo.ThumbPrint = $Thumbprint
                if($certificates.Thumbprint -match $Thumbprint) {
                    Write-ToScreen -Message "  De HTTPS listener heeft een overeenkomstig certificaat gekoppeld" -ShowOnScreen $ShowMessage
                    $WinRMStateInfo.CorrectCert = "Yes"
                } else {
                    $WinRMStateInfo.Certificate = "Yes"
                    $WinRMStateInfo.CorrectCert = "No"
                    Write-ToScreen -Message "  De HTTPS listener ThumbPrint is niet valide, geen overeenkomstig certificaat aanwezig" -ShowOnScreen $ShowMessage
                    $CertToUse = Get-CertificateToUse -Certificates $certificates -FQDN $FQDNhost
                    if(@($CertToUse).count -ne 1) {
                        $WinRMStateInfo.Certificate = "No"
                        $WinRMStateInfo.CorrectCert = "No"
                        Write-ToScreen -Message "  Geen geschikte certificaten gevonden voor de HTTPS listener."  -ShowOnScreen $ShowMessage
                    } else {
                        $WinRMStateInfo.CandidateTP = $CertToUse.ThumbPrint
                        Write-ToScreen -Message "`nCertificaat wat gekoppeld kan worden aan de HTTPS listener" -ShowOnScreen $ShowMessage
                        if($ShowMessage) {
                            $certtouse | Select-Object Subject, ThumbPrint, NotBefore, NotAfter
                        }
                    }
                }
    
                Write-Verbose "HTTPS certificaat zoeken in CertStore"
                $HTTPSCert = $certificates | where { $_.Thumbprint -match $ThumbPrint } # Zoek naar certificaat in de CertStore
                if($HTTPSCert.count -gt 0) { # dan is er dus een ThumbPrint gekoppeld.
                    if($HTTPSCert.EnhancedKeyUsageList.objectID -match  '1.3.6.1.5.5.7.3.1') { # ServerAuthentication OID
                        Write-ToScreen -Message "  HTTPS gebruikt een certificaat voor 'Server Authentication'" -ShowOnScreen $ShowMessage
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
                Write-ToScreen -Message "  Er is geen certificaat om te laten zien." -ShowOnScreen $ShowMessage
            }
        }
        
        if($TestPSSessionSSL) {
            if(Test-SSLPSSessionConnection -FQDNHostname $FQDNHost) {
                $WinRMStateInfo.SSLPSSession = "Successful"
            } else {
                $WinRMStateInfo.SSLPSSession = "Unavailable"
            }
        }
    
        Write-ToScreen -Message "`nPSSession Test met -UseSSL" -ShowOnScreen $ShowMessage
        Write-ToScreen -Message "  PSSession Test is : $($WinRMStateInfo.SSLPSSession)" -ShowOnScreen $ShowMessage
                
        Write-ToScreen -Message "" -ShowOnScreen $ShowMessage
                
        if($Summary) {
            $WinRMStateInfo
        }
              
    }
}
 
end {
    LeaveScript -CimSession $CimSession
}
 

