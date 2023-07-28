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
 
    .PARAMETER EnterSSLSession
        Creates a PSSession connection to the tested computer if possible
 
    .EXAMPLE
        Test-WinRMAccess -ComputerName server.example.com
 
    .EXAMPLE
        Test-WinRMAccess -ComputerName localhost
 
    .EXAMPLE
        Test-WinRMAccess -ComputerName 127.0.0.1
 
    .EXAMPLE
        Get-ADComputer -Filter * | Select-Object Name | .\Test-WinRMAccess.ps1
        -Summary
 
        Reads AD Computer objects and pipes it to the script
 
    .INPUTS
        Pipeline-Aware, see Examples
 
    .NOTES
        Filename         : Test-WinRMAccess
        Creation Date    : 07-20-2023
        Author           : Paschal Bekke
        Copyright        : (c) 2023 - Paschal Bekke
        Purpose / Change : Test WinRM Access Configuration
        Prerequisite     : None
        Version          : 0.4
 
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias("Name")]
    [string[]]$ComputerName,
    [switch]$ShowListener,
    [switch]$ShowHTTPSCertificate,
    [switch]$ShowAllCertificates,
                [switch]$Summary,
                [switch]$TestPSSessionSSL,
                [switch]$EnterSSLSession
               
)
 
begin {
 
                $Global:SaveProgressPreference = $Global:ProgressPreference
                $Global:ProgressPreference = 'SilentlyContinue'
 
                function WriteTo-Screen($Message,$ShowOnScreen)
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
                        Write-Verbose "${IDS_FUNCTIONNAME}: Now trying again with WSMAN -UseSSL: $_"
                        # Trying again with -UseSSL
                        if ((Test-WSMan -ComputerName $computer -UseSSL).productversion -match 'Stack: ([3-9]|[1-9][0-9]+)\.[0-9]+') {
                            $CimSessionOption = New-CimSessionOption -UseSSL
                            $cimSession = New-CimSession -ComputerName $computer @sessionSplat -SessionOption $CimSessionOption
                            Write-Verbose "${IDS_FUNCTIONNAME}: Connected to $computer using the WSMAN protocol (SSL)."
                        }

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
        Write-Verbose "Searching domain: $($MySearcher.SearchRoot.name)"
        $Info = $mySearcher.FindAll()
   
        # nu opzoek naar eventuele sub domains
        if($SearchTrustedDomain) {
            Write-Verbose "TrustedDomain search"
            $MySearcher.Filter = "(& (ObjectClass=TrustedDomain))"
            $Domains = $mySearcher.FindAll()
            if(@($Domains).count -gt 0) {
                Write-Verbose "Trusted Domains found: $(@($Domains).count)"
                foreach($Domain in @($Domains)) {
                    Write-Verbose "Busy searching in Domain: $($Domain.properties.name)"
                    $SubDomainSearcher = New-Object System.DirectoryServices.DirectorySearcher
                    $SubDomainSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($domain.properties.name)")
                    $SubDomainSearcher.Filter = "(&(ObjectClass=$ObjectClass) (name=$LDAPObjectName))"
                    $result = $SubDomainSearcher.FindAll()
                    if(![string]::IsNullOrEmpty($result)) {
                        Write-Verbose "Object Found!"
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
    foreach($Computer in $computername) {
 
        $WinRMStateOK = $False # We will assume that WinRM is NOT configured correctly
   
        $WinRMStateInfo = "" | Select-Object FQDN, RealName, IPAddress, HTTP, HTTPS, Certificate, CorrectCert, ThumbPrint, CandidateTP, Connection, MachineType, SSLPSSession, GPODefined, Compatibility, DomainMember, Role, OperatingSystem
               
        $WinRMStateInfo.FQDN            = "<empty>"
        $WinRMStateInfo.RealName        = ""
        $WinRMStateInfo.IPAddress       = "<empty>"
        $WinRMStateInfo.HTTPS           = "Disabled"
        $WinRMStateInfo.HTTP            = "Disabled"
        $WinRMStateInfo.Certificate     = "No"
        $WinRMStateInfo.CorrectCert     = "No"
        $WinRMStateInfo.ThumbPrint      = "-"
        $WinRMStateInfo.CandidateTP     = "-"
        $WinRMStateInfo.Connection      = "Unknown"
        $WinRMStateInfo.MachineType     = "Unknown"
        $WinRMStateInfo.SSLPSSession    = "NotTested"
        $WinRMStateInfo.GPODefined      = "No"
        $WinRMStateInfo.Compatibility   = "No"
        $WinRMStateInfo.DomainMember    = "-"
        $WinRMStateInfo.Role            = "-"
        $WinRMStateInfo.OperatingSystem = "-"               
 
        if($Summary) { $ShowMessage = $False } else { $ShowMessage = $True }
   
        if([string]::IsNullOrEmpty($Computer)) {
                    WriteTo-Screen -Message "No ComputerName given." -ShowOnScreen $ShowMessage
                    Continue
        }
        WriteTo-Screen -Message "Gathering Computer data: $Computer" -ShowOnScreen $ShowMessage
        if(IsValidIPv4Address -ip $Computer) {
            try {
                $HostInfo = [system.net.dns]::GetHostByAddress($Computer)
            }
            catch {
                WriteTo-Screen -Message "Given ComputerName ($Computer) is an IPAddress, but cannot be resolved" -ShowOnScreen $ShowMessage
                Continue
            }
        } else {
            try {
                $HostInfo = [system.net.dns]::GetHostByName($Computer)
            }
            catch {
                WriteTo-Screen -Message "Cannot find a computer with this name." -ShowOnScreen $ShowMessage
                WriteTo-Screen -Message "try again, but this time with something that does exist." -ShowOnScreen $ShowMessage
                Continue
            }
   
        }
   
        $Hostname = ($HostInfo.Hostname -split "\.")[0]
        $FQDNHost = $HostInfo.Hostname
        $IPAddress = $HostInfo.AddressList.Ipaddresstostring
   
        $WinRMStateInfo.FQDN = $FQDNHost
        $WinRMStateInfo.IPAddress = $IPAddress
   
        WriteTo-Screen -Message "`nGeneral data:" -ShowOnScreen $ShowMessage
        WriteTo-Screen -Message "  Hostname  : $Hostname" -ShowOnScreen $ShowMessage
        WriteTo-Screen -Message "  Host FQDN : $FQDNHost" -ShowOnScreen $ShowMessage
        WriteTo-Screen -Message "  IPAddress : $IPAddress" -ShowOnScreen $ShowMessage
        WriteTo-Screen -Message "`nCheck if the computer is online" -ShowOnScreen $ShowMessage
               
        try {
            if(Test-PortConnection $FQDNHost -Port 135) {
                WriteTo-Screen -Message "  $FQDNHost is online (Port 135)" -ShowOnScreen $ShowMessage
                if(Test-PortConnection -Address $FQDNHost -Port 5986) {
                    WriteTo-Screen -Message "  $FQDNHost has port 5986 enabled" -ShowOnScreen $ShowMessage
                }

        } else {
            Throw
        }
   
        }
        catch {
            WriteTo-Screen -Message "  $FQDNHost is offline (according to the Port Test)" -ShowOnScreen $ShowMessage
            WriteTo-Screen -Message "  ICMP Control.." -ShowOnScreen $ShowMessage
   
            if (Test-Connection -ComputerName $FQDNHost -Quiet -Count 1) {
                WriteTo-Screen -Message "  $FQDNHost is online (ICMP)" -ShowOnScreen $ShowMessage
                if(Test-PortConnection -Address $FQDNHost -Port 22) {
                    WriteTo-Screen -Message "  $FQDNHost is probably a Linux computer (Port 22 is active)" -ShowOnScreen $ShowMessage
                    Clean-CimSession -CimSession $CimSession
                    Continue
                }
            } else         {
                WriteTo-Screen -Message "  $FQDNHost is offline (ICMP / Port test)" -ShowOnScreen $ShowMessage
                Clean-CimSession -CimSession $CimSession
                Continue
            }
        }
   
        WriteTo-Screen -Message "`nVerifying that WinRM is running on the remote computer" -ShowOnScreen $ShowMessage
        Try {
            # Eerst met DCOM (Meestal actief op PC), daarna met WSMAN
            $CimSession = New-CimSessionDown -ComputerName $FQDNHost -ErrorAction Stop
            Write-Verbose "A CIM Session is created with $FQDNHost using the $($CimSession.Protocol) protocol"
            $ServiceInfo = Get-CimInstance -ClassName Win32_Service -CimSession $CimSession -Filter 'Name="WinRM"'
        $WinRMStateInfo.Connection = $($CimSession.Protocol)
        }
        catch {
            WriteTo-Screen -Message "Connection via WSMAN and DCOM failed, probably a firewall problem." -ShowOnScreen $ShowMessage
            Clean-CimSession -CimSession $CimSession
            Continue
        }
        if ($ServiceInfo.count -eq 0) {
            WriteTo-Screen -Message "  Looks like WinRM is not installed." -ShowOnScreen $ShowMessage
            Clean-CimSession -CimSession $CimSession
            Continue
        }
   
        if(($ServiceInfo.Status -eq 'OK') -and ($ServiceInfo.State -eq 'Running')) {
            WriteTo-Screen -Message "  WinRM is installed and running" -ShowOnScreen $ShowMessage
        } else {
            WriteTo-Screen -Message "  WinRM is installed but has a problem`nSee information below:`n`n" -ShowOnScreen $ShowMessage
            $ServiceInfo
            Clean-CimSession -CimSession $CimSession
            Continue
        }
    
        $ComputerInformation = (Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession)
                                $OSInformation = (Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $CimSession)
       
                                $VirtualMachine  = $ComputerInformation.Model -Match 'vmware|virtual'
        $isDomainMember  = $ComputerInformation.PartOfDomain
        $DomainRole      = Get-DomainRole -DomainRoleNumber $($ComputerInformation.DomainRole)
        $CIMName         = $ComputerInformation.Name
        $CIMDomain       = $ComputerInformation.Domain
                                $OperatingSystem = $OSInformation.Caption
               
                                $WinRMStateInfo.RealName = $CIMName+'.'+$CIMDomain
        $WinRMStateInfo.DomainMember = $isDomainMember
        $WinRMStateInfo.Role = $DomainRole
                                $WinRMStateInfo.OperatingSystem = $OperatingSystem
 
  
        if($VirtualMachine) { $MachineType = "Virtual" } else { $MachineType= "Physical" }
        $WinRMStateInfo.MachineType = $MachineType
        WriteTo-Screen -Message "`nMachine data:  " -ShowOnScreen $ShowMessage
        WriteTo-Screen -Message "  MachineType : $MachineType" -ShowOnScreen $ShowMessage
        WriteTo-Screen -Message "  RealName    : $($WinRMStateInfo.RealName)" -ShowOnScreen $ShowMessage
   
        WriteTo-Screen -Message "`nGetting WinRM Listener Information (Registry)" -ShowOnScreen $ShowMessage
        $ListenerItems = Get-CimEnumRegKey -Hive HKLM -Key 'SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener' -CimSession $CimSession
        $NrOfListeners = $ListenerItems.sNames.Count
   
        if($NrOfListeners -gt 0) {
            WriteTo-Screen -Message "  Number of Listeners defined : $NrOfListeners" -ShowOnScreen $ShowMessage
        } else {
            WriteTo-Screen -Message "  No Listeners defined" -ShowOnScreen $ShowMessage
            Clean-CimSession -CimSession $CimSession
            Continue
        }
   
        $HTTPEnabled = $false
        $HTTPSEnabled = $false
   
        if($ListenerItems.sNames -match "\bHTTP\b") {
            WriteTo-Screen -Message "  - HTTP Enabled" -ShowOnScreen $ShowMessage
            $HTTPEnabled = $true
            $WinRMStateInfo.HTTP = "Enabled"
        }
        else {
            # poging 2 voor als HTTP niet is gevonden in de Registry (is NIET okay!)
            $ProgressPreference = 'SilentlyContinue'
            if(Test-PortConnection -Address $FQDNHost -Port 5985) {
                WriteTo-Screen -Message "  - HTTP Enabled (missing in Registry)" -ShowOnScreen $ShowMessage
               $HTTPEnabled = $true
                $WinRMStateInfo.HTTP = "Enabled"
            }
   
        }
        if($ListenerItems.sNames -match "\bHTTPS\b") {
            WriteTo-Screen -Message "  - HTTPS Enabled" -ShowOnScreen $ShowMessage
            $HTTPSEnabled = $true
            $WinRMStateInfo.HTTPS = "Enabled"
        }
   
        if($HTTPEnabled) {
                write-Verbose "HTTP Enabled - retrieving listener information via Get-WSManInstance"
                try {
                    $ListenerInfo = Get-WSManInstance -ComputerName $FQDNHost -ResourceURI winrm/config/listener -Enumerate -ErrorAction stop
                }
                catch {
                    WriteTo-Screen -Message "  Get-WSManInstance Error" -ShowOnScreen $ShowMessage
                }
            }
   
            if(($HTTPSEnabled -eq $true) -and ($HTTPEnabled -eq $false)) { # HTTP Not enabled
                write-Verbose "HTTPS Enabled - retrieving listener information via Get-WSManInstance -UseSSL"
                try {
                    $ListenerInfo = Get-WSManInstance -ComputerName $FQDNHost -ResourceURI winrm/config/listener -Enumerate -UseSSL -ErrorAction Stop
                }
                catch {
                    WriteTo-Screen -Message "  It is not possible to request the Listener information." -ShowOnScreen $ShowMessage
                    WriteTo-Screen -Message "  There is probably no certificate associated with the HTTPS Listener" -ShowOnScreen $ShowMessage
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
            WriteTo-Screen -Message "Listener Information of $FQDNHost`n" -ShowOnScreen $ShowMessage
            $ListenerInfo | Select-Object Transport, Port, Enabled, CertificateThumbprint, Address, ListeningOn, Hostname | Format-Table
        }
   
        WriteTo-Screen -Message "`nReading remote certificates" -ShowOnScreen $ShowMessage
   
        # Ophalen lijst met certificaten van remote computer
        if($HTTPEnabled) {
            try {
                $certificates = Invoke-Command -ComputerName $FQDNhost -ScriptBlock { Get-ChildItem Cert:\LocalMachine\My } -ErrorAction Stop
            }
            catch {
                WriteTo-Screen -Message "  Unable to execute Invoke-Command over HTTP" -ShowOnScreen $ShowMessage
            }
        } elseif($HTTPsEnabled) {
            try {
                $certificates = Invoke-Command -ComputerName $FQDNhost -ScriptBlock { Get-ChildItem Cert:\LocalMachine\My } -UseSSL -ErrorAction Stop
            }
            catch {
                WriteTo-Screen -Message "  Unable to execute Invoke-Command over HTTPS" -ShowOnScreen $ShowMessage
            }
        }
   
        if($ShowAllCertificates) {
            WriteTo-Screen -Message "" -ShowOnScreen $ShowMessage
            $certificates | Select-Object ThumbPrint, NotBefore, NotAfter, Subject, EnhancedKeyUsageList
            WriteTo-Screen -Message "" -ShowOnScreen $ShowMessage
        }
       
        if($HTTPSEnabled) {
            if($WinRMStateInfo.GPODefined -eq 'Yes') {
                $ThumbPrint = ($ListenerInfo | Where { $_.transport -eq 'HTTPS'}).CertificateThumbprint -replace ' ' | Select-Object -First 1
            } else {
                $ThumbPrint = ($ListenerInfo | Where { $_.transport -eq 'HTTPS'}).CertificateThumbprint -replace ' '
            }
 
            if([string]::IsNullOrEmpty($ThumbPrint)) {
                WriteTo-Screen -Message "  HTTPS listener is enabled, but has no certificate." -ShowOnScreen $ShowMessage
                $WinRMStateInfo.Certificate = "No"
            }
            else {
                WriteTo-Screen -Message "  HTTPS listener certificate ThumbPrint : $ThumbPrint" -ShowOnScreen $ShowMessage
                $WinRMStateInfo.Certificate = "Yes"
                $WinRMStateInfo.ThumbPrint = $Thumbprint
                if($certificates.Thumbprint -match $Thumbprint) {
                    WriteTo-Screen -Message "  The HTTPS listener has a matching certificate associated with it" -ShowOnScreen $ShowMessage
                    $WinRMStateInfo.CorrectCert = "Yes"
                } else {
                    $WinRMStateInfo.Certificate = "Yes"
                    $WinRMStateInfo.CorrectCert = "No"
                    WriteTo-Screen -Message "  The HTTPS listener ThumbPrint is not valid, no corresponding certificate present" -ShowOnScreen $ShowMessage
                    $CertToUse = Get-CertificateToUse -Certificates $certificates -FQDN $FQDNhost
                    if(@($CertToUse).count -ne 1) {
                        $WinRMStateInfo.Certificate = "No"
                        $WinRMStateInfo.CorrectCert = "No"
                        WriteTo-Screen -Message "  No suitable certificates found for the HTTPS listener."  -ShowOnScreen $ShowMessage
                    } else {
                        $WinRMStateInfo.CandidateTP = $CertToUse.ThumbPrint
                        WriteTo-Screen -Message "`nCertificate that can be linked to the HTTPS listener" -ShowOnScreen $ShowMessage
                        if($ShowMessage) {
                            $certtouse | Select-Object Subject, ThumbPrint, NotBefore, NotAfter
                        }
                    }
                }
   
                Write-Verbose "Finding HTTPS certificate in CertStore"
                $HTTPSCert = $certificates | where { $_.Thumbprint -match $ThumbPrint } # Zoek naar certificaat in de CertStore
                if($HTTPSCert.count -gt 0) { # dan is er dus een ThumbPrint gekoppeld.
                    if($HTTPSCert.EnhancedKeyUsageList.objectID -match  '1.3.6.1.5.5.7.3.1') { # ServerAuthentication OID
                        WriteTo-Screen -Message "  HTTPS uses a 'Server Authentication' certificate" -ShowOnScreen $ShowMessage
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
                WriteTo-Screen -Message "  There is no certificate to show." -ShowOnScreen $ShowMessage
            }
        }
       
        if($TestPSSessionSSL) {
            if(Test-SSLPSSessionConnection -FQDNHostname $FQDNHost) {
                $WinRMStateInfo.SSLPSSession = "Successful"
            } else {
                $WinRMStateInfo.SSLPSSession = "Unavailable"
            }
        }
                               
                                if($EnterSSLSession) {
                                                if(Test-SSLPSSessionConnection -FQDNHostname $FQDNHost) {
                                                                Try {
                                                                                $NewSession = New-PSSession -ComputerName $FQDNHost -UseSSL -ErrorAction Stop
                                                                                Enter-PSSession -Session $NewSession
                                                                                #Remove-PSSession -Id $NewSession.Id
                                                                }
                                                                Catch {
                                                                                WriteTo-Screen -Message "No Session possible!" -ShowOnScreen $ShowMessage
                                                                                LeaveScript -CimSession $CimSession
                                                                }
                                                }
                                }
                                   
        WriteTo-Screen -Message "`nPSSession Test with -UseSSL" -ShowOnScreen $ShowMessage
        WriteTo-Screen -Message "  PSSession Test is : $($WinRMStateInfo.SSLPSSession)" -ShowOnScreen $ShowMessage
               
        WriteTo-Screen -Message "" -ShowOnScreen $ShowMessage
               
        if($Summary) {
            $WinRMStateInfo
        }
             
    }
}
end {
                LeaveScript -CimSession $CimSession
}
 
