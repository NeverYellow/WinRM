[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias("Name")]
    [string[]]$ComputerName,
    [switch]$Summary
)
 

begin {

    write-verbose "$computername"
    $ProfileInfoList = @()
    $NLAKey1 = 'SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\NegativeCachePeriod'
    $NLAKey1a = 'SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\SignSecureChannel'
    
    $NLAKey2 = 'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\MaxNegativeCacheTtl'
    $NLAKey3 = 'SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\AlwaysExpectDomainController'

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
    function Get-CimEnumRegValues {
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
    
        $Result = Invoke-CimMethod -ClassName StdRegProv -MethodName EnumValues -Arguments $argList -CimSession $CimSession
    
        return($Result)
    
    }
    
    Function Test-PortConnection {
        Param (
        [Parameter(Mandatory=$true)]
        [String]$Address,
        [parameter(Mandatory=$true)]
        [Int]$Port,
        [Int]$Timeout=100
        )
    
        [System.Net.Sockets.TcpClient]::new().ConnectAsync($Address,$Port).Wait($Timeout)
    
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
    
    Function Find-LDAPObject {
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
    
    function IsValidIPv4Address ($ip) {
        return ($ip -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" -and [bool]($ip -as [ipaddress]))
    }
    
    function WriteTo-Screen($Message,$ShowOnScreen){
                    if($ShowOnScreen) { Write-Output "$Message" }
    }
    
    function Get-CertificateToUse($Certificates, $FQDN){
                    $ServerCerts = $certificates | where { $_.EnhancedKeyUsageList.objectId -match '1.3.6.1.5.5.7.3.1' }
                    $DNSServerCerts  = $ServerCerts | where { ($_.Subject -replace 'CN=')  -eq $FQDN }
                    $ValidCerts = $DNSServerCerts | where { $_.NotAfter -gt (Get-Date)}
                    $CertToUse = ($validcerts | Sort-Object -Unique -Culture 'nl-NL' -Descending -Property NotBefore) | Select-Object -First 1
                    return($CertToUse)
                
    }
    
    function RetrieveDomainFromDN($Distinguishedname) {

        $DomainName = (ForEach-Object{ $Distinguishedname.Split(",") | where { $_.substring(0,2) -eq "DC" } }) -join "." -replace "DC=",""
        return($DomainName)
    }
    
    function LeaveScript($CimSession) {
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
}
process {
    foreach($Computer in $ComputerName) {

        # definieer record om wat info in te verzamelen.
        
        $Record = "" | Select-Object ComputerName, ActiveProfile
        $record.ComputerName = ''
        $record.ActiveProfile = ''
        
        if($Summary) { $ShowMessage = $False } else { $ShowMessage = $True }

        if([string]::IsNullOrEmpty($Computer)) {
            WriteTo-Screen -Message "Geen ComputerName opgegeven." -ShowOnScreen $ShowMessage
            LeaveScript -CimSession $CimSession
        }
        WriteTo-Screen -Message "Opvragen computer gegevens : $ComputerName" -ShowOnScreen $ShowMessage
        if(IsValidIPv4Address -ip $Computer) {
            try {
                $HostInfo = [system.net.dns]::GetHostByAddress($Computer)
            }
            catch {
                WriteTo-Screen -Message "Opgegeven ComputerName ($ComputerName) is een IP adres, maar kan niet resolved worden" -ShowOnScreen $ShowMessage
                Continue
                #LeaveScript -CimSession $CimSession
            }
            } else {
            try {
                $HostInfo = [system.net.dns]::GetHostByName($Computer)
            }
            catch {
                WriteTo-Screen -Message "Kan geen computer met deze naam vinden." -ShowOnScreen $ShowMessage
                WriteTo-Screen -Message "probeer het nog eens, maar nu met iets wat wel bestaat." -ShowOnScreen $ShowMessage
                Continue
                #LeaveScript -CimSession $CimSession
            }
        }

        $Hostname = ($HostInfo.Hostname -split "\.")[0]
        $FQDNHost = $HostInfo.Hostname
        $IPAddress = $HostInfo.AddressList.Ipaddresstostring

        WriteTo-Screen -Message "`nAlgemene gegevens:" -ShowOnScreen $ShowMessage
        WriteTo-Screen -Message "  Hostname  : $Hostname" -ShowOnScreen $ShowMessage
        WriteTo-Screen -Message "  Host FQDN : $FQDNHost" -ShowOnScreen $ShowMessage
        WriteTo-Screen -Message "  IPAddress : $IPAddress" -ShowOnScreen $ShowMessage
        WriteTo-Screen -Message "`nControleren of de computer online is" -ShowOnScreen $ShowMessage
        
        try {
            if(Test-PortConnection $FQDNHost -Port 135) {
                WriteTo-Screen -Message "  $FQDNHost is online (Port 135)" -ShowOnScreen $ShowMessage
            } else {
                Throw
            }
        }
        catch {
            WriteTo-Screen -Message "  $FQDNHost is offline (volgens Port Test)" -ShowOnScreen $ShowMessage
            WriteTo-Screen -Message "  Controle dmv ICMP.." -ShowOnScreen $ShowMessage

            if (Test-Connection -ComputerName $FQDNHost -Quiet -Count 1) {
                WriteTo-Screen -Message "  $FQDNHost is online (ICMP)" -ShowOnScreen $ShowMessage
                if(Test-PortConnection -Address $FQDNHost -Port 22) {
                    WriteTo-Screen -Message "  $FQDNHost is waarschijnlijk een Linux computer (Port 22 is actief)" -ShowOnScreen $ShowMessage
                    Continue
                    #LeaveScript -CimSession $CimSession
                }
            } else         {
                WriteTo-Screen -Message "  $FQDNHost is offline (ICMP / Port test)" -ShowOnScreen $ShowMessage
                Continue
                #LeaveScript -CimSession $CimSession
            }
        }

        Try {
            # Eerst met DCOM (Meestal actief op PC), daarna met WSMAN
            $CimSession = New-CimSessionDown -ComputerName $FQDNHost -ErrorAction Stop
            Write-Verbose "Een CIM Sessie is gemaakt met $FQDNHost using $($CimSession.Protocol) protocol"
            $ServiceInfo = Get-CimInstance -ClassName Win32_Service -CimSession $CimSession -Filter 'Name="WinRM"'

        }
        catch {
            WriteTo-Screen -Message "Connectie via WSMAN en DCOM niet gelukt, waarschijnlijk een firewall probleem." -ShowOnScreen $ShowMessage
            Continue
            #LeaveScript -CimSession $CimSession
        }                                             
        
        
        if( (Get-CimEnumRegKey -Hive HKLM -Key $NLAKey1 -CimSession $cimsession).ReturnValue -eq 2) {
            WriteTo-Screen -Message "  $NLAKey1 bestaat niet" -ShowOnScreen $ShowMessage
        }
        if( (Get-CimEnumRegKey -Hive HKLM -Key $NLAKey1a -CimSession $cimsession).ReturnValue -eq 2) {
            WriteTo-Screen -Message "  $NLAKey1a bestaat niet" -ShowOnScreen $ShowMessage
        }
        
        if( (Get-CimEnumRegKey -Hive HKLM -Key $NLAKey2 -CimSession $cimsession).ReturnValue -eq 2) {
            WriteTo-Screen -Message "  $NLAKey2 bestaat niet" -ShowOnScreen $ShowMessage
        }

        if( (Get-CimEnumRegKey -Hive HKLM -Key $NLAKey3 -CimSession $cimsession).ReturnValue -eq 2) {
            WriteTo-Screen -Message "  $NLAKey3 bestaat niet" -ShowOnScreen $ShowMessage
        }
        
        
        WriteTo-Screen -Message "`n--------------------------------------------------------------------------`n" -ShowOnScreen $ShowMessage
        $ActiveProfile =(Get-NetFirewallSetting -PolicyStore ActiveStore -CimSession $cimsession).activeprofile
        $Record.ComputerName = $FQDNHost
        $record.ActiveProfile = $ActiveProfile
        $profileInfoList += $record
    }
}
end {
                return ($profileInfoList)
}
               
 

 
