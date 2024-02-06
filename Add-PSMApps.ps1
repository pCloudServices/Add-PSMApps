[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("MicrosoftEdgeX86", "MicrosoftEdgeX64", "GoogleChromeX86", "GoogleChromeX64", "SqlMgmtStudio18", "SqlMgmtStudio19", "GenericMMC", "TOTPToken", "ADUC", "DNS", "DHCP", "ADDT", "ADSS", "GPMC")]
    [string[]]
    $Application,
    [Parameter(Mandatory = $false)]
    [ValidateSet("Default", "OnByDefault", "OffByDefault")]
    [string]
    $HTML5 = "Default",
    [Parameter(Mandatory = $false)]
    [string]
    $MSCPath,
    [Parameter(Mandatory = $false)]
    [string]
    $ComponentName,
    [Parameter(Mandatory = $false)]
    [string]
    $ComponentDisplayName,
    [Parameter(Mandatory = $false)]
    [switch]
    $SupportGPMC,
    [Parameter(Mandatory = $false)]
    [string]
    $PortalUrl
)

# Version: 1.0.2

Function Add-PSMConfigureAppLockerSection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $SectionName,
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlDocument]
        [REF]$XmlDoc,
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement[]]
        $AppLockerEntries,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Application", "Libraries")]
        [string]
        $SectionType = "Application"
    )
    # Prepare the comments that will begin and end the section
    Write-LogMessage -type Verbose -MSG "Adding $SectionName section to AppLocker" 
    $XmlEntries = @(
        (New-XmlComment -Xml $XmlDoc -Comment " $SectionName section "),
        (New-XmlComment -Xml $XmlDoc -Comment " End of $SectionName section ")
    )
        
    # Identify the Allowed DLLs comment. If adding an application, the new section will be added just before that comment
    $AllowedDllsComment = $XmlDoc.PSMAppLockerConfiguration.AllowedApplications.SelectSingleNode("/PSMAppLockerConfiguration/AllowedApplications/comment()[. = ' Allowed DLLs ']")
    # for each new comment
    $XmlEntries | ForEach-Object {
        $XmlEntry = $_
        # check if it already exists
        $ExistingEntries = $XmlDoc.PSMAppLockerConfiguration.AllowedApplications.SelectSingleNode("/PSMAppLockerConfiguration/AllowedApplications/comment()[. = '$($XmlEntry.Value)']")
        If (!($ExistingEntries)) {
            If ($SectionType -eq "Application") {
                # And insert the new entry just above the Allowed DLLs comment
                $null = $XmlDoc.PSMAppLockerConfiguration.AllowedApplications.InsertBefore($XmlEntry, $AllowedDllsComment)
            }
            else {
                # it's a Libraries section, so create it at the very end of the AllowedApplications element
                $null = $xml.PSMAppLockerConfiguration.AllowedApplications.AppendChild($XmlEntry)
        
            }
        }
        else {
            Write-LogMessage -type Verbose -MSG "Entry already added to AppLocker configuration."
        }
    }

    # for each new entry
    $AppLockerEntries | ForEach-Object {
        $AppLockerEntry = $_
            
        # check if it already exists
        $ExistingEntries = Get-PSMApplicationsByPath -Xml $XmlDoc -AppLockerEntry $AppLockerEntry
        If (!($ExistingEntries)) {
            # Find the comment we added above
            $comment = $XmlDoc.PSMAppLockerConfiguration.AllowedApplications.SelectSingleNode("/PSMAppLockerConfiguration/AllowedApplications/comment()[. = ' $SectionName section ']")
            # And insert the new entry just below it
            $null = $XmlDoc.PSMAppLockerConfiguration.AllowedApplications.InsertAfter($AppLockerEntry, $comment)
        }
        else {
            Write-LogMessage -type Verbose -MSG "Entry already added to AppLocker configuration."
        }
    }
}

Function Import-PSMConnectionComponent {
    <#
    .SYNOPSIS
    Import a connection component
    .DESCRIPTION
    Import a connection component
    .EXAMPLE
    Import-PSMConnectionComponent
    .PARAMETER Input_File
    Zip file to import
    .PARAMETER pvwaAddress
    PVWA Address
    .PARAMETER pvwaToken
    PVWA Address
    #>

    param($ComponentName, $Input_File, $pvwaAddress, $pvwaToken)
    If ($HTML5 -ne "Default") {
        Write-LogMessage -type Verbose -MSG "Modifying $Input_File to set AllowSelectHTML5 to $HTML5..."
        Set-HTML5Parameter -ComponentZipFile $Input_File -HTML5 $HTML5
    }
    Write-LogMessage -type Verbose -MSG "Importing $Input_File..."
    $Input_File_Bytes = ([IO.File]::ReadAllBytes($Input_File))
    $Input_File_Base64 = [Convert]::ToBase64String($Input_File_Bytes)

    $restBody = @{ ImportFile = $Input_File_Base64 } | ConvertTo-Json -Depth 3 -Compress
    $URL_Import = $pvwaAddress + "/PasswordVault/api/ConnectionComponents/Import"

    $s_pvwaLogonHeader = @{
        Authorization = $pvwaToken
    }
    Try {
        $null = Invoke-RestMethod -Uri $URL_Import -Headers $s_pvwaLogonHeader -Method Post -Body $restBody -ContentType "application/json" -ErrorAction SilentlyContinue
    }
    Catch {
        If ($_.Exception.Response.StatusCode.value__ -eq 409) {
            Write-LogMessage -type Warning -MSG "Conflict error importing connection component $ComponentName. This may mean the connection component already exists. Please ensure it is configured correctly, or delete it and run this script again to recreate."
        }
        else {
            Write-LogMessage -type Error -MSG "$($Error[0])"
            Write-LogMessage -type Error -MSG $_.exception
            exit 1
        }
    }
    return $true
}

Function Test-PvwaToken {
    <#
    .SYNOPSIS
    Test a PVWA token to ensure it is valid
    .DESCRIPTION
    The function receive the service name and return the path or returns NULL if not found
    .EXAMPLE
    Test-PvwaToken -Token $Token -PvwaAddress https://subdomain.privilegecloud.cyberark.cloud
    .PARAMETER pvwaAddress
    The PVWA server address (e.g. https://subdomain.privilegecloud.cyberark.cloud)
    .PARAMETER Token
    PVWA Token
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [string]$Token        
    )
    $url = $pvwaAddress + "/PasswordVault/API/Accounts?limit=1"
    $Headers = @{
        Authorization = $Token
    }
    $testToken = Invoke-RestMethod -Method 'Get' -Uri $url -Headers $Headers -ContentType 'application/json'
    if ($testToken) {
        return $true
    }
    else {
        return $false
    }
}

Function Get-PvwaAddress {
    <#
    .SYNOPSIS
    Backs up PSMConfig ps1 scripts
    .DESCRIPTION
    Copies PSM config items to -backup.ps1
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    )
    try {
        $VaultIni = Get-Content "$psmRootInstallLocation\vault\vault.ini"
        $VaultIniAddressesLine = $VaultIni | Select-String "^Addresses"
        $null = $VaultIniAddressesLine -match "(https://[0-9a-zA-Z][\.\-0-9a-zA-Z]*)"
        $Address = $Matches[0]
        If (!($Address)) {
            Throw
        }
        return $Address
    }
    catch {
        Write-Host "Unable to detect PVWA address automatically. Please rerun script and provide it using the -PvwaAddress parameter."
        exit 1
    }
}


Function New-ConnectionToRestAPI {
    <#
    .SYNOPSIS
    Get the installation path of a service
    .DESCRIPTION
    The function receive the service name and return the path or returns NULL if not found
    .EXAMPLE
    (Get-ServiceInstallPath $<ServiceName>) -ne $NULL
    .PARAMETER pvwaAddress
    The PVWA server address (e.g. https://subdomain.privilegecloud.cyberark.cloud)
    .PARAMETER tinaCreds
    Tenant administrator/installer user credentials
    #>
    # Get PVWA and login informatioN
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        [PSCredential]$tinaCreds        
    )
    $url = $pvwaAddress + "/PasswordVault/API/auth/Cyberark/Logon"
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tinaCreds.Password)
    
    $headerPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $body = @{
        username = $tinaCreds.UserName
        password = $headerPass
    }
    $json = $body | ConvertTo-Json
    Try {
        $pvwaToken = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -ContentType 'application/json'
    }
    Catch {
        Write-Host "Failed to retrieve token. Response received:"
        Write-Host $_.Exception.Message
        exit 1
    }
    if ($pvwaToken -match "[0-9a-zA-Z]{200,256}") {
        return $pvwaToken
    }
    else {
        Write-Host "Failed to retrieve token. Response received:"
        Write-Host $_.Exception.Message
        exit 1
    }
}

Function Write-LogMessage {
    <# 
.SYNOPSIS 
	Method to log a message on screen and in a log file

.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type

.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$Early,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )
    Try {
        If ($Header) {
            "=======================================" | Out-File -Append -FilePath $LogFile 
            Write-Host "=======================================" -ForegroundColor Magenta
        }
        ElseIf ($SubHeader) { 
            "------------------------------------" | Out-File -Append -FilePath $LogFile 
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }
		
        $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
        $writeToFile = $true
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		
        # Mask Passwords
        if ($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
            $Msg = $Msg.Replace($Matches[2], "****")
        }
        # Check the message type
        switch ($type) {
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } { 
                If ($_ -eq "Info") {
                    Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) { "magenta" } Elseif ($Early) { "DarkGray" } Else { "White" })
                }
                $msgToWrite += "[INFO]`t$Msg"
            }
            "Success" { 
                Write-Host $MSG.ToString() -ForegroundColor Green
                $msgToWrite += "[SUCCESS]`t$Msg"
            }
            "Warning" {
                Write-Host $MSG.ToString() -ForegroundColor Yellow
                $msgToWrite += "[WARNING]`t$Msg"
            }
            "Error" {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite += "[ERROR]`t$Msg"
            }
            "Debug" { 
                if ($InDebug -or $InVerbose) {
                    Write-Debug $MSG
                    $msgToWrite += "[DEBUG]`t$Msg"
                }
                else { $writeToFile = $False }
            }
            "Verbose" { 
                if ($InVerbose) {
                    Write-Verbose -Msg $MSG
                    $msgToWrite += "[VERBOSE]`t$Msg"
                }
                else { $writeToFile = $False }
            }
        }

        If ($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LogFile }
        If ($Footer) { 
            "=======================================" | Out-File -Append -FilePath $LogFile 
            Write-Host "=======================================" -ForegroundColor Magenta
        }
    }
    catch {
        Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
    }
}

function ReadFromRegistry([string]$key, [string]$name) {
    Try {
        If (! (Test-Path $key)) {
            return $null
        }
        $rc = (Get-ItemProperty -path $key -name $name -ErrorAction SilentlyContinue).$name 
        return $rc
    }
    Catch {
        Write-Host "Failed to read registry value of parameter name: $name in key: $key" -ForegroundColor red
        return $false > $null
    }
}   

function Get-PSMDirectory() {
    Try {
        $key = "HKLM:\SOFTWARE\Wow6432Node\CyberArk\CyberArk Privileged Session Manager\"
        $PSM_INSTALL_DIREC = ReadFromRegistry $key "HomeDirectory"
        if (-not $PSM_INSTALL_DIREC) {
            return $false > $null 
        }
    }
    Catch {
        return $false > $null
    }
    return $PSM_INSTALL_DIREC
}

function New-PSMApplicationElement {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlDocument]$Xml,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Path", "Publisher", "Hash")]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$FileType,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Libraries", "Application")]
        [string]$EntryType,
        [Parameter(Mandatory = $false)]
        [string]$SessionType = $null
    )
    
    $Element = $Xml.CreateElement($EntryType)
    $Element.SetAttribute("Name", $Name)
    $Element.SetAttribute("Type", $FileType)
    $Element.SetAttribute("Path", $Path)
    $Element.SetAttribute("Method", $Method)
    If ($SessionType) {
        $Element.SetAttribute("SessionType", $SessionType) 
    }
    Return $Element
}

function New-XmlComment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlDocument]$Xml,
        [Parameter(Mandatory = $true)]
        [string]$Comment
    )
    
    $Element = $Xml.CreateComment($Comment)
    Return $Element
}

function Install-Chromium {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DownloadUrl,
        [Parameter(Mandatory = $true)]
        [string]$OutFile,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Google Chrome", "Microsoft Edge")]
        [string]$Type
    )
    
    Write-LogMessage -type Verbose -MSG "Downloading $Type"
    $ProgressPreference = "SilentlyContinue" # https://github.com/PowerShell/PowerShell/issues/13414
    Invoke-WebRequest $DownloadUrl -OutFile $OutFile
    $ProgressPreference = "Continue"
    Write-LogMessage -type Verbose -MSG "Installing $Type"
    $ChromiumInstallResult = Start-Process -Wait msiexec.exe -ArgumentList "/qb!", "/i", $OutFile -PassThru 
    If ($ChromiumInstallResult.ExitCode -ne 0) {
        Write-LogMessage -type Error -MSG "$Type installation failed. Please resolve the issue or install $Type manually and try again."
        Write-LogMessage -type Error -MSG "The $Type installation MSI is located at $OutFile"
        exit 1
    }

}

function Get-PSMApplicationsByPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlDocument[]]$Xml,
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$AppLockerEntry
    )
    return ($xml.PSMAppLockerConfiguration.AllowedApplications.$($AppLockerEntry.LocalName)) | Where-Object Path -eq $AppLockerEntry.Path
}

Function Invoke-PSMHardening {
    <#
    .SYNOPSIS
    Runs the PSMHardening script
    .DESCRIPTION
    Runs the PSMHardening script
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    )
    Write-Verbose "Starting PSM Hardening"
    $hardeningScriptRoot = "$psmRootInstallLocation\Hardening"
    $CurrentLocation = Get-Location
    Set-Location $hardeningScriptRoot
    & "$hardeningScriptRoot\PSMHardening.ps1"
    Set-Location $CurrentLocation
}

Function Invoke-PSMConfigureAppLocker {
    <#
    .SYNOPSIS
    Runs the AppLocker PowerShell script
    .DESCRIPTION
    Runs the AppLocker PowerShell script
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    )
    Write-Verbose "Starting PSMConfigureAppLocker"
    $hardeningScriptRoot = "$psmRootInstallLocation\Hardening"
    $CurrentLocation = Get-Location
    Set-Location $hardeningScriptRoot
    & "$hardeningScriptRoot\PSMConfigureAppLocker.ps1"
    Set-Location $CurrentLocation
}

Function Enable-PSMWebAppSupport {
    <#
    .SYNOPSIS
    Updates PSM scripts and basic_psm.ini to have domain user(s) in them rather than local user(s).
    .DESCRIPTION
    Updates PSM scripts and basic_psm.ini to have domain user(s) in them rather than local user(s).
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation,
        [Parameter(Mandatory = $true)]
        $BackupFile
    )
    try {
        Copy-Item -Path "$psmRootInstallLocation\Hardening\PSMHardening.ps1" -Destination $BackupFile -Force
        #PSMHardening
        #-------------------------
        $psmHardeningContent = Get-Content -Path $psmRootInstallLocation\Hardening\PSMHardening.ps1

        $newPsmHardeningContent = $psmHardeningContent -replace '^(\$SUPPORT_WEB_APPLICATIONS\s*=) .*', '$1 $true'
        $newPsmHardeningContent | Set-Content -Path "$psmRootInstallLocation\Hardening\PSMHardening.ps1"
    }
    catch {
        Write-LogMessage -Type Error -MSG "Failed to enable web application support in PSMHardening.ps1 script, please verify the files manually."
        Write-LogMessage -Type Error -MSG $_
        Exit 1
    }
}

Function Set-GenericMmcConnectionComponent {
    Param(
        [Parameter(Mandatory = $true)]
        [string]
        $ComponentZipFile,
        [Parameter(Mandatory = $true)]
        [string]
        $TargetComponentZipFile,
        [Parameter(Mandatory = $true)]
        [string]
        $MSCPath,
        [Parameter(Mandatory = $true)]
        [string]
        $ComponentName,
        [Parameter(Mandatory = $true)]
        [string]
        $ComponentDisplayName,
        [Parameter(Mandatory = $true)]
        [string]
        $PSMInstallationFolder,
        [Parameter(Mandatory = $true)]
        [switch]
        $SupportGPMC
    )

    Try {
        # Extract ZIP to temp folder logic
        $TempGuid = [guid]::NewGuid().ToString()
        $tempFolder = $env:temp + "\CC-$ComponentName-$TempGuid"
    
        #Remove folder if it exists already before unzipping 
        if (Test-Path $tempFolder) {
            Remove-Item -Recurse $tempFolder -Force
        }	
        #Unzip to temp folder
        $null = Expand-Archive $ComponentZipFile -DestinationPath $tempFolder

        # Find all XML files in the ConnectionComponent ZIP
        $fileEntries = Get-ChildItem -Path $tempFolder -Filter '*.xml'

        #Read XML file
        $xmlContent = New-Object System.Xml.XmlDocument
        $xmlContent.Load($fileEntries[0].FullName)
        
        # Modify CC
        If ($SupportGPMC) {
            $Element = ($xmlContent.ConnectionComponent.TargetSettings.ClientSpecific.SelectSingleNode("/ConnectionComponent/TargetSettings/ClientSpecific/Parameter[@Name='LogonFlag']"))
            $Element.SetAttribute("Value", "1")
        }
        $Element = ($xmlContent.ConnectionComponent.TargetSettings.ClientSpecific.SelectSingleNode("/ConnectionComponent/TargetSettings/ClientSpecific/Parameter[@Name='ClientInstallationPath']"))
        $Element.SetAttribute("Value", $MSCPath)
        $xmlContent.ConnectionComponent.SetAttribute("DisplayName", $ComponentDisplayName)
        $xmlContent.ConnectionComponent.SetAttribute("Id", $ComponentName)
            
        # Save modified XML
        $xmlContent.Save($fileEntries[0].FullName)
            
        # Zip the file back again.
        Compress-Archive -DestinationPath $TargetComponentZipFile -Path $tempFolder\*.xml -Force
            
        #Delete temporary Files
        Remove-Item $tempFolder -Recurse
    }
    Catch {
        Write-LogMessage -type Error -MSG $_.Exception
        exit 1
    }
}

Function Set-HTML5Parameter {
    Param(
        [Parameter(Mandatory = $true)]
        [string]
        $ComponentZipFile,
        [Parameter(Mandatory = $true)]
        [string]
        $HTML5Preference
    )

    Try {
        # Extract ZIP to temp folder logic
        $TempGuid = [guid]::NewGuid().ToString()
        $tempFolder = $env:temp + "\CC-$ComponentName-$TempGuid"
    
        #Remove folder if it exists already before unzipping 
        if (Test-Path $tempFolder) {
            Remove-Item -Recurse $tempFolder -Force
        }	
        #Unzip to temp folder
        $null = Expand-Archive $ComponentZipFile -DestinationPath $tempFolder

        # Find all XML files in the ConnectionComponent ZIP
        $fileEntries = Get-ChildItem -Path $tempFolder -Filter '*.xml'

        #Read XML file
        $xmlContent = New-Object System.Xml.XmlDocument
        $xmlContent.Load($fileEntries[0].FullName)
        
        # Modify CC

        $HTML5Element = $xmlContent.CreateElement("Parameter")
        $HTML5Element.SetAttribute("Name", "AllowSelectHTML5")
        $HTML5Element.SetAttribute("DisplayName", "In Browser")
        $HTML5Element.SetAttribute("Type", "CyberArk.TransparentConnection.BooleanUserParameter, CyberArk.PasswordVault.TransparentConnection")
        $HTML5Element.SetAttribute("Required", "Yes")
        $HTML5Element.SetAttribute("Visible", "Yes")
        If ($HTML5Preference -eq "OnByDefault") {
            $HTML5Element.SetAttribute("Value", "Yes")
        }
        else {
            $HTML5Element.SetAttribute("Value", "No")
        }
        $UserParametersElement = ($xmlContent.ConnectionComponent.TargetSettings.ClientSpecific.SelectSingleNode("/ConnectionComponent/UserParameters"))
        $null = $UserParametersElement.AppendChild($HTML5Element)
            
        # Save modified XML
        $xmlContent.Save($fileEntries[0].FullName)
            
        # Zip the file back again.
        Compress-Archive -DestinationPath $TargetComponentZipFile -Path $tempFolder\*.xml -Force
            
        #Delete temporary Files
        Remove-Item $tempFolder -Recurse
    }
    Catch {
        Write-LogMessage -type Error -MSG $_.Exception
        exit 1
    }
}

Function Test-PSMWebAppSupport {
    <#
    .SYNOPSIS
    Updates PSM scripts and basic_psm.ini to have domain user(s) in them rather than local user(s).
    .DESCRIPTION
    Updates PSM scripts and basic_psm.ini to have domain user(s) in them rather than local user(s).
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    )
    try {
        $Result = Get-Content "$psmRootInstallLocation\Hardening\PSMHardening.ps1" | Select-String '^\$SUPPORT_WEB_APPLICATIONS\s*=\s*\$true'
        If ($Result) {
            return $true
        }
        else {
            return $false
        }
    }
    catch {
        Write-LogMessage -Type Error -MSG "Failed to verify web application support in PSMHardening.ps1 script, please verify the files manually."
        Write-LogMessage -Type Error -MSG $_
        Exit 1
    }
}

# Script start

$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_FILE_PATH = "$ScriptLocation\_Add-PSMApplication.log"
$global:HTML5 = $HTML5

$CurrentDirectory = (Get-Location).Path
$PSMInstallationFolder = Get-PSMDirectory
$BackupSuffix = (Get-Date).ToString('yyyMMdd-HHmmss')

$AppLockerXmlFilePath = "$PSMInstallationFolder\Hardening\PSMConfigureAppLocker.xml"
$BackupAppLockerXmlFilePath = "$PSMInstallationFolder\Hardening\PSMConfigureAppLocker.$BackupSuffix.bkp"
$BackupHardeningXmlFilePath = "$PSMInstallationFolder\Hardening\PSMHardening.$BackupSuffix.bkp"

if ($AppLockerXmlFilePath) {
    if (-not (Test-Path -Path $AppLockerXmlFilePath)) {
        Write-LogMessage -type Error -MSG "PSMConfigureAppLocker.xml not found in PSM Hardening folder. Aborting."
        exit 1
    }
}

If ("GenericMMC" -in $Application) {
    If ($False -eq ( ($ComponentName) -and ($ComponentDisplayName) -and ($MSCPath) )
    ) {
        Write-LogMessage -type Error -MSG "ComponentName, ComponentDisplayName and MscPath are mandatory for Generic MMC components"
        exit 1
    }
}

If ("SqlMgmtStudio18" -in $Application) {
    If (!(Test-Path "C:\Program Files (x86)\Microsoft SQL Server Management Studio 18\Common7\IDE\Ssms.exe")) {
        Write-LogMessage -type Error -MSG "SQL Management Studio 18 does not appear to be installed. Please install it first."
        exit 1
    }
}

If ("SqlMgmtStudio19" -in $Application) {
    If (!(Test-Path "C:\Program Files (x86)\Microsoft SQL Server Management Studio 19\Common7\IDE\Ssms.exe")) {
        Write-LogMessage -type Error -MSG "SQL Management Studio 18 does not appear to be installed. Please install it first."
        exit 1
    }
}

$RunHardening = $false

# Load the current XML
$xml = New-Object System.Xml.XmlDocument
#$xml.PreserveWhitespace = $true
$xml.Load("$PSMInstallationFolder\Hardening\PSMConfigureAppLocker.xml")

If (!($PortalUrl)) {
    $PortalUrl = Get-PvwaAddress -psmRootInstallLocation $PSMInstallationFolder
}
$Tasks = @()

# Only prompt for admin credentials if we need to import connection components.

$ListApplicationsWithoutConnectionComponents = "GoogleChromeX86", "GoogleChromeX64", "SqlMgmtStudio18", "SqlMgmtStudio19", "MicrosoftEdgeX86", "MicrosoftEdgeX64"

switch ($Application) {
    { $PSItem -in $ListApplicationsWithoutConnectionComponents } {
        continue
    }
    Default {
        $tinaCreds = Get-Credential -Message "Please enter CyberArk credentials to import connection components or cancel to skip." 
        if ($tinaCreds) {
            Write-LogMessage -type Verbose -MSG "Logging in to CyberArk"
            $pvwaToken = New-ConnectionToRestAPI -pvwaAddress $PortalUrl -tinaCreds $tinaCreds
            if (Test-PvwaToken -Token $pvwaToken -pvwaAddress $PortalUrl) {
                Write-LogMessage -type Verbose -MSG "Successfully logged in"
                $Tasks += "Add the newly created connection components to any domain platforms."
            }
            else {
                Write-LogMessage -type Verbose -MSG "Error logging in to CyberArk"
                exit 1
            }
        }
        else {
            Write-LogMessage -type Warning -MSG "No credentials provided. Will not import connection components."
        }
        # Break out of the switch. No need to evaluate other items in $Application. If there's at least one we need to get credentials.
        break
    }
}

$ListMmcApps = "ADSS", "ADDT", "ADUC", "DHCP", "DNS", "GPMC"

# Check whether any of the requested applications are MMC-based, by checking for intersections between the $Applications array and an array of the MMC-based applications
# If any are present, we'll install the dipatcher, MSC Files, and install the required Windows Features
$MmcAppsTest = $Application | Where-Object { $ListMmcApps -contains $_ }

if ($MmcAppsTest) {
    Write-LogMessage -type Info -MSG "Installing dispatcher"
    Expand-Archive -Path "$CurrentDirectory\Supplemental\GenericMmc\Dispatcher.zip" -DestinationPath "$PSMInstallationFolder\Components\" -Force
    
    Write-LogMessage -type Info -MSG "Adding MMC and dispatcher to AppLocker configuration"
    $AppLockerEntries = @(
        (New-PSMApplicationElement -Xml $xml -EntryType Application -Name MMC -FileType Exe -Path "C:\Windows\System32\MMC.exe" -Method Hash)
    )
    Add-PSMConfigureAppLockerSection -SectionName "Microsoft Management Console (MMC)" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries
    
    $AppLockerEntries = @(
        (New-PSMApplicationElement -Xml $xml -EntryType Application -Name PSM-MMCDispatcher -FileType Exe -Path "$PSMInstallationFolder\Components\PSMMMCDispatcher.exe" -Method Hash)
    )
    Add-PSMConfigureAppLockerSection -SectionName "PSM Generic MMC Dispatcher" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries
    
    Write-LogMessage -type Info -MSG "Installing MSC Files"
    If (!(Test-Path -Path "C:\PSMApps" -PathType Container)) {
        try {
            $null = New-Item -ItemType Directory -Path "C:\PSMApps"
        }
        catch {
            Write-LogMessage -type Error -MSG "Error creating C:\PSMApps folder"
            Exit 1
        }
    }
    Expand-Archive -Path "$CurrentDirectory\Supplemental\GenericMmc\MscFiles.zip" -DestinationPath "C:\PSMApps\" -Force
    $Components = @()
    $WindowsFeatures = @()
    switch ($Application) {
        { $PSItem -in "ADSS", "ADDT", "ADUC" } {
            $WindowsFeatures += "RSAT-ADDS-Tools"
            switch ($PSItem) {
                "ADUC" {
                    $Components += @{
                        Name        = "ADUC"
                        DisplayName = "AD Users & Computers"
                        MscFile     = "ADUC.msc"
                    }
                }
                "ADDT" {
                    $Components += @{
                        Name        = "ADDT"
                        DisplayName = "AD Domains & Trusts"
                        MscFile     = "ADDT.msc"
                    }
                }
                "ADSS" {
                    $Components += @{
                        Name        = "ADSS"
                        DisplayName = "AD Sites & Services"
                        MscFile     = "ADSS.msc"
                    }
                }
            }
        }
        { $PSItem -in "DHCP" } {
            Write-Verbose "DHCP"
            $WindowsFeatures += "RSAT-DHCP"
            $Components += @{
                Name        = "DHCPMGMT"
                DisplayName = "DHCP Management"
                MscFile     = "DHCP.msc"
            }
        }
        { $PSItem -in "DNS" } {
            $WindowsFeatures += "RSAT-DNS-Server"
            $Components += @{
                Name        = "DNSMGMT"
                DisplayName = "AD DNS Management"
                MscFile     = "DNS.msc"
            }
        }
        { $PSItem -in "GPMC" } {
            $WindowsFeatures += "GPMC"
            $Components += @{
                Name        = "GPMC"
                DisplayName = "Group Policy Management"
                MscFile     = "GPMC.msc"
                GPMC        = $true
            }
            $Tasks += "Group Policy Management:"
            $Tasks += " - Note: To support Group Policy Management:"
            $Tasks += "   - The target account must have the `"Allow Log on Locally`" user right."
            $Tasks += "   - If the target account is an administrator on the CyberArk server, UAC must be disabled."
            $Tasks += "   - Please consider the risks carefully before enabling this connection component."
        }

    }
    Write-LogMessage -type Info -MSG "Installing Remote Server Administration Tools"
    try {
        $null = Install-WindowsFeature $WindowsFeatures
    }
    catch {
        Write-LogMessage -type Error -MSG "Error installing Remote Server Administration Tools. Please resolve and try again."
        exit 1
    }

    if ($tinaCreds) {
        Write-LogMessage -type Info -MSG "Importing connection components"
        $ComponentZipFile = "$CurrentDirectory\Supplemental\GenericMmc\ConnectionComponent.zip"
        foreach ($Component in $Components) {
            $TargetComponentZipFile = $env:temp + "\CC-" + $Component.Name + "-" + (Get-Date -UFormat '%Y%m%d%H%M%S') + ".zip"
            Write-LogMessage -type Verbose -MSG "Preparing connection component"
            Set-GenericMmcConnectionComponent -PSMInstallationFolder $PSMInstallationFolder `
                -ComponentZipFile $ComponentZipFile `
                -TargetComponentZipFile $TargetComponentZipFile `
                -ComponentName ("PSM-" + $Component.Name) `
                -ComponentDisplayName $Component.DisplayName `
                -MSCPath ("C:\PSMApps\" + $Component.MscFile) `
                -SupportGPMC:$Component.GPMC
            $result = Import-PSMConnectionComponent -Input_File $TargetComponentZipFile -pvwaAddress $PortalUrl -pvwaToken $pvwaToken -ComponentName $Component.Name
            if ($result) {
                Write-LogMessage -type Verbose "Successfully imported connection component"
            }
        }
    }
    else {
        Write-LogMessage -type Info -MSG "Installer user credentials not provided; skipping connection component creation"
    }
}

switch ($Application) {
    # Generic MMC connector
    "GenericMMC" {
        if ($tinaCreds) {
            $ComponentZipFile = "$CurrentDirectory\Supplemental\GenericMmc\ConnectionComponent.zip"
            $TargetComponentZipFile = $env:temp + "\CC-" + (Get-Date -UFormat '%Y%m%d%H%M%S') + ".zip"
            Set-GenericMmcConnectionComponent -PSMInstallationFolder $PSMInstallationFolder `
                -ComponentZipFile $ComponentZipFile `
                -TargetComponentZipFile $TargetComponentZipFile `
                -ComponentName $ComponentName `
                -ComponentDisplayName $ComponentDisplayName `
                -MSCPath $MSCPath `
                -SupportGPMC:$SupportGPMC
            $result = Import-PSMConnectionComponent -ComponentName $ComponentName -Input_File $TargetComponentZipFile -pvwaAddress $PortalUrl -pvwaToken $pvwaToken
            if ($result) {
                Write-LogMessage -type Verbose "Successfully imported connection component"
            }

        }
        else {
            Write-LogMessage -type Warning -MSG "No credentials provided. Will not import connection component."
        }

        Write-LogMessage -type Info -MSG "Adding MMC and ADUC dispatcher to AppLocker configuration"
        $AppLockerEntries = @(
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name MMC -FileType Exe -Path "C:\Windows\System32\MMC.exe" -Method Hash)
        )
        Add-PSMConfigureAppLockerSection -SectionName "Microsoft Management Console (MMC)" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries

        $AppLockerEntries = @(
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name PSM-MMCDispatcher -FileType Exe -Path "$PSMInstallationFolder\Components\PSMMMCDispatcher.exe" -Method Hash)
        )
        Add-PSMConfigureAppLockerSection -SectionName "PSM Generic MMC Dispatcher" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries

        Write-LogMessage -type Info -MSG "Installing Generic MMC dispatcher"
        Expand-Archive -Path "$CurrentDirectory\Supplemental\GenericMmc\Dispatcher.zip" -DestinationPath $PSMInstallationFolder\Components\ -Force
        
        $Tasks += "GenericMMC:"
        $Tasks += " - Create $MSCPath"
        $Tasks += " - Add the `"$ComponentDisplayName`" connection component to applicable domain platforms"
    }
    "TOTPToken" {
        $ZipPath = "$CurrentDirectory\PSM-TOTPToken.zip"
        If (!(Test-Path $ZipPath)) {
            Write-LogMessage -type Error -MSG "Please download PSM-TOTPToken.zip from https://cyberark-customers.force.com/mplace/s/#a352J000000GPw5QAG-a392J000002hZX8QAM and place it in $CurrentDirectory"
            exit 1
        }

        $TempGuid = [guid]::NewGuid().ToString()
        $TempDir = "$env:temp\$TempGuid"

        If (!(Test-Path -Path $TempDir -PathType Container)) {
            try {
                $null = New-Item -ItemType Directory -Path $TempDir
            }
            catch {
                Write-LogMessage -type Error -MSG "Error creating $TempDir folder"
                Exit 1
            }
        }
    
        Expand-Archive -Path $ZipPath -DestinationPath $TempDir -Force

        $TargetComponentZipFile = "$TempDir\CC-TOTPToken.zip"

        Compress-Archive -Path "$TempDir\*.xml" -DestinationPath $TargetComponentZipFile

        if ($tinaCreds) {
            $result = Import-PSMConnectionComponent -ComponentName TOTPToken -Input_File "$TargetComponentZipFile" -pvwaAddress $PortalUrl -pvwaToken $pvwaToken
            if ($result) {
                Write-LogMessage -type Verbose "Successfully imported connection component"
            }
        }
        else {
            Write-LogMessage -type Warning -MSG "No credentials provided. Will not import connection component."
        }

        Copy-Item -Path "$TempDir\TOTPToken.exe" -Destination "$PSMInstallationFolder\Components\" -Force
        $RunHardening = $true

        $AppLockerEntries = @(
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name PSM-TOTPToken -FileType Exe -Path "$PSMInstallationFolder\Components\TOTPToken.exe" -Method Hash -SessionType "*")
        )
        Add-PSMConfigureAppLockerSection -SectionName "PSM-TOTPToken" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries
        $Tasks += "TOTPToken:"
        $Tasks += "- Import a platform supporting MFADeviceKeys-*.zip"
        $Tasks += "- Associate the TOTP Token connection component with an appropriate platform"
    }
    "SqlMgmtStudio18" {
        Write-LogMessage -type Info -MSG "SqlMgmtStudio18: Modifying AppLocker configuration"
        $AppLockerEntries = @(
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name SSMS18 -FileType Exe -Path "C:\Program Files (x86)\Microsoft SQL Server Management Studio 18\Common7\IDE\Ssms.exe" -Method Publisher),
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name SSMS18-DTAShell -FileType Exe -Path "C:\Program Files (x86)\Microsoft SQL Server Management Studio 18\Common7\DTASHELL.exe" -Method Publisher),
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name SSMS18-Profiler -FileType Exe -Path "C:\Program Files (x86)\Microsoft SQL Server Management Studio 18\Common7\Profiler.exe" -Method Publisher)
        )
        Add-PSMConfigureAppLockerSection -SectionName "SQL Management Studio 18" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries
        
        $AppLockerEntries = @(
            (New-PSMApplicationElement -Xml $xml -EntryType Libraries -Name SSMS18-Debugger -FileType Dll -Path "C:\Program Files (x86)\Microsoft SQL Server Management Studio 18\Common7\Packages\Debugger\*" -Method Path)
        )
        Add-PSMConfigureAppLockerSection -SectionName "SQL Management Studio 18 Libraries" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries -SectionType Libraries
        $Tasks += "SqlMgmtStudio18:"
        $Tasks += " - Create/Configure SQL Management Studio connection components"
        $Tasks += " - - Set ClientInstallationPath in your connection component to C:\Program Files (x86)\Microsoft SQL Server Management Studio 18\Common7\IDE\Ssms.exe"
    }
    "SqlMgmtStudio19" {
        Write-LogMessage -type Info -MSG "SqlMgmtStudio19: Modifying AppLocker configuration"
        $AppLockerEntries = @(
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name SSMS19 -FileType Exe -Path "C:\Program Files (x86)\Microsoft SQL Server Management Studio 19\Common7\IDE\Ssms.exe" -Method Publisher),
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name SSMS19-DTAShell -FileType Exe -Path "C:\Program Files (x86)\Microsoft SQL Server Management Studio 19\Common7\DTASHELL.exe" -Method Publisher),
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name SSMS19-Profiler -FileType Exe -Path "C:\Program Files (x86)\Microsoft SQL Server Management Studio 19\Common7\Profiler.exe" -Method Publisher)
        )
        Add-PSMConfigureAppLockerSection -SectionName "SQL Management Studio 19" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries
        
        $AppLockerEntries = @(
            (New-PSMApplicationElement -Xml $xml -EntryType Libraries -Name SSMS19-Debugger -FileType Dll -Path "C:\Program Files (x86)\Microsoft SQL Server Management Studio 19\Common7\Packages\Debugger\*" -Method Path)
        )
        Add-PSMConfigureAppLockerSection -SectionName "SQL Management Studio 19 Libraries" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries -SectionType Libraries
        $Tasks += "SqlMgmtStudio19:"
        $Tasks += " - Create/Configure SQL Management Studio connection components"
        $Tasks += " - - Set ClientInstallationPath in your connection component to C:\Program Files (x86)\Microsoft SQL Server Management Studio 19\Common7\IDE\Ssms.exe"
        $Tasks += " - - You may need to disable `"Lock Application Window`" to support SSMS19"
    }
    # Google Chrome 32 bit
    "GoogleChromeX86" {
        If (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe") {
            Write-LogMessage -type Error -MSG "Chrome exists at `"C:\Program Files\Google\Chrome\Application\chrome.exe`""
            Write-LogMessage -type Error -MSG "which is the 64-bit installation path. Please uninstall it and run script again if you"
            Write-LogMessage -type Error -MSG "want to switch to the 32-bit version "
            exit 1
        }
        If (Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") {
            Write-LogMessage -type Info -MSG "Chrome appears to be installed already. Will not reinstall."
        }
        else {
            $DownloadUrl = "https://dl.google.com/edgedl/chrome/install/GoogleChromeStandaloneEnterprise.msi"
            $OutFile = "$env:temp\GoogleChromeStandaloneEnterprise.msi"
            Write-LogMessage -type Info -MSG "Downloading and installing Chrome"
            $null = Install-Chromium -Type "Google Chrome" -DownloadUrl $DownloadUrl -OutFile $OutFile
        }
        $WebAppSupport = Test-PSMWebAppSupport -psmRootInstallLocation $PSMInstallationFolder
        If ($WebAppSupport) {
            Write-LogMessage -type Info -MSG "Web app support already enabled. Not modifying PSMHardening.ps1"
        }
        else {
            Write-LogMessage -type Info "Enabling web app support in PSMHardening script"
            Enable-PSMWebAppSupport -psmRootInstallLocation $PSMInstallationFolder -BackupFile $BackupHardeningXmlFilePath
            $RunHardening = $true
        }

        $Path = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"

        $AppLockerEntries = @(
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name GoogleChrome -FileType Exe -Path $Path -Method Publisher)
        )
        Add-PSMConfigureAppLockerSection -SectionName "Google Chrome" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries
    }
    # Google Chrome 64 bit
    "GoogleChromeX64" {
        Write-LogMessage -type Info -MSG "Checking if Chrome 32 bit is present"
        If (Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") {
            Write-LogMessage -type Error -MSG "Chrome exists at `"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`""
            Write-LogMessage -type Error -MSG "which is the 32-bit installation path. Please uninstall it and run script again if you"
            Write-LogMessage -type Error -MSG "want to switch to the 64-bit version "
            exit 1
        }
        If (Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") {
            Write-LogMessage -type Info -MSG "Chrome appears to be installed already. Will not reinstall."
        }
        else {
            $DownloadUrl = "https://dl.google.com/edgedl/chrome/install/GoogleChromeStandaloneEnterprise64.msi"
            $OutFile = "$env:temp\GoogleChromeStandaloneEnterprise64.msi"
            Write-LogMessage -type Info -MSG "Downloading and installing Chrome"
            $null = Install-Chromium -Type "Google Chrome" -DownloadUrl $DownloadUrl -OutFile $OutFile
        }
        $WebAppSupport = Test-PSMWebAppSupport -psmRootInstallLocation $PSMInstallationFolder
        If ($WebAppSupport) {
            Write-LogMessage -type Verbose -MSG "Web app support already enabled. Not modifying PSMHardening.ps1"
        }
        else {
            Write-LogMessage -type Info "Enabling web app support in PSMHardening script"
            Enable-PSMWebAppSupport -psmRootInstallLocation $PSMInstallationFolder -BackupFile $BackupHardeningXmlFilePath
            $RunHardening = $true
        }
        $Path = "C:\Program Files\Google\Chrome\Application\chrome.exe"

        $AppLockerEntries = @(
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name GoogleChrome -FileType Exe -Path $Path -Method Publisher)
        )
        Add-PSMConfigureAppLockerSection -SectionName "Google Chrome" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries
    }

    # Microsoft Edge 64 bit
    "MicrosoftEdgeX64" {
        Write-LogMessage -type Info -MSG "Checking if Microsoft Edge 32 bit is present"
        $Packages = Get-Package | Where-Object TagId -eq "0E72E0CA-1196-3B77-9B71-9FE483875A84"
        If ($Packages) {
            Write-LogMessage -type Error -MSG "Microsoft Edge 32-bit is currently installed."
            Write-LogMessage -type Error -MSG "Please uninstall it and run script again if you want to switch to the 64-bit version "
            Write-LogMessage -type Error -MSG " or run the script with -Application MicrosoftEdgeX64 to configure the PSM server"
            exit 1
        }
        Write-LogMessage -type Info -MSG "Checking if Microsoft Edge is installed"
        If (Test-Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe") {
            Write-LogMessage -type Info -MSG "Microsoft Edge appears to be installed already. Will not reinstall."
        }
        else {
            Write-LogMessage -type Info -MSG "Downloading and installing Microsoft Edge 64 bit"
            $DownloadUrl = "http://go.microsoft.com/fwlink/?LinkID=2093437"
            $OutFile = "$env:temp\MicrosoftEdgeStandaloneEnterprise64.msi"
            Write-LogMessage -type Info -MSG "Downloading and installing Microsoft Edge"
            $null = Install-Chromium -Type "Microsoft Edge" -DownloadUrl $DownloadUrl -OutFile $OutFile
        }
        $WebAppSupport = Test-PSMWebAppSupport -psmRootInstallLocation $PSMInstallationFolder
        If ($WebAppSupport) {
            Write-LogMessage -type Verbose -MSG "Web app support already enabled. Not modifying PSMHardening.ps1"
        }
        else {
            Write-LogMessage -type Info "Enabling web app support in PSMHardening script"
            Enable-PSMWebAppSupport -psmRootInstallLocation $PSMInstallationFolder -BackupFile $BackupHardeningXmlFilePath
            $RunHardening = $true
        }
        $Path = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

        $AppLockerEntries = @(
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name MicrosoftEdge -FileType Exe -Path $Path -Method Publisher)
        )
        Add-PSMConfigureAppLockerSection -SectionName "Microsoft Edge" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries
    }

    # Microsoft Edge 32 bit
    "MicrosoftEdgeX86" {
        Write-LogMessage -type Info -MSG "Checking if Microsoft Edge 64 bit is present"
        $Packages = Get-Package | Where-Object TagId -eq "DF6DD533-D7E9-3ECF-892D-62A737C8619D"
        If ($Packages) {
            Write-LogMessage -type Error -MSG "Microsoft Edge 64-bit is currently installed."
            Write-LogMessage -type Error -MSG "Please uninstall it and run script again if you want to switch to the 64-bit version "
            Write-LogMessage -type Error -MSG " or run the script with -Application MicrosoftEdgeX86 to configure the PSM server"
            exit 1
        }
        Write-LogMessage -type Info -MSG "Checking if Microsoft Edge is installed"
        If (Test-Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe") {
            Write-LogMessage -type Info -MSG "Microsoft Edge appears to be installed already. Will not reinstall."
        }
        else {
            Write-LogMessage -type Info -MSG "Downloading and installing Microsoft Edge 32 bit"
            $DownloadUrl = "http://go.microsoft.com/fwlink/?LinkID=2093505"
            $OutFile = "$env:temp\MicrosoftEdgeStandaloneEnterprise86.msi"
            Write-LogMessage -type Info -MSG "Downloading and installing Microsoft Edge"
            $null = Install-Chromium -Type "Microsoft Edge" -DownloadUrl $DownloadUrl -OutFile $OutFile
        }
        $WebAppSupport = Test-PSMWebAppSupport -psmRootInstallLocation $PSMInstallationFolder
        If ($WebAppSupport) {
            Write-LogMessage -type Verbose -MSG "Web app support already enabled. Not modifying PSMHardening.ps1"
        }
        else {
            Write-LogMessage -type Info "Enabling web app support in PSMHardening script"
            Enable-PSMWebAppSupport -psmRootInstallLocation $PSMInstallationFolder -BackupFile $BackupHardeningXmlFilePath
            $RunHardening = $true
        }
        $Path = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    
        $AppLockerEntries = @(
                (New-PSMApplicationElement -Xml $xml -EntryType Application -Name MicrosoftEdge -FileType Exe -Path $Path -Method Publisher)
        )
        Add-PSMConfigureAppLockerSection -SectionName "Microsoft Edge" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries
    }
    
}

try { Copy-Item -Force $AppLockerXmlFilePath $BackupAppLockerXmlFilePath }
catch { 
    Write-LogMessage -type Error -MSG "Backup of current PSMConfigureAppLocker.xml failed. Aborting."
    exit 1
}
$xml.Save($AppLockerXmlFilePath)
Write-LogMessage -Type Info -MSG "Running PSM Configure AppLocker script"
Write-LogMessage -Type Info -MSG "---"
Invoke-PSMConfigureAppLocker -psmRootInstallLocation $PSMInstallationFolder
Write-LogMessage -Type Info -MSG "---"
Write-LogMessage -Type Info -MSG "End of PSM Configure AppLocker script output"
    
If ($RunHardening) {
    Write-LogMessage -Type Info -MSG "Running PSM Hardening script"
    Write-LogMessage -Type Info -MSG "---"
    Invoke-PSMHardening -psmRootInstallLocation $PSMInstallationFolder
    Write-LogMessage -Type Info -MSG "---"
    Write-LogMessage -Type Info -MSG "End of PSM Hardening script output"
}

Write-LogMessage -type Success "All tasks completed."
If ($Tasks) {
    Write-LogMessage -type Info "The following additional steps may be required:"
    foreach ($Task in $Tasks) {
        Write-LogMessage -type Info " - $Task"
    }
}
# SIG # Begin signature block
# MIIqRQYJKoZIhvcNAQcCoIIqNjCCKjICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDNsTWtFOS2zx0d
# D/Zsg8jIR5KnqInL0EXQTiUWrUPzMaCCGFcwggROMIIDNqADAgECAg0B7l8Wnf+X
# NStkZdZqMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBH
# bG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9i
# YWxTaWduIFJvb3QgQ0EwHhcNMTgwOTE5MDAwMDAwWhcNMjgwMTI4MTIwMDAwWjBM
# MSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xv
# YmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8RgJDx7KKnQRf
# JMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsTgHeMCOFJ0mpi
# Lx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmmKPZpO/bLyCiR
# 5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zdQQ4gOsC0p6Hp
# sk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZXriX7613t2Sa
# er9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaOCASIwggEeMA4GA1Ud
# DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSP8Et/qC5FJK5N
# UPpjmove4t0bvDAfBgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzA9Bggr
# BgEFBQcBAQQxMC8wLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL3Jvb3RyMTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLmdsb2JhbHNp
# Z24uY29tL3Jvb3QuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIB
# FiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG
# 9w0BAQsFAAOCAQEAI3Dpz+K+9VmulEJvxEMzqs0/OrlkF/JiBktI8UCIBheh/qvR
# XzzGM/Lzjt0fHT7MGmCZggusx/x+mocqpX0PplfurDtqhdbevUBj+K2myIiwEvz2
# Qd8PCZceOOpTn74F9D7q059QEna+CYvCC0h9Hi5R9o1T06sfQBuKju19+095VnBf
# DNOOG7OncA03K5eVq9rgEmscQM7Fx37twmJY7HftcyLCivWGQ4it6hNu/dj+Qi+5
# fV6tGO+UkMo9J6smlJl1x8vTe/fKTNOvUSGSW4R9K58VP3TLUeiegw4WbxvnRs4j
# vfnkoovSOWuqeRyRLOJhJC2OKkhwkMQexejgcDCCBaIwggSKoAMCAQICEHgDGEJF
# cIpBz28BuO60qVQwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2ln
# biBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkds
# b2JhbFNpZ24wHhcNMjAwNzI4MDAwMDAwWhcNMjkwMzE4MDAwMDAwWjBTMQswCQYD
# VQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEpMCcGA1UEAxMgR2xv
# YmFsU2lnbiBDb2RlIFNpZ25pbmcgUm9vdCBSNDUwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC2LcUw3Xroq5A9A3KwOkuZFmGy5f+lZx03HOV+7JODqoT1
# o0ObmEWKuGNXXZsAiAQl6fhokkuC2EvJSgPzqH9qj4phJ72hRND99T8iwqNPkY2z
# BbIogpFd+1mIBQuXBsKY+CynMyTuUDpBzPCgsHsdTdKoWDiW6d/5G5G7ixAs0sdD
# HaIJdKGAr3vmMwoMWWuOvPSrWpd7f65V+4TwgP6ETNfiur3EdaFvvWEQdESymAfi
# dKv/aNxsJj7pH+XgBIetMNMMjQN8VbgWcFwkeCAl62dniKu6TjSYa3AR3jjK1L6h
# wJzh3x4CAdg74WdDhLbP/HS3L4Sjv7oJNz1nbLFFXBlhq0GD9awd63cNRkdzzr+9
# lZXtnSuIEP76WOinV+Gzz6ha6QclmxLEnoByPZPcjJTfO0TmJoD80sMD8IwM0kXW
# LuePmJ7mBO5Cbmd+QhZxYucE+WDGZKG2nIEhTivGbWiUhsaZdHNnMXqR8tSMeW58
# prt+Rm9NxYUSK8+aIkQIqIU3zgdhVwYXEiTAxDFzoZg1V0d+EDpF2S2kUZCYqaAH
# N8RlGqocaxZ396eX7D8ZMJlvMfvqQLLn0sT6ydDwUHZ0WfqNbRcyvvjpfgP054d1
# mtRKkSyFAxMCK0KA8olqNs/ITKDOnvjLja0Wp9Pe1ZsYp8aSOvGCY/EuDiRk3wID
# AQABo4IBdzCCAXMwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFB8Av0aACvx4ObeltEPZVlC7zpY7
# MB8GA1UdIwQYMBaAFI/wS3+oLkUkrk1Q+mOai97i3Ru8MHoGCCsGAQUFBwEBBG4w
# bDAtBggrBgEFBQcwAYYhaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vcm9vdHIz
# MDsGCCsGAQUFBzAChi9odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2Vy
# dC9yb290LXIzLmNydDA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2Jh
# bHNpZ24uY29tL3Jvb3QtcjMuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsG
# AQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAN
# BgkqhkiG9w0BAQwFAAOCAQEArPfMFYsweagdCyiIGQnXHH/+hr17WjNuDWcOe2LZ
# 4RhcsL0TXR0jrjlQdjeqRP1fASNZhlZMzK28ZBMUMKQgqOA/6Jxy3H7z2Awjuqgt
# qjz27J+HMQdl9TmnUYJ14fIvl/bR4WWWg2T+oR1R+7Ukm/XSd2m8hSxc+lh30a6n
# sQvi1ne7qbQ0SqlvPfTzDZVd5vl6RbAlFzEu2/cPaOaDH6n35dSdmIzTYUsvwyh+
# et6TDrR9oAptksS0Zj99p1jurPfswwgBqzj8ChypxZeyiMgJAhn2XJoa8U1sMNSz
# BqsAYEgNeKvPF62Sk2Igd3VsvcgytNxN69nfwZCWKb3BfzCCBugwggTQoAMCAQIC
# EHe9DgW3WQu2HUdhUx4/de0wDQYJKoZIhvcNAQELBQAwUzELMAkGA1UEBhMCQkUx
# GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2JhbFNpZ24g
# Q29kZSBTaWduaW5nIFJvb3QgUjQ1MB4XDTIwMDcyODAwMDAwMFoXDTMwMDcyODAw
# MDAwMFowXDELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MjAwBgNVBAMTKUdsb2JhbFNpZ24gR0NDIFI0NSBFViBDb2RlU2lnbmluZyBDQSAy
# MDIwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyyDvlx65ATJDoFup
# iiP9IF6uOBKLyizU/0HYGlXUGVO3/aMX53o5XMD3zhGj+aXtAfq1upPvr5Pc+OKz
# GUyDsEpEUAR4hBBqpNaWkI6B+HyrL7WjVzPSWHuUDm0PpZEmKrODT3KxintkktDw
# tFVflgsR5Zq1LLIRzyUbfVErmB9Jo1/4E541uAMC2qQTL4VK78QvcA7B1MwzEuy9
# QJXTEcrmzbMFnMhT61LXeExRAZKC3hPzB450uoSAn9KkFQ7or+v3ifbfcfDRvqey
# QTMgdcyx1e0dBxnE6yZ38qttF5NJqbfmw5CcxrjszMl7ml7FxSSTY29+EIthz5hV
# oySiiDby+Z++ky6yBp8mwAwBVhLhsoqfDh7cmIsuz9riiTSmHyagqK54beyhiBU8
# wurut9itYaWvcDaieY7cDXPA8eQsq5TsWAY5NkjWO1roIs50Dq8s8RXa0bSV6KzV
# SW3lr92ba2MgXY5+O7JD2GI6lOXNtJizNxkkEnJzqwSwCdyF5tQiBO9AKh0ubcdp
# 0263AWwN4JenFuYmi4j3A0SGX2JnTLWnN6hV3AM2jG7PbTYm8Q6PsD1xwOEyp4Lk
# tjICMjB8tZPIIf08iOZpY/judcmLwqvvujr96V6/thHxvvA9yjI+bn3eD36blcQS
# h+cauE7uLMHfoWXoJIPJKsL9uVMCAwEAAaOCAa0wggGpMA4GA1UdDwEB/wQEAwIB
# hjATBgNVHSUEDDAKBggrBgEFBQcDAzASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBQlndD8WQmGY8Xs87ETO1ccA5I2ETAfBgNVHSMEGDAWgBQfAL9GgAr8eDm3
# pbRD2VZQu86WOzCBkwYIKwYBBQUHAQEEgYYwgYMwOQYIKwYBBQUHMAGGLWh0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2NvZGVzaWduaW5ncm9vdHI0NTBGBggrBgEF
# BQcwAoY6aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvY29kZXNp
# Z25pbmdyb290cjQ1LmNydDBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2NvZGVzaWduaW5ncm9vdHI0NS5jcmwwVQYDVR0gBE4wTDBB
# BgkrBgEEAaAyAQIwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2ln
# bi5jb20vcmVwb3NpdG9yeS8wBwYFZ4EMAQMwDQYJKoZIhvcNAQELBQADggIBACV1
# oAnJObq3oTmJLxifq9brHUvolHwNB2ibHJ3vcbYXamsCT7M/hkWHzGWbTONYBgIi
# ZtVhAsVjj9Si8bZeJQt3lunNcUAziCns7vOibbxNtT4GS8lzM8oIFC09TOiwunWm
# dC2kWDpsE0n4pRUKFJaFsWpoNCVCr5ZW9BD6JH3xK3LBFuFr6+apmMc+WvTQGJ39
# dJeGd0YqPSN9KHOKru8rG5q/bFOnFJ48h3HAXo7I+9MqkjPqV01eB17KwRisgS0a
# Ifpuz5dhe99xejrKY/fVMEQ3Mv67Q4XcuvymyjMZK3dt28sF8H5fdS6itr81qjZj
# yc5k2b38vCzzSVYAyBIrxie7N69X78TPHinE9OItziphz1ft9QpA4vUY1h7pkC/K
# 04dfk4pIGhEd5TeFny5mYppegU6VrFVXQ9xTiyV+PGEPigu69T+m1473BFZeIbuf
# 12pxgL+W3nID2NgiK/MnFk846FFADK6S7749ffeAxkw2V4SVp4QVSDAOUicIjY6i
# vSLHGcmmyg6oejbbarphXxEklaTijmjuGalJmV7QtDS91vlAxxCXMVI5NSkRhyTT
# xPupY8t3SNX6Yvwk4AR6TtDkbt7OnjhQJvQhcWXXCSXUyQcAerjH83foxdTiVdDT
# HvZ/UuJJjbkRcgyIRCYzZgFE3+QzDiHeYolIB9r1MIIHbzCCBVegAwIBAgIMcE3E
# /BY6leBdVXwMMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUg
# RVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDAeFw0yMjAyMTUxMzM4MzVaFw0yNTAyMTUx
# MzM4MzVaMIHUMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjESMBAGA1UE
# BRMJNTEyMjkxNjQyMRMwEQYLKwYBBAGCNzwCAQMTAklMMQswCQYDVQQGEwJJTDEQ
# MA4GA1UECBMHQ2VudHJhbDEUMBIGA1UEBxMLUGV0YWggVGlrdmExEzARBgNVBAkT
# CjkgSGFwc2Fnb3QxHzAdBgNVBAoTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4xHzAd
# BgNVBAMTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4wggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDys9frIBUzrj7+oxAS21ansV0C+r1R+DEGtb5HQ225eEqe
# NXTnOYgvrOIBLROU2tCq7nKma5qA5bNgoO0hxYQOboC5Ir5B5mmtbr1zRdhF0h/x
# f/E1RrBcsZ7ksbqeCza4ca1yH2W3YYsxFYgucq+JLqXoXToc4CjD5ogNw0Y66R13
# Km94WuowRs/tgox6SQHpzb/CF0fMNCJbpXQrzZen1dR7Gtt2cWkpZct9DCTONwbX
# GZKIdBSmRIfjDYDMHNyz42J2iifkUQgVcZLZvUJwIDz4+jkODv/++fa2GKte06po
# L5+M/WlQbua+tlAyDeVMdAD8tMvvxHdTPM1vgj11zzK5qVxgrXnmFFTe9knf9S2S
# 0C8M8L97Cha2F5sbvs24pTxgjqXaUyDuMwVnX/9usgIPREaqGY8wr0ysHd6VK4wt
# o7nroiF2uWnOaPgFEMJ8+4fRB/CSt6OyKQYQyjSUSt8dKMvc1qITQ8+gLg1budzp
# aHhVrh7dUUVn3N2ehOwIomqTizXczEFuN0siQJx+ScxLECWg4X2HoiHNY7KVJE4D
# L9Nl8YvmTNCrHNwiF1ctYcdZ1vPgMPerFhzqDUbdnCAU9Z/tVspBTcWwDGCIm+Yo
# 9V458g3iJhNXi2iKVFHwpf8hoDU0ys30SID/9mE3cc41L+zoDGOMclNHb0Y5CQID
# AQABo4IBtjCCAbIwDgYDVR0PAQH/BAQDAgeAMIGfBggrBgEFBQcBAQSBkjCBjzBM
# BggrBgEFBQcwAoZAaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# Z3NnY2NyNDVldmNvZGVzaWduY2EyMDIwLmNydDA/BggrBgEFBQcwAYYzaHR0cDov
# L29jc3AuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNvZGVzaWduY2EyMDIwMFUG
# A1UdIAROMEwwQQYJKwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3
# Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMAkGA1UdEwQCMAAw
# RwYDVR0fBEAwPjA8oDqgOIY2aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9nc2dj
# Y3I0NWV2Y29kZXNpZ25jYTIwMjAuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8G
# A1UdIwQYMBaAFCWd0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTRWDsgBgAr
# Xx8j10jVgqJYDQPVsTANBgkqhkiG9w0BAQsFAAOCAgEAU50DXmYXBEgzng8gv8EN
# mr1FT0g75g6UCgBhMkduJNj1mq8DWKxLoS11gomB0/8zJmhbtFmZxjkgNe9cWPvR
# NZa992pb9Bwwwe1KqGJFvgv3Yu1HiVL6FYzZ+m0QKmX0EofbwsFl6Z0pLSOvIESr
# ICa4SgUk0OTDHNBUo+Sy9qm+ZJjA+IEK3M/IdNGjkecsFekr8tQEm7x6kCArPoug
# mOetMgXhTxGjCu1QLQjp/i6P6wpgTSJXf9PPCxMmynsxBKGggs+vX/vl9CNT/s+X
# Z9sz764AUEKwdAdi9qv0ouyUU9fiD5wN204fPm8h3xBhmeEJ25WDNQa8QuZddHUV
# hXugk2eHd5hdzmCbu9I0qVkHyXsuzqHyJwFXbNBuiMOIfQk4P/+mHraq+cynx6/2
# a+G8tdEIjFxpTsJgjSA1W+D0s+LmPX+2zCoFz1cB8dQb1lhXFgKC/KcSacnlO4SH
# oZ6wZE9s0guXjXwwWfgQ9BSrEHnVIyKEhzKq7r7eo6VyjwOzLXLSALQdzH66cNk+
# w3yT6uG543Ydes+QAnZuwQl3tp0/LjbcUpsDttEI5zp1Y4UfU4YA18QbRGPD1F9y
# wjzg6QqlDtFeV2kohxa5pgyV9jOyX4/x0mu74qADxWHsZNVvlRLMUZ4zI4y3KvX8
# vZsjJFVKIsvyCgyXgNMM5Z4xghFEMIIRQAIBATBsMFwxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdD
# QyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMAIMcE3E/BY6leBdVXwMMA0GCWCG
# SAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEID35eRHdEKVFrAi46J0UcLy6Ih6LsHl3Mdi6o1uURH3lMA0GCSqGSIb3
# DQEBAQUABIICAOwNnm9N7PkTumYXX+Nay65KC47hob/+BirSj5J/t0HA78gkksXD
# OdAv4u7RTUUrAfUnDhCwYWPlcviDaz7mYojjPsyx9iHgBtx6uXW25PMb8stpCCao
# eaDPLEM+LIvBxtkR3yNcserIX0TJ27ZrW6d6iC8CsOC2Y3ZR5MWMu3NzFthLB19D
# toEDdSVm4lWIAurVAQh19mNRvb9Lp+tcWiFSzyFINQcSy+/8v0FchJmhK4sid5eg
# 4+2NArZbORllLXP3z7XnDfnoUaBQyPO4nfALHZd7F+d/gfjIlZvrommxTihqcQLG
# uLn+aif3to2eWrVEcbEgEFxCSuayV3dcvd2tRROsCPbdXh2tZT5yKyfuXWHsQVZp
# CH3axxOF9VBB1j9YDwrzSjgNL8GyRe43hnzxV/aIwP7jQEXsT3d7ZXjgvUzqZYuO
# sHp0afSWiL+oxGhShOrk3ugn5UyxB30tlMeB12wAOCnLZ/A9aRNoqFzwXsnCNdrW
# VlPistPydnPzgo13IUal3kzpgvTjZRM8z8DSzHgPGeHAxcVhp+WgFkm1b0kAM3U0
# kKKkZU584z9t9zlZyh5wru3oDYA9xO/Ni/St5MIbwSOYjwvefCy5KKtNJRu9qEXD
# A0gmiQfOiJ4AaR2bcYdcy3SiXHCAn0QT7XiRqsSvO47KCsMd6B/z77L+oYIOKzCC
# DicGCisGAQQBgjcDAwExgg4XMIIOEwYJKoZIhvcNAQcCoIIOBDCCDgACAQMxDTAL
# BglghkgBZQMEAgEwgf4GCyqGSIb3DQEJEAEEoIHuBIHrMIHoAgEBBgtghkgBhvhF
# AQcXAzAhMAkGBSsOAwIaBQAEFBsuIozlaER/jpZ/eosVLRbScA5PAhRgMoLryAGk
# gBebh+5N8iHubZA8HBgPMjAyNDAyMDYwODI5MTVaMAMCAR6ggYakgYMwgYAxCzAJ
# BgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UE
# CxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazExMC8GA1UEAxMoU3ltYW50ZWMgU0hB
# MjU2IFRpbWVTdGFtcGluZyBTaWduZXIgLSBHM6CCCoswggU4MIIEIKADAgECAhB7
# BbHUSWhRRPfJidKcGZ0SMA0GCSqGSIb3DQEBCwUAMIG9MQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0
# IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA4IFZlcmlTaWduLCBJbmMuIC0gRm9y
# IGF1dGhvcml6ZWQgdXNlIG9ubHkxODA2BgNVBAMTL1ZlcmlTaWduIFVuaXZlcnNh
# bCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE2MDExMjAwMDAwMFoX
# DTMxMDExMTIzNTk1OVowdzELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVj
# IENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMSgw
# JgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1mdWVVPnYxyXRqBoutV87ABrTxxrDKP
# BWuGmicAMpdqTclkFEspu8LZKbku7GOz4c8/C1aQ+GIbfuumB+Lef15tQDjUkQbn
# QXx5HMvLrRu/2JWR8/DubPitljkuf8EnuHg5xYSl7e2vh47Ojcdt6tKYtTofHjmd
# w/SaqPSE4cTRfHHGBim0P+SDDSbDewg+TfkKtzNJ/8o71PWym0vhiJka9cDpMxTW
# 38eA25Hu/rySV3J39M2ozP4J9ZM3vpWIasXc9LFL1M7oCZFftYR5NYp4rBkyjyPB
# MkEbWQ6pPrHM+dYr77fY5NUdbRE6kvaTyZzjSO67Uw7UNpeGeMWhNwIDAQABo4IB
# dzCCAXMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwZgYDVR0g
# BF8wXTBbBgtghkgBhvhFAQcXAzBMMCMGCCsGAQUFBwIBFhdodHRwczovL2Quc3lt
# Y2IuY29tL2NwczAlBggrBgEFBQcCAjAZGhdodHRwczovL2Quc3ltY2IuY29tL3Jw
# YTAuBggrBgEFBQcBAQQiMCAwHgYIKwYBBQUHMAGGEmh0dHA6Ly9zLnN5bWNkLmNv
# bTA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vcy5zeW1jYi5jb20vdW5pdmVyc2Fs
# LXJvb3QuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMIMCgGA1UdEQQhMB+kHTAbMRkw
# FwYDVQQDExBUaW1lU3RhbXAtMjA0OC0zMB0GA1UdDgQWBBSvY9bKo06FcuCnvEHz
# KaI4f4B1YjAfBgNVHSMEGDAWgBS2d/ppSEefUxLVwuoHMnYH0ZcHGTANBgkqhkiG
# 9w0BAQsFAAOCAQEAdeqwLdU0GVwyRf4O4dRPpnjBb9fq3dxP86HIgYj3p48V5kAp
# reZd9KLZVmSEcTAq3R5hF2YgVgaYGY1dcfL4l7wJ/RyRR8ni6I0D+8yQL9YKbE4z
# 7Na0k8hMkGNIOUAhxN3WbomYPLWYl+ipBrcJyY9TV0GQL+EeTU7cyhB4bEJu8LbF
# +GFcUvVO9muN90p6vvPN/QPX2fYDqA/jU/cKdezGdS6qZoUEmbf4Blfhxg726K/a
# 7JsYH6q54zoAv86KlMsB257HOLsPUqvR45QDYApNoP4nbRQy/D+XQOG/mYnb5DkU
# vdrk08PqK1qzlVhVBH3HmuwjA42FKtL/rqlhgTCCBUswggQzoAMCAQICEHvU5a+6
# zAc/oQEjBCJBTRIwDQYJKoZIhvcNAQELBQAwdzELMAkGA1UEBhMCVVMxHTAbBgNV
# BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVz
# dCBOZXR3b3JrMSgwJgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5n
# IENBMB4XDTE3MTIyMzAwMDAwMFoXDTI5MDMyMjIzNTk1OVowgYAxCzAJBgNVBAYT
# AlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3lt
# YW50ZWMgVHJ1c3QgTmV0d29yazExMC8GA1UEAxMoU3ltYW50ZWMgU0hBMjU2IFRp
# bWVTdGFtcGluZyBTaWduZXIgLSBHMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBAK8Oiqr43L9pe1QXcUcJvY08gfh0FXdnkJz93k4Cnkt29uU2PmXVJCBt
# MPndHYPpPydKM05tForkjUCNIqq+pwsb0ge2PLUaJCj4G3JRPcgJiCYIOvn6QyN1
# R3AMs19bjwgdckhXZU2vAjxA9/TdMjiTP+UspvNZI8uA3hNN+RDJqgoYbFVhV9Hx
# AizEtavybCPSnw0PGWythWJp/U6FwYpSMatb2Ml0UuNXbCK/VX9vygarP0q3InZl
# 7Ow28paVgSYs/buYqgE4068lQJsJU/ApV4VYXuqFSEEhh+XetNMmsntAU1h5jlIx
# Bk2UA0XEzjwD7LcA8joixbRv5e+wipsCAwEAAaOCAccwggHDMAwGA1UdEwEB/wQC
# MAAwZgYDVR0gBF8wXTBbBgtghkgBhvhFAQcXAzBMMCMGCCsGAQUFBwIBFhdodHRw
# czovL2Quc3ltY2IuY29tL2NwczAlBggrBgEFBQcCAjAZGhdodHRwczovL2Quc3lt
# Y2IuY29tL3JwYTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vdHMtY3JsLndzLnN5
# bWFudGVjLmNvbS9zaGEyNTYtdHNzLWNhLmNybDAWBgNVHSUBAf8EDDAKBggrBgEF
# BQcDCDAOBgNVHQ8BAf8EBAMCB4AwdwYIKwYBBQUHAQEEazBpMCoGCCsGAQUFBzAB
# hh5odHRwOi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wOwYIKwYBBQUHMAKGL2h0
# dHA6Ly90cy1haWEud3Muc3ltYW50ZWMuY29tL3NoYTI1Ni10c3MtY2EuY2VyMCgG
# A1UdEQQhMB+kHTAbMRkwFwYDVQQDExBUaW1lU3RhbXAtMjA0OC02MB0GA1UdDgQW
# BBSlEwGpn4XMG24WHl87Map5NgB7HTAfBgNVHSMEGDAWgBSvY9bKo06FcuCnvEHz
# KaI4f4B1YjANBgkqhkiG9w0BAQsFAAOCAQEARp6v8LiiX6KZSM+oJ0shzbK5pnJw
# Yy/jVSl7OUZO535lBliLvFeKkg0I2BC6NiT6Cnv7O9Niv0qUFeaC24pUbf8o/mfP
# cT/mMwnZolkQ9B5K/mXM3tRr41IpdQBKK6XMy5voqU33tBdZkkHDtz+G5vbAf0Q8
# RlwXWuOkO9VpJtUhfeGAZ35irLdOLhWa5Zwjr1sR6nGpQfkNeTipoQ3PtLHaPpp6
# xyLFdM3fRwmGxPyRJbIblumFCOjd6nRgbmClVnoNyERY3Ob5SBSe5b/eAL13sZgU
# chQk38cRLB8AP8NLFMZnHMweBqOQX1xUiz7jM1uCD8W3hgJOcZ/pZkU/djGCAlow
# ggJWAgEBMIGLMHcxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jw
# b3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEoMCYGA1UE
# AxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQe9Tlr7rMBz+hASME
# IkFNEjALBglghkgBZQMEAgGggaQwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MBwGCSqGSIb3DQEJBTEPFw0yNDAyMDYwODI5MTVaMC8GCSqGSIb3DQEJBDEiBCCc
# aPKRzQej+sgsGn9VgJzwxvOIr98fa26lOodQ1bHDIDA3BgsqhkiG9w0BCRACLzEo
# MCYwJDAiBCDEdM52AH0COU4NpeTefBTGgPniggE8/vZT7123H99h+DALBgkqhkiG
# 9w0BAQEEggEAFD9tBKOqzec/sX6ISNvPl88uaHlYOLFkQ4JQtsYiKaHbJc6w8tNh
# 0k+A3z/G3N0oHL+aWBXHbh/L0zjA8cZ/Ub0njmHnpIILDGjzwaYA87ImUoK/NEMr
# +H94koRzqj2gnWVZO3Oyub874iDxeWUd3FG5Jw226LebOCGfDvZPmKt92jNTK1At
# B9ySId5FCZta86CFXtMyyj0Q1yaTP5ECBPm2MaKr8sLaXk+Cftwe7qojQENirWXY
# vKPIUJS+byeEjRi6oLfxP/K5VpWm8FLcVtv7Fxyu2DmEhwzMZAY0sWKCcE5WB/1D
# BQn7MTxLCosDz3eThDKOSjsoCiLYy5g4BQ==
# SIG # End signature block
