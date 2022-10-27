[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("MicrosoftEdgeX86", "MicrosoftEdgeX64", "GoogleChromeX86", "GoogleChromeX64", "SqlMgmtStudio18", "GenericMMC", "TOTPToken", "ADUC", "DNS", "DHCP", "ADDT", "ADSS", "GPMC")]
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

$ListApplicationsWithoutConnectionComponents = "GoogleChromeX86", "GoogleChromeX64", "SqlMgmtStudio18", "MicrosoftEdgeX86", "MicrosoftEdgeX64"

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
            $Tasks += "Note: To support Group Policy Management:"
            $Tasks += "  The target account must have the `"Allow Log on Locally`" user right."
            $Tasks += "  If the target account is an administrator on the CyberArk server, UAC must be disabled."
            $Tasks += "  Please consider the risks carefully before enabling this connection component."
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
        If (
            !(
            ($ComponentName) -and ($ComponentDisplayName) -and ($MSCPath)
            )
        ) {
            Write-LogMessage -type Error -MSG "ComponentName, ComponentDisplayName and MscPath are mandatory for Generic MMC components"
            exit 1
        }
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

        $Tasks += "Create $MSCPath"
        $Tasks += "Add the `"$ComponentDisplayName`" connection component to applicable domain platforms"
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
        $Tasks += "Import a platform supporting MFADeviceKeys-*.zip"
        $Tasks += "Associate the TOTP Token connection component with an appropriate platform"
    }
    "SqlMgmtStudio18" {
        If (!(Test-Path "C:\Program Files (x86)\Microsoft SQL Server Management Studio 18\Common7\IDE\Ssms.exe")) {
            Write-LogMessage -type Error -MSG "SQL Management Studio 18 does not appear to be installed. Please install it first."
            exit 1
        }

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
        If (Test-Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe") {
            Write-LogMessage -type Error -MSG "Microsoft Edge exists at `"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`""
            Write-LogMessage -type Error -MSG "which is the 32-bit installation path. Please uninstall it and run script again if you"
            Write-LogMessage -type Error -MSG "want to switch to the 64-bit version "
            exit 1
        }
        If (Test-Path "C:\Program Files\Microsoft\Edge\Application\msedge.exe") {
            Write-LogMessage -type Info -MSG "Microsoft Edge appears to be installed already. Will not reinstall."
        }
        else {
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
        $Path = "C:\Program Files\Microsoft\Edge\Application\msedge.exe"

        $AppLockerEntries = @(
            (New-PSMApplicationElement -Xml $xml -EntryType Application -Name MicrosoftEdge -FileType Exe -Path $Path -Method Publisher)
        )
        Add-PSMConfigureAppLockerSection -SectionName "Microsoft Edge" -XmlDoc ([REF]$xml) -AppLockerEntries $AppLockerEntries
    }

    # Microsoft Edge 32 bit
    "MicrosoftEdgeX86" {
        Write-LogMessage -type Info -MSG "Checking if Microsoft Edge 64 bit is present"
        If (Test-Path "C:\Program Files\Microsoft\Edge\Application\msedge.exe") {
            Write-LogMessage -type Error -MSG "Microsoft Edge exists at `"C:\Program Files\Microsoft\Edge\Application\msedge.exe`""
            Write-LogMessage -type Error -MSG "which is the 64-bit installation path. Please uninstall it and run script again if you"
            Write-LogMessage -type Error -MSG "want to switch to the 32-bit version "
            exit 1
        }
        If (Test-Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe") {
            Write-LogMessage -type Info -MSG "Microsoft Edge appears to be installed already. Will not reinstall."
        }
        else {
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
