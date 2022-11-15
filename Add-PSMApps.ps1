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
# SIG # Begin signature block
# MIIgTQYJKoZIhvcNAQcCoIIgPjCCIDoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBhUMUoeUlb/EMq
# +v7VQwc7+w4cYYCvZB5cNEZrOM6nbKCCDl8wggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB28wggVXoAMCAQICDHBNxPwWOpXgXVV8
# DDANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjIwMjE1MTMzODM1WhcNMjUwMjE1MTMzODM1WjCB
# 1DEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEjAQBgNVBAUTCTUxMjI5
# MTY0MjETMBEGCysGAQQBgjc8AgEDEwJJTDELMAkGA1UEBhMCSUwxEDAOBgNVBAgT
# B0NlbnRyYWwxFDASBgNVBAcTC1BldGFoIFRpa3ZhMRMwEQYDVQQJEwo5IEhhcHNh
# Z290MR8wHQYDVQQKExZDeWJlckFyayBTb2Z0d2FyZSBMdGQuMR8wHQYDVQQDExZD
# eWJlckFyayBTb2Z0d2FyZSBMdGQuMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA8rPX6yAVM64+/qMQEttWp7FdAvq9UfgxBrW+R0NtuXhKnjV05zmIL6zi
# AS0TlNrQqu5ypmuagOWzYKDtIcWEDm6AuSK+QeZprW69c0XYRdIf8X/xNUawXLGe
# 5LG6ngs2uHGtch9lt2GLMRWILnKviS6l6F06HOAow+aIDcNGOukddypveFrqMEbP
# 7YKMekkB6c2/whdHzDQiW6V0K82Xp9XUexrbdnFpKWXLfQwkzjcG1xmSiHQUpkSH
# 4w2AzBzcs+Nidoon5FEIFXGS2b1CcCA8+Po5Dg7//vn2thirXtOqaC+fjP1pUG7m
# vrZQMg3lTHQA/LTL78R3UzzNb4I9dc8yualcYK155hRU3vZJ3/UtktAvDPC/ewoW
# thebG77NuKU8YI6l2lMg7jMFZ1//brICD0RGqhmPMK9MrB3elSuMLaO566Ihdrlp
# zmj4BRDCfPuH0QfwkrejsikGEMo0lErfHSjL3NaiE0PPoC4NW7nc6Wh4Va4e3VFF
# Z9zdnoTsCKJqk4s13MxBbjdLIkCcfknMSxAloOF9h6IhzWOylSROAy/TZfGL5kzQ
# qxzcIhdXLWHHWdbz4DD3qxYc6g1G3ZwgFPWf7VbKQU3FsAxgiJvmKPVeOfIN4iYT
# V4toilRR8KX/IaA1NMrN9EiA//ZhN3HONS/s6AxjjHJTR29GOQkCAwEAAaOCAbYw
# ggGyMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYBBQUH
# MAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2NjcjQ1
# ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3NwLmds
# b2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAETjBM
# MEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1UdHwRA
# MD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNv
# ZGVzaWduY2EyMDIwLmNybDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSMEGDAW
# gBQlndD8WQmGY8Xs87ETO1ccA5I2ETAdBgNVHQ4EFgQU0Vg7IAYAK18fI9dI1YKi
# WA0D1bEwDQYJKoZIhvcNAQELBQADggIBAFOdA15mFwRIM54PIL/BDZq9RU9IO+YO
# lAoAYTJHbiTY9ZqvA1isS6EtdYKJgdP/MyZoW7RZmcY5IDXvXFj70TWWvfdqW/Qc
# MMHtSqhiRb4L92LtR4lS+hWM2fptECpl9BKH28LBZemdKS0jryBEqyAmuEoFJNDk
# wxzQVKPksvapvmSYwPiBCtzPyHTRo5HnLBXpK/LUBJu8epAgKz6LoJjnrTIF4U8R
# owrtUC0I6f4uj+sKYE0iV3/TzwsTJsp7MQShoILPr1/75fQjU/7Pl2fbM++uAFBC
# sHQHYvar9KLslFPX4g+cDdtOHz5vId8QYZnhCduVgzUGvELmXXR1FYV7oJNnh3eY
# Xc5gm7vSNKlZB8l7Ls6h8icBV2zQbojDiH0JOD//ph62qvnMp8ev9mvhvLXRCIxc
# aU7CYI0gNVvg9LPi5j1/tswqBc9XAfHUG9ZYVxYCgvynEmnJ5TuEh6GesGRPbNIL
# l418MFn4EPQUqxB51SMihIcyqu6+3qOlco8Dsy1y0gC0Hcx+unDZPsN8k+rhueN2
# HXrPkAJ2bsEJd7adPy423FKbA7bRCOc6dWOFH1OGANfEG0Rjw9RfcsI84OkKpQ7R
# XldpKIcWuaYMlfYzsl+P8dJru+KgA8Vh7GTVb5USzFGeMyOMtyr1/L2bIyRVSiLL
# 8goMl4DTDOWeMYIRRDCCEUACAQEwbDBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjACDHBNxPwWOpXgXVV8DDANBglghkgBZQMEAgEF
# AKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC4
# ZEE377JBYAGhEsUhytWLWY7SZwRZsq/tGOZ04HqG6TANBgkqhkiG9w0BAQEFAASC
# AgBIIAr9xqg5K+fpidlQVC8WXRkBMvDKjZweNabwsaqszgrwr1eUldPQd4CI9t2N
# /ei6oXZR9RbGjLfG6w91kjjuGedZpKtjU1GHuwBYLKGQiC7/EFv9Img8BLXnbNRH
# 6Kn3NLjzd3BhzPncuiqZy6XGGWlMbLyLCvIGIPzmPxgxBryyI3ZkFgDgLHovAGzK
# Ab3jukb9u5AW9tkWE9qo0LmTJx/b+DyrGtQEGbp12TO4IBJXBeytQbehFHi14oXk
# Gd5FFXf1VbN7r0tt/N6uQ+QUYalHHjGdcwqv3DEwOoc9Ln1AlQ6fx9p96dtKp6+4
# X2eNtHM7g4o9j1Uw7rZAMKDfEU8uXcBQAR9luv0DUwb/xNhvsZixNTtPGbyh694r
# 6fhr3SUKN4vYAjSDvl9Y1GYjh6GQUJAdsuuRidVbcwwgNVwXhhLk5PMWKjcdAfye
# 7ntRgFYb7sg7xCg3Kfs2jMHaOBV+W6e/3Tzduqx159EtwZNs6Bftpo1WL0mCzCYv
# L2rFOPPnabucMcPRc7Zeq9aizZtCjHhbmQQTW2VB+KGeEstyv9Y3dCWkRV4Y9lsf
# fTfADQcH8ChzdH3uaQwnN0HFgbZRak5bp8RFnMu/jcdu31XSSQENl/h3D4k5m4kP
# ZUzvVC9pSVTaBErYmGJa10AQlf4ZXMOalfEsAwsMjKjSJaGCDiswgg4nBgorBgEE
# AYI3AwMBMYIOFzCCDhMGCSqGSIb3DQEHAqCCDgQwgg4AAgEDMQ0wCwYJYIZIAWUD
# BAIBMIH+BgsqhkiG9w0BCRABBKCB7gSB6zCB6AIBAQYLYIZIAYb4RQEHFwMwITAJ
# BgUrDgMCGgUABBQZCa2bJgGaX6HW0Tp9CdievW/unwIUG+886YRU+CNDfWc1iK8K
# pyR+wFUYDzIwMjIxMTE1MTUwNTUyWjADAgEeoIGGpIGDMIGAMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFu
# dGVjIFRydXN0IE5ldHdvcmsxMTAvBgNVBAMTKFN5bWFudGVjIFNIQTI1NiBUaW1l
# U3RhbXBpbmcgU2lnbmVyIC0gRzOgggqLMIIFODCCBCCgAwIBAgIQewWx1EloUUT3
# yYnSnBmdEjANBgkqhkiG9w0BAQsFADCBvTELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3Jr
# MTowOAYDVQQLEzEoYykgMjAwOCBWZXJpU2lnbiwgSW5jLiAtIEZvciBhdXRob3Jp
# emVkIHVzZSBvbmx5MTgwNgYDVQQDEy9WZXJpU2lnbiBVbml2ZXJzYWwgUm9vdCBD
# ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNjAxMTIwMDAwMDBaFw0zMTAxMTEy
# MzU5NTlaMHcxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEoMCYGA1UEAxMf
# U3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBALtZnVlVT52Mcl0agaLrVfOwAa08cawyjwVrhponADKX
# ak3JZBRLKbvC2Sm5Luxjs+HPPwtWkPhiG37rpgfi3n9ebUA41JEG50F8eRzLy60b
# v9iVkfPw7mz4rZY5Ln/BJ7h4OcWEpe3tr4eOzo3HberSmLU6Hx45ncP0mqj0hOHE
# 0XxxxgYptD/kgw0mw3sIPk35CrczSf/KO9T1sptL4YiZGvXA6TMU1t/HgNuR7v68
# kldyd/TNqMz+CfWTN76ViGrF3PSxS9TO6AmRX7WEeTWKeKwZMo8jwTJBG1kOqT6x
# zPnWK++32OTVHW0ROpL2k8mc40juu1MO1DaXhnjFoTcCAwEAAaOCAXcwggFzMA4G
# A1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMGYGA1UdIARfMF0wWwYL
# YIZIAYb4RQEHFwMwTDAjBggrBgEFBQcCARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9j
# cHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6Ly9kLnN5bWNiLmNvbS9ycGEwLgYIKwYB
# BQUHAQEEIjAgMB4GCCsGAQUFBzABhhJodHRwOi8vcy5zeW1jZC5jb20wNgYDVR0f
# BC8wLTAroCmgJ4YlaHR0cDovL3Muc3ltY2IuY29tL3VuaXZlcnNhbC1yb290LmNy
# bDATBgNVHSUEDDAKBggrBgEFBQcDCDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQ
# VGltZVN0YW1wLTIwNDgtMzAdBgNVHQ4EFgQUr2PWyqNOhXLgp7xB8ymiOH+AdWIw
# HwYDVR0jBBgwFoAUtnf6aUhHn1MS1cLqBzJ2B9GXBxkwDQYJKoZIhvcNAQELBQAD
# ggEBAHXqsC3VNBlcMkX+DuHUT6Z4wW/X6t3cT/OhyIGI96ePFeZAKa3mXfSi2VZk
# hHEwKt0eYRdmIFYGmBmNXXHy+Je8Cf0ckUfJ4uiNA/vMkC/WCmxOM+zWtJPITJBj
# SDlAIcTd1m6JmDy1mJfoqQa3CcmPU1dBkC/hHk1O3MoQeGxCbvC2xfhhXFL1TvZr
# jfdKer7zzf0D19n2A6gP41P3CnXsxnUuqmaFBJm3+AZX4cYO9uiv2uybGB+queM6
# AL/OipTLAduexzi7D1Kr0eOUA2AKTaD+J20UMvw/l0Dhv5mJ2+Q5FL3a5NPD6ita
# s5VYVQR9x5rsIwONhSrS/66pYYEwggVLMIIEM6ADAgECAhB71OWvuswHP6EBIwQi
# QU0SMA0GCSqGSIb3DQEBCwUAMHcxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1h
# bnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29y
# azEoMCYGA1UEAxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0x
# NzEyMjMwMDAwMDBaFw0yOTAzMjIyMzU5NTlaMIGAMQswCQYDVQQGEwJVUzEdMBsG
# A1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRy
# dXN0IE5ldHdvcmsxMTAvBgNVBAMTKFN5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBp
# bmcgU2lnbmVyIC0gRzMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCv
# Doqq+Ny/aXtUF3FHCb2NPIH4dBV3Z5Cc/d5OAp5LdvblNj5l1SQgbTD53R2D6T8n
# SjNObRaK5I1AjSKqvqcLG9IHtjy1GiQo+BtyUT3ICYgmCDr5+kMjdUdwDLNfW48I
# HXJIV2VNrwI8QPf03TI4kz/lLKbzWSPLgN4TTfkQyaoKGGxVYVfR8QIsxLWr8mwj
# 0p8NDxlsrYViaf1OhcGKUjGrW9jJdFLjV2wiv1V/b8oGqz9KtyJ2ZezsNvKWlYEm
# LP27mKoBONOvJUCbCVPwKVeFWF7qhUhBIYfl3rTTJrJ7QFNYeY5SMQZNlANFxM48
# A+y3API6IsW0b+XvsIqbAgMBAAGjggHHMIIBwzAMBgNVHRMBAf8EAjAAMGYGA1Ud
# IARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcCARYXaHR0cHM6Ly9kLnN5
# bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6Ly9kLnN5bWNiLmNvbS9y
# cGEwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5j
# b20vc2hhMjU2LXRzcy1jYS5jcmwwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYD
# VR0PAQH/BAQDAgeAMHcGCCsGAQUFBwEBBGswaTAqBggrBgEFBQcwAYYeaHR0cDov
# L3RzLW9jc3Aud3Muc3ltYW50ZWMuY29tMDsGCCsGAQUFBzAChi9odHRwOi8vdHMt
# YWlhLndzLnN5bWFudGVjLmNvbS9zaGEyNTYtdHNzLWNhLmNlcjAoBgNVHREEITAf
# pB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtNjAdBgNVHQ4EFgQUpRMBqZ+F
# zBtuFh5fOzGqeTYAex0wHwYDVR0jBBgwFoAUr2PWyqNOhXLgp7xB8ymiOH+AdWIw
# DQYJKoZIhvcNAQELBQADggEBAEaer/C4ol+imUjPqCdLIc2yuaZycGMv41UpezlG
# Tud+ZQZYi7xXipINCNgQujYk+gp7+zvTYr9KlBXmgtuKVG3/KP5nz3E/5jMJ2aJZ
# EPQeSv5lzN7Ua+NSKXUASiulzMub6KlN97QXWZJBw7c/hub2wH9EPEZcF1rjpDvV
# aSbVIX3hgGd+Yqy3Ti4VmuWcI69bEepxqUH5DXk4qaENz7Sx2j6aescixXTN30cJ
# hsT8kSWyG5bphQjo3ep0YG5gpVZ6DchEWNzm+UgUnuW/3gC9d7GYFHIUJN/HESwf
# AD/DSxTGZxzMHgajkF9cVIs+4zNbgg/Ft4YCTnGf6WZFP3YxggJaMIICVgIBATCB
# izB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24x
# HzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMTH1N5bWFu
# dGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEHvU5a+6zAc/oQEjBCJBTRIwCwYJ
# YIZIAWUDBAIBoIGkMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG
# 9w0BCQUxDxcNMjIxMTE1MTUwNTUyWjAvBgkqhkiG9w0BCQQxIgQgva7WlaHeay13
# 9H2VkwVXfqvrGDHt2CkNTyb5ZDQO+kUwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQg
# xHTOdgB9AjlODaXk3nwUxoD54oIBPP72U+9dtx/fYfgwCwYJKoZIhvcNAQEBBIIB
# AAVlwXNPpAP0K8BEfuuM60jfvZPr9u16OrQJEajx+EK4/j43o9cr9Fc7iB1NvqRZ
# 8eRm/YRFDLUCBdM2nMvLrS+VAubctf28XDQygE/VQeWdYd0utJyXO9r35d2XZyoL
# 0XJyDA3a8WK4j+EzonQgAANC6Gsti+OAK+EknEmINz82zsdM+U+4hWS3dGnw1FOO
# x+UUV73xtebL+A6y8zaJYTJ+qLMUxuYXTC9uUnP5wnir6Lf9vy1Sfdj6U1Coefuz
# ex0OKWDb4ha7/hLSIxOK8V7BTmge6TArQlCVQJMLwl3/FsOs1sLzOgonaYS/nx75
# k0uxLGnIvxyKNPH2Bqgayl8=
# SIG # End signature block
