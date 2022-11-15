# Add-PSMApplication

## Information
Script to assist in configuration of custom connection components

The script is provided in a zip file containing:
- Readme.md file
- Add-PSMApplication.ps1 - script to run
- Supplemental - directory containing additional files as needed to support connection component creation

## Usage
PS C:\> .\Add-PSMApplication.ps1 -Application `(Comma-separated list of applications to configure)`

The script will prompt for credentials for the _admin account or installeruser account, to import required components to the Privilege Cloud platform. This only needs to be supplied once, and can be skipped when executing the script on additional connector servers.

## Parameters
### Mandatory Parameters
Add-PSMApplication will prompt for these if not provided on the command line

| Parameter     | Description  	                                          |
| ---           | ---	                                                    |
| Application   | A comma-separated list of the applications to configure |

### Optional Parameters
| Parameter | Valid Values	                     | Description  	                                                                    |
| ---       | ---	                               | ---	                                                                              |
| HTML5     | Default, OnByDefault, OffByDefault | Control the creation of an AllowSelectHTML5 user parameter, and its default Value  |
| PortalUrl | Privilege Cloud portal address     | The address of the Privilege Cloud web portal.                                     |

If `-HTML5` is omitted, or set to Default, the AllowSelectHTML5 user parameter will not be created.

`PortalUrl` Will be detected automatically in most environments.

## Applications
### Valid applications
| Argument              | MMC-based               | Application                                             |
| ---                   | ---                     | ---	                                                    |
| ADUC                  | Yes                     | Active Directory Users and Computers                    |
| ADDT                  | Yes                     | Active Directory Domains and Trusts                     |
| ADSS                  | Yes                     | Active Directory Sites and Services                     |
| GPMC                  | Yes                     | Group Policy Management Console                         |
| DNS                   | Yes                     | DNS Management Console                                  |
| DHCP                  | Yes                     | DHCP Management Console                                 |
| GenericMMC            | Yes                     | User-configurable MMC-based connection component        |
| MicrosoftEdgeX86      | No                      | Microsoft Edge 32-bit                                   |
| MicrosoftEdgeX64      | No                      | Microsoft Edge 64-bit                                   |
| GoogleChromeX86       | No                      | Google Chrome 32-bit                                    |
| GoogleChromeX64       | No                      | Google Chrome 64-bit                                    |
| SqlMgmtStudio18       | No                      | Microsoft SQL Management Studio 18                      |
| TOTPToken             | No                      | CyberArk TOTP MFA Code Generator Connection Component   |

See below for further information on operations performed for each component.

### MMC-based connection components

MMC-based connection components install and use a generic MMC dispatcher which use the following Target-Specific Client Settings from CyberArk Privilege Cloud.
| Setting                 | Description  	                                                        |
| ---                     | ---	                                                                  |
| ClientInstallationPath  | The full path of the MMC file which will be opened by the dispatcher. |
| LogonFlag               | The LOGON_FLAG the AutoIt RunAs function will use. Default is 2.      |

Any instances of `{address}` in ClientInstallationPath will be replaced with the address of the account.

### Per-component information

#### All MMC-based components
- Installs required Remote Server Administration Tools
- Installs Generic MMC Dispatcher and MSC
- Adds MMC and Dispatcher to AppLocker configuration
- Imports required connection components into CyberArk

##### GenericMMC-specific
- Requires the following additional parameters
  - MscPath - the path of the MSC file that will be launched upon connection
  - ComponentName - the internal ID of the connection component
  - ComponentDisplayName - the name that will be displayed to users
- Supports the following additional parameters
  - SupportGPMC - Runs MMC as the target user, instead of just using the target user for network connections  
    - The target user must have the right to log on locally
    - If the target user is an administrator on the CyberArk Privilege Cloud Connector servers, UAC must be disabled on the server

#### Google Chrome
- Downloads and installs Google Chrome
- Adds Google Chrome to AppLocker configuration
- Enables web application support

#### Microsoft Edge
- Downloads and installs Microsoft Edge
- Adds Microsoft Edge to AppLocker configuration
- Enables web application support

#### Microsoft SQL Management Studio 18
- Adds required EXE and DLL files to AppLocker configuration
- Does not install SSMS - this must be installed manually before running Add-PSMApplication
- The required connection component already exists by default in Privilege Cloud for Windows Authentication
- Database Authentication support requires connection component from CyberArk Marketplace

#### TOTPToken
- Requires the component zip to be downloaded from the marketplace and placed in the same folder as Add-PSMApplication
  - https://cyberark-customers.force.com/mplace/s/#a352J000000GPw5QAG-a392J000002hZX8QAM
- Adds required EXE and DLL files to AppLocker configuration
- Imports Connection Component

