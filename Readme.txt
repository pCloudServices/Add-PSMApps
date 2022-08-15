#########################################################################
#                                                                    	  #
#                                                                    	  #
#   Add-PSMApplication                                                  #
#                                                                    	  #
#   Script to assist in configuration of custom connection components   #
#            		     										                            		#
#                                                                    	  #
#                                          		         		     	        #
#########################################################################

  .EXAMPLE
  PS C:\> .\Add-PSMApplication.ps1 -Application <Application>

The script is provided in a zip file containing:
 - Readme.txt file.
 - Add-PSMApplication.ps1 - script to run
================================================

Mandatory parameters (Add-PSMApplication will prompt for these if not provided on the command line):
	- Application - A comma-separated list of the applications to configure

The script will prompt for credentials for the _admin account or installeruser account, to
  import required components to the Privilege Cloud platform. This only needs to be supplied
  once, and can be skipped when executing the script on additional connector servers.

Valid Applications:
- SqlMgmtStudio18 - Microsoft SQL Management Studio 18
  - Adds required EXE and DLL files to AppLocker configuration
  - Does not install SSMS - this must be installed manually
  - The required connection component already exists by default in Privilege Cloud

- TOTPToken - CyberArk TOTP MFA Code Generator Connection Component (https://cyberark-customers.force.com/mplace/s/#a352J000000GPw5QAG-a392J000002hZX8QAM)
  - Adds required EXE and DLL files to AppLocker configuration
  - Imports Connection Component
  - NOTE: Download the component zip file from the Marketplace and place it in the same folder as the script

- ADUC - Active Directory Users and Computers
  - Installs required Remote Server Administration Tools
  - Installs Dispatcher and MSC
  - Adds MMC and Dispatcher to AppLocker configuration
  - Imports required connection components into CyberArk

- ADDT - Active Directory Domains and Trusts
  - Installs required Remote Server Administration Tools
  - Installs Dispatcher and MSC
  - Adds MMC and Dispatcher to AppLocker configuration
  - Imports required connection components into CyberArk

- ADSS - Active Directory Sites and Services
  - Installs required Remote Server Administration Tools
  - Installs Dispatcher and MSC
  - Adds MMC and Dispatcher to AppLocker configuration
  - Imports required connection components into CyberArk

- GPMC - Group Policy Management Console
  - Installs required Remote Server Administration Tools
  - Installs Dispatcher and MSC
  - Adds MMC and Dispatcher to AppLocker configuration
  - Imports required connection components into CyberArk

- DNS - DNS Management Console
  - Installs required Remote Server Administration Tools
  - Installs Dispatcher and MSC
  - Adds MMC and Dispatcher to AppLocker configuration
  - Imports required connection components into CyberArk

- DHCP - DHCP Management Console
  - Installs required Remote Server Administration Tools
  - Installs Dispatcher and MSC
  - Adds MMC and Dispatcher to AppLocker configuration
  - Imports required connection components into CyberArk

- GenericMMC - User-configurable MMC-based connection component
  - Installs Generic MMC Dispatcher
  - Adds MMC and Dispatcher to AppLocker configuration
  - Imports connection component into CyberArk
  - Requires the following additional parameters
    - MscPath - the path of the MSC file that will be launched upon connection
    - ComponentName - the internal ID of the connection component
    - ComponentDisplayName - the name that will be displayed to users
  - Supports the following additional parameters
    - SupportGPMC - Runs MMC as the target user, instead of just using the target user for network connections
      The target user must have the right to log on locally
      If the target user is an administrator on the CyberArk Privilege Cloud Connector servers, UAC must be disabled on the server

- GoogleChromeX86 - Google Chrome 32-bit
  - Downloads and installs Google Chrome 32-bit
  - Adds Chrome to AppLocker configuration
  - Enables web application support

- GoogleChromeX64 - Google Chrome 64-bit
  - Downloads and installs Google Chrome 64-bit
  - Adds Chrome to AppLocker configuration
  - Enables web application support
  