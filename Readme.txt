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
	Application - The application to configure

Valid Applications:
- SqlMgmtStudio18 - Microsoft SQL Management Studio 18
  - Adds required EXE and DLL files to AppLocker configuration
- TOTPToken - CyberArk TOTP MFA Code Generator Connection Component (https://cyberark-customers.force.com/mplace/s/#a352J000000GPw5QAG-a392J000002hZX8QAM)
  - Adds required EXE and DLL files to AppLocker configuration
  - Imports Connection Component
  - NOTE: Download the component zip file from the Marketplace and place it in the same folder as the script
- ADTools - Active Directory Management Tools
  - Use -ADTools to provide a comma-separated list of connection components to install
    - All  - All of the below
    - ADUC - Active Directory Users and Computers
    - ADDT - Active Directory Domains and Trusts
    - ADSS - Active Directory Sites and Services
    - GPMC - Group Policy Management Console
    - DNS  - DNS Management Console
    - DHCP - DHCP Management Console
  - Example: .\Add-PSMApplication.ps1 -Application ADTools -ADTools ADUC,GPMC,DNS
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
      The target user must be an admin
- GoogleChromeX86 - Google Chrome 32-bit
  - Downloads and installs Google Chrome 32-bit
  - Adds Chrome to AppLocker configuration
  - Enables web application support
- GoogleChromeX64 - Google Chrome 64-bit
  - Downloads and installs Google Chrome 64-bit
  - Adds Chrome to AppLocker configuration
  - Enables web application support
  