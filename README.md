Security module
================


The following information is stored in the security table:


* Gatekeeper Status 10.7+
* SIP Status 10.11+
* Firmware Password State
* Application Firewall State
* User-Approved Kernel Extension Loading (UAKEL/SKEL) State

In the future, this module can be expanded to support xprotect, screen saver password, etc...

For the application firewall state, there are three possible values:
* Disabled = 0 - the firewall is fully disabled
* Enabled = 1 - the firewall is enabled.
* Block All = 2 - the firewall is enabled, and "Block all incoming connections" is checked in the GUI

For the user-approved kernel extension loading state, there are two possible values:
* User Approved = 0 - Machines with UAKEL/SKEL turned on in the default state (security.skel.user-approved)
* Open = 1 - Pre-10.13 machines or machines where UAKEL/SKEL is in disabled state (security.skel.all-approved)

Table Schema
-----

Database:
* gatekeeper - varchar(255) - Status of Gatekeeper
* sip - varchar(255) - Status of SIP
* ssh_groups - varchar(255) - SSH enabled groups
* ssh_users - varchar(255) - SSH enabled users
* ard_groups - varchar(255) - Apple Remote Desktop enabled groups
* root_user - varchar(255) - Status of root user account
* ard_users - varchar(255) - Apple Remote Desktop enabled users
* firmwarepw - varchar(255) - Status of firmware password or Recovery Lock
* firewall_state - varchar(255) - Status of firewall
* skel_state - varchar(255) - SKEL state
* t2_secureboot - varchar(255) - State of SecureBoot, T2 and Apple Silicon Macs only
* t2_externalboot - varchar(255) - State of External Boot, T2 and Apple Silicon Macs only
* activation_lock - varchar(255) - Status of Activation lock
* filevault_status - boolean - FileVault encrypted or unencrypted
* filevault_users - varchar(255) - FileVault enabled users
* as_security_mode - varchar(255) - Security Mode, Apple Silicon Macs only
* as_third_party_kexts - varchar(255) - 3rd party kexts allowed, Apple Silicon Macs only
* as_user_mdm_control - varchar(255) - User allowed MDM control, Apple Silicon Macs only
* as_dep_mdm_control - varchar(255) - DEP allowed MDM control, Apple Silicon Macs only
* apple_setup_timestamp - bigint - Timestamp of when .AppleSetupDone file was created