<?php 

/**
 * Security module class
 *
 * @package munkireport
 * @author tuxudo
 **/
class Security_controller extends Module_controller
{

	/*** Protect methods with auth! ****/
	function __construct()
	{
		// Store module path
		$this->module_path = dirname(__FILE__);
	}

	/**
	 * Default method
	 * @author AvB
	 *
	 **/
	function index()
	{
		echo "You've loaded the security module!";
	}

    /**
    * Get Activation Lock statistics data in json format
    *
    * @return void
    * @author eholtam/tuxudo
    **/
    public function get_activation_lock_stats()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `activation_lock` = 'activation_lock_enabled' THEN 1 END) AS 'Enabled'")
                ->selectRaw("COUNT(CASE WHEN `activation_lock` = 'activation_lock_disabled' THEN 1 END) AS 'Disabled'")
                ->selectRaw("COUNT(CASE WHEN `activation_lock` = 'not_supported' THEN 1 END) AS 'Notsupported'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get SIP statistics data in json format
    *
    * @return void
    * @author rickheil/tuxudo
    **/
    public function get_sip_stats()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `sip` = 'Active' THEN 1 END) AS 'Active'")
                ->selectRaw("COUNT(CASE WHEN `sip` = 'Disabled' THEN 1 END) AS 'Disabled'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get Gatekeeper statistics data in json format
    *
    * @return void
    * @author rickheil/tuxudo
    **/
    public function get_gatekeeper_stats()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `gatekeeper` = 'Active' THEN 1 END) AS 'Active'")
                ->selectRaw("COUNT(CASE WHEN `gatekeeper` = 'Disabled' THEN 1 END) AS 'Disabled'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get firmware statistics data in json format
    *
    * @return void
    * @author rickheil/tuxudo
    **/
    public function get_firmwarepw_stats()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `firmwarepw` = 'Yes' THEN 1 END) AS 'enabled'")
                ->selectRaw("COUNT(CASE WHEN `firmwarepw` = 'No' THEN 1 END) AS 'disabled'")
                ->selectRaw("COUNT(CASE WHEN `firmwarepw` = 'Not Supported' THEN 1 END) AS 'notsupported'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get firewall state data in json format
    *
    * @return void
    * @author rickheil/tuxudo
    **/
    public function get_firewall_state_stats()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `firewall_state` = '2' THEN 1 END) AS 'blockall'")
                ->selectRaw("COUNT(CASE WHEN `firewall_state` = '1' THEN 1 END) AS 'enabled'")
                ->selectRaw("COUNT(CASE WHEN `firewall_state` = '0' THEN 1 END) AS 'disabled'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get Secure Kernel Extension Loading ("SKEL") data in json format
    *
    * @return void
    * @author rickheil/tuxudo
    **/
    public function get_skel_stats()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `skel_state` = '0' THEN 1 END) AS 'disabled'")
                ->selectRaw("COUNT(CASE WHEN `skel_state` = '1' THEN 1 END) AS 'enabled'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get SSH data in json format
    *
    * @return void
    * @author eholtam/tuxudo
    **/
    public function get_ssh_stats()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `ssh_users` <> 'SSH Disabled' THEN 1 END) AS 'enabled'")
                ->selectRaw("COUNT(CASE WHEN `ssh_users` = 'SSH Disabled' THEN 1 END) AS 'disabled'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get root user data in json format
    *
    * @return void
    * @author rickheil/tuxudo
    **/
    public function get_root_user_stats()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `root_user` = '0' THEN 1 END) AS 'disabled'")
                ->selectRaw("COUNT(CASE WHEN `root_user` = '1' THEN 1 END) AS 'enabled'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get secure boot data in json format
    *
    * @return void
    * @author eholtam/tuxudo
    **/
    public function get_secureboot_stats()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `t2_secureboot` = 'SECUREBOOT_FULL' THEN 1 END) AS 'securebootfull'")
                ->selectRaw("COUNT(CASE WHEN `t2_secureboot` = 'SECUREBOOT_MEDIUM' THEN 1 END) AS 'securebootmedium'")
                ->selectRaw("COUNT(CASE WHEN `t2_secureboot` = 'SECUREBOOT_OFF' THEN 1 END) AS 'securebootoff'")
                ->selectRaw("COUNT(CASE WHEN `t2_secureboot` = 'SECUREBOOT_UNKNOWN' THEN 1 END) AS 'securebootunknown'")
                ->selectRaw("COUNT(CASE WHEN `t2_secureboot` = 'SECUREBOOT_UNSUPPORTED' THEN 1 END) AS 'securebootunsupported'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get external boot data in json format
    *
    * @return void
    * @author eholtam/tuxudo
    **/
    public function get_externalboot_stats()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `t2_externalboot` = 'EXTERNALBOOT_ON' THEN 1 END) AS 'externalbooton'")
                ->selectRaw("COUNT(CASE WHEN `t2_externalboot` = 'EXTERNALBOOT_OFF' THEN 1 END) AS 'externalbootoff'")
                ->selectRaw("COUNT(CASE WHEN `t2_externalboot` = 'EXTERNALBOOT_UNKNOWN' THEN 1 END) AS 'externalbootunknown'")
                ->selectRaw("COUNT(CASE WHEN `t2_externalboot` = 'EXTERNALBOOT_UNSUPPORTED' THEN 1 END) AS 'externalbootunsupported'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get security mode data in json format
    *
    * @return void
    * @author tuxudo
    **/
    public function get_security_mode_stats()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `as_security_mode` = 'FULL_SECURITY' THEN 1 END) AS 'full'")
                ->selectRaw("COUNT(CASE WHEN `as_security_mode` = 'REDUCED_SECURITY' THEN 1 END) AS 'reduced'")
                ->selectRaw("COUNT(CASE WHEN `as_security_mode` = 'PERMISSIVE_SECURITY' THEN 1 END) AS 'permissive'")
                ->selectRaw("COUNT(CASE WHEN `as_security_mode` = 'UNKNOWN' THEN 1 END) AS 'unknown'")
                ->selectRaw("COUNT(CASE WHEN `as_security_mode` = 'SECURITYMODE_UNSUPPORTED' THEN 1 END) AS 'unsupported'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get FileVault data in json format
    *
    * @return void
    * @author tuxudo
    **/
    public function get_filevault_status()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `filevault_status` = 1 THEN 1 END) AS 'On'")
                ->selectRaw("COUNT(CASE WHEN `filevault_status` = 0 THEN 1 END) AS 'Off'")
                ->selectRaw("COUNT(CASE WHEN `filevault_status` IS NULL THEN 1 END) AS 'Unknown'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get 3rd party kexts data in json format
    *
    * @return void
    * @author tuxudo
    **/
    public function get_third_party_kexts()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `as_third_party_kexts` = 'Enabled' THEN 1 END) AS 'Enabled'")
                ->selectRaw("COUNT(CASE WHEN `as_third_party_kexts` = 'Disabled' THEN 1 END) AS 'Disabled'")
                ->selectRaw("COUNT(CASE WHEN `as_third_party_kexts` = 'UNKNOWN' THEN 1 END) AS 'Unknown'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get user allowed MDM control data in json format
    *
    * @return void
    * @author tuxudo
    **/
    public function get_user_mdm_control()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `as_user_mdm_control` = 'Enabled' THEN 1 END) AS 'Enabled'")
                ->selectRaw("COUNT(CASE WHEN `as_user_mdm_control` = 'Disabled' THEN 1 END) AS 'Disabled'")
                ->selectRaw("COUNT(CASE WHEN `as_user_mdm_control` = 'UNKNOWN' THEN 1 END) AS 'Unknown'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

    /**
    * Get DEP allowed MDM control data in json format
    *
    * @return void
    * @author tuxudo
    **/
    public function get_dep_mdm_control()
    {
        jsonView(
            Security_model::selectRaw("COUNT(CASE WHEN `as_dep_mdm_control` = 'Enabled' THEN 1 END) AS 'Enabled'")
                ->selectRaw("COUNT(CASE WHEN `as_dep_mdm_control` = 'Disabled' THEN 1 END) AS 'Disabled'")
                ->selectRaw("COUNT(CASE WHEN `as_dep_mdm_control` = 'UNKNOWN' THEN 1 END) AS 'Unknown'")
                ->filter()
                ->first()
                ->toLabelCount()
        );
    }

	/**
     * Retrieve data in json format
     *
     **/
    public function get_data($serial_number)
    {
        jsonView(
            Security_model::select()
                ->where('security.serial_number', $serial_number)
                ->filter()
                ->get()
                ->toArray()
        );
   }
} // End class Security_controller