<?php

use munkireport\models\MRModel as Eloquent;

class Security_model extends Eloquent
{
	protected $table = 'security';

	protected $fillable = [
		'serial_number',
		'gatekeeper',
		'sip',
		'ssh_groups',
		'ssh_users',
		'ard_groups',
		'ard_users',
		'firmwarepw',
		'firewall_state',
		'skel_state',
		'root_user',
		't2_secureboot',
		't2_externalboot',
		'activation_lock',
		'as_security_mode',
		'filevault_status',
		'filevault_users',
		'as_third_party_kexts',
		'as_user_mdm_control',
		'as_dep_mdm_control',
		'apple_setup_timestamp',
		'console_session_locked',
	];

	public $timestamps = false;
}
