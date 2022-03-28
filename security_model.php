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
		'filevault_status',
		'filevault_users',
    ];

    public $timestamps = false;
}
