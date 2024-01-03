<div class="col-lg-4">
    <h4><i class="fa fa-key fa-fixed"></i> <span data-i18n="security.security"></span></h4>
    <table id="security-data" class="table"></table>
</div>

<script>
$(document).on('appReady', function(){
    // Get security data
    $.getJSON( appUrl + '/module/security/get_data/' + serialNumber, function( data ) {
        $.each(data, function(index, item){
            $('#security-data')
                .append($('<tbody>')
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.gatekeeper')))
                        .append($('<td>')
                            .text(item.gatekeeper)))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.sip')))
                        .append($('<td>')
                            .text(item.sip)))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.ssh_groups')))
                        .append($('<td>')
                            .text(item.ssh_groups)))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.ssh_users')))
                        .append($('<td>')
                            .text(item.ssh_users)))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.ard_users')))
                        .append($('<td>')
                            .text(item.ard_users)))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.ard_groups')))
                        .append($('<td>')
                            .text(item.ard_groups)))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.apple_setup_timestamp')))
                        .append($('<td>')
                            .html(function(){
                                if(item.apple_setup_timestamp > 0){
                                    var date = new Date(parseInt(item.apple_setup_timestamp) * 1000);
                                    return('<span title="'+moment(date).fromNow()+'">'+moment(date).format('llll')+'</span>')
                                }
                            })))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.console_session_locked')))
                        .append($('<td>')
                            .text(function(){
                                if(item.console_session_locked == '1'){
                                    return i18n.t('yes');
                                }
                                if(item.console_session_locked == '0'){
                                    return i18n.t('no');
                                }
                            })))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.firmwarepw')))
                        .append($('<td>')
                            .text(item.firmwarepw)))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.firewall_state')))
                        .append($('<td class="mr-firewall_state">')
                            .text(item.firewall_state)))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.skel.kext-loading')))
                        .append($('<td class="mr-skel_state">')
                            .text(item.skel_state)))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.t2_secureboot')))
                        .append($('<td>')
                            .text(function(){
                                if(item.t2_secureboot == 'SECUREBOOT_OFF'){
                                    return i18n.t('security.off');
                                }
                                if(item.t2_secureboot == 'SECUREBOOT_MEDIUM'){
                                    return i18n.t('security.medium');
                                }
                                if(item.t2_secureboot == 'SECUREBOOT_FULL'){
                                    return i18n.t('security.full');
                                }
                                if(item.t2_secureboot == 'SECUREBOOT_UNSUPPORTED'){
                                    return i18n.t('security.unsupported');
                                }
                            })))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.t2_externalboot')))
                        .append($('<td>')
                            .text(function(){
                                if(item.t2_externalboot == 'EXTERNALBOOT_OFF'){
                                    return i18n.t('security.off');
                                }
                                if(item.t2_externalboot == 'EXTERNALBOOT_ON'){
                                    return i18n.t('security.on');
                                }
                                if(item.t2_externalboot == 'EXTERNALBOOT_UNSUPPORTED'){
                                    return i18n.t('security.unsupported');
                                }
                           })))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.security_mode')))
                        .append($('<td>')
                            .text(function(){
                                if(item.as_security_mode == 'FULL_SECURITY'){
                                    return i18n.t('security.full');
                                }
                                if(item.as_security_mode == 'REDUCED_SECURITY'){
                                    return i18n.t('security.reduced');
                                }
                                if(item.as_security_mode == 'PERMISSIVE_SECURITY'){
                                    return i18n.t('security.permissive');
                                }
                                if(item.as_security_mode == 'SECURITYMODE_UNSUPPORTED'){
                                    return i18n.t('security.unsupported');
                                }
                           })))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.third_party_kexts')))
                        .append($('<td>')
                            .text(function(){
                                if(item.as_third_party_kexts == 'Enabled'){
                                    return i18n.t('enabled');
                                }
                                if(item.as_third_party_kexts == 'Disabled'){
                                    return i18n.t('disabled');
                                }
                                if(item.as_third_party_kexts == 'UNKNOWN'){
                                    return i18n.t('security.unknown');
                                }
                                if(item.as_third_party_kexts == 'UNSUPPORTED'){
                                    return i18n.t('security.unsupported');
                                }
                           })))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.user_mdm_control')))
                        .append($('<td>')
                            .text(function(){
                                if(item.as_user_mdm_control == 'Enabled'){
                                    return i18n.t('enabled');
                                }
                                if(item.as_user_mdm_control == 'Disabled'){
                                    return i18n.t('disabled');
                                }
                                if(item.as_user_mdm_control == 'UNKNOWN'){
                                    return i18n.t('security.unknown');
                                }
                                if(item.as_user_mdm_control == 'UNSUPPORTED'){
                                    return i18n.t('security.unsupported');
                                }
                           })))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.dep_mdm_control')))
                        .append($('<td>')
                            .text(function(){
                                if(item.as_dep_mdm_control == 'Enabled'){
                                    return i18n.t('enabled');
                                }
                                if(item.as_dep_mdm_control == 'Disabled'){
                                    return i18n.t('disabled');
                                }
                                if(item.as_dep_mdm_control == 'UNKNOWN'){
                                    return i18n.t('security.unknown');
                                }
                                if(item.as_dep_mdm_control == 'UNSUPPORTED'){
                                    return i18n.t('security.unsupported');
                                }
                           })))
                    .append($('<tr>')
                        .append($('<th>')
                            .text(i18n.t('security.activation_lock_status')))
                        .append($('<td class="mr-activation_lock">')
                            .text(function(){
                                if(item.activation_lock == 'activation_lock_enabled'){
                                    return i18n.t('enabled');
                                }
                                if(item.activation_lock == 'activation_lock_disabled'){
                                    return i18n.t('disabled');
                                }
                                if(item.activation_lock == 'not_supported'){
                                    return i18n.t('unsupported');
                                }
                            }))))

            // Firewall
            var fw_states = [i18n.t('disabled'), i18n.t('enabled'), i18n.t('security.block_all')]
            var firewall_state = parseInt(item.firewall_state);
            $('.mr-firewall_state').text(fw_states[firewall_state] || i18n.t('unknown'));

            // SKEL status
            var skel_states = [i18n.t('security.skel.all-allowed'), i18n.t('security.skel.user-approved')]
            var skel_state = parseInt(item.skel_state);
            $('.mr-skel_state').text(skel_states[skel_state] || i18n.t('unknown'));

        });
    });
});
</script>
