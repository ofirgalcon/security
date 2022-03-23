var formatSecurityFirewall = function(colNumber, row){
    var col = $('td:eq('+colNumber+')', row),
        colvar = col.text();
    colvar = colvar == '1' ? '<span class="label label-success">'+i18n.t('enabled')+'</span>' :
    colvar = colvar == '2' ? '<span class="label label-success">'+i18n.t('security.block_all')+'</span>' :
    (colvar === '0' ? '<span class="label label-danger">'+i18n.t('disabled')+'</span>' : colvar)
    col.html(colvar)
}

var formatSecurityFileVaultEncrypted = function(colNumber, row){
    var col = $('td:eq('+colNumber+')', row),
        colvar = col.text();
    colvar = colvar == '1' ? '<span class="label label-success">'+i18n.t('encrypted')+'</span>' :
    (colvar === '0' ? '<span class="label label-danger">'+i18n.t('unencrypted')+'</span>' : 
    colvar = '<span class="label label-default">'+i18n.t('unknown')+'</span>')
    col.html(colvar)
}

var formatSecurityGatekeeper = function(colNumber, row){
    var col = $('td:eq('+colNumber+')', row),
        colvar = col.text();
    colvar = colvar == 'Active' ? '<span class="label label-success">'+i18n.t('enabled')+'</span>' :
    colvar = (colvar == 'Not Supported' ? '<span class="label label-info">'+i18n.t('unsupported')+'</span>' : 
    colvar = '<span class="label label-danger">'+i18n.t('disabled')+'</span>')
    col.html(colvar)
}

var formatSecurityRootUser = function(colNumber, row){
    var col = $('td:eq('+colNumber+')', row),
        colvar = col.text();
    colvar = colvar == '0' ? '<span class="label label-success">'+i18n.t('disabled')+'</span>' :
    colvar = (colvar == '1' ? '<span class="label label-danger">'+i18n.t('enabled')+'</span>' :
    colvar = '<span class="label label-default">'+i18n.t('unknown')+'</span>')
    col.html(colvar)
}

var formatSecurityFirmwarePW = function(colNumber, row){
    var col = $('td:eq('+colNumber+')', row),
        colvar = col.text();
    colvar = colvar == 'Yes' ? '<span class="label label-success">'+i18n.t('enabled')+'</span>' :
    colvar = colvar == 'command' ? '<span class="label label-success">'+i18n.t('enabled')+'</span>' :
    colvar = colvar == 'No' ? '<span class="label label-danger">'+i18n.t('disabled')+'</span>' :
    colvar = (colvar == 'Not Supported' ? '<span class="label label-info">'+i18n.t('unsupported')+'</span>' : 
    colvar = '<span class="label label-default">'+i18n.t('unknown')+'</span>')
    col.html(colvar)
}

var formatSecuritySKEL = function(colNumber, row){
    var col = $('td:eq('+colNumber+')', row),
        colvar = col.text();
    colvar = colvar == '1' ? '<span class="label label-info">'+i18n.t('security.skel.all-approved')+'</span>' :
    colvar = (colvar == '0' ? '<span class="label label-info">'+i18n.t('security.skel.user-approved')+'</span>' :
    colvar = '<span class="label label-default">'+i18n.t('unknown')+'</span>')
    col.html(colvar)
}

var formatSecuritySecureBoot = function(colNumber, row){
    var col = $('td:eq('+colNumber+')', row),
        colvar = col.text();
    colvar = colvar == 'SECUREBOOT_FULL' ? '<span class="label label-success">'+i18n.t('security.full')+'</span>' :
    colvar = colvar == 'SECUREBOOT_MEDIUM' ? '<span class="label label-warning">'+i18n.t('security.medium')+'</span>' :
    colvar = colvar == 'SECUREBOOT_OFF' ? '<span class="label label-danger">'+i18n.t('security.off')+'</span>' :
    colvar = (colvar == 'SECUREBOOT_UNSUPPORTED' ? '<span class="label label-info">'+i18n.t('security.unsupported')+'</span>' : 
    colvar = '<span class="label label-default">'+i18n.t('unknown')+'</span>')
    col.html(colvar)
}

var formatSecurityExternalBoot = function(colNumber, row){
    var col = $('td:eq('+colNumber+')', row),
        colvar = col.text();
    colvar = colvar == 'EXTERNALBOOT_ON' ? '<span class="label label-danger">'+i18n.t('security.on')+'</span>' :
    colvar = colvar == 'EXTERNALBOOT_OFF' ? '<span class="label label-success">'+i18n.t('security.off')+'</span>' :
    colvar = (colvar == 'EXTERNALBOOT_UNSUPPORTED' ? '<span class="label label-info">'+i18n.t('security.unsupported')+'</span>' : 
    colvar = '<span class="label label-default">'+i18n.t('unknown')+'</span>')
    col.html(colvar)
}

var formatSecurityActivationLock = function(colNumber, row){
    var col = $('td:eq('+colNumber+')', row),
        colvar = col.text();
    colvar = colvar == 'activation_lock_enabled' ? '<span class="label label-danger">'+i18n.t('enabled')+'</span>' :
    colvar = colvar == 'activation_lock_disabled' ? '<span class="label label-success">'+i18n.t('disabled')+'</span>' :
    colvar = (colvar == 'not_supported' ? '<span class="label label-info">'+i18n.t('security.unsupported')+'</span>' : 
    colvar = '<span class="label label-default">'+i18n.t('unknown')+'</span>')
    col.html(colvar)
}