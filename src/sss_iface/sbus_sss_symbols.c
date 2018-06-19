/*
    Generated by sbus code generator

    Copyright (C) 2017 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "sbus/sbus_interface_declarations.h"
#include "sss_iface/sbus_sss_symbols.h"

const struct sbus_method_arguments
_sbus_sss_args_org_freedesktop_FleetCommanderClient_ProcessSSSDFiles = {
    .input = (const struct sbus_argument[]){
        {.type = "u", .name = "uid"},
        {.type = "s", .name = "user_dir"},
        {.type = "q", .name = "prio"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_org_freedesktop_systemd1_Manager_RestartUnit = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "name"},
        {.type = "s", .name = "mode"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "o", .name = "job"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_org_freedesktop_systemd1_Manager_StartUnit = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "name"},
        {.type = "s", .name = "mode"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "o", .name = "job"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_org_freedesktop_systemd1_Manager_StopUnit = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "name"},
        {.type = "s", .name = "mode"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "o", .name = "job"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_AccessControl_RefreshRules = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Backend_IsOnline = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "domain_name"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "b", .name = "status"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Client_Register = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "Name"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Failover_ActiveServer = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "service_name"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "s", .name = "server"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Failover_ListServers = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "service_name"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "as", .name = "servers"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Failover_ListServices = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "domain_name"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "as", .name = "services"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_ProxyChild_Auth_PAM = {
    .input = (const struct sbus_argument[]){
        {.type = "issssssuayuayiu", .name = "pam_data"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "uua(uay)", .name = "pam_response"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_ProxyChild_Client_Register = {
    .input = (const struct sbus_argument[]){
        {.type = "u", .name = "ID"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_Responder_Domain_SetActive = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "name"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_Responder_Domain_SetInconsistent = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "name"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_Responder_NegativeCache_ResetGroups = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_Responder_NegativeCache_ResetUsers = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_autofsHandler = {
    .input = (const struct sbus_argument[]){
        {.type = "u", .name = "dp_flags"},
        {.type = "s", .name = "mapname"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "q", .name = "dp_error"},
        {.type = "u", .name = "error"},
        {.type = "s", .name = "error_message"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_getAccountDomain = {
    .input = (const struct sbus_argument[]){
        {.type = "u", .name = "entry_type"},
        {.type = "s", .name = "filter"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "q", .name = "dp_error"},
        {.type = "u", .name = "error"},
        {.type = "s", .name = "domain_name"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_getAccountInfo = {
    .input = (const struct sbus_argument[]){
        {.type = "u", .name = "dp_flags"},
        {.type = "u", .name = "entry_type"},
        {.type = "s", .name = "filter"},
        {.type = "s", .name = "domain"},
        {.type = "s", .name = "extra"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "q", .name = "dp_error"},
        {.type = "u", .name = "error"},
        {.type = "s", .name = "error_message"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_getDomains = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "domain_hint"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "q", .name = "dp_error"},
        {.type = "u", .name = "error"},
        {.type = "s", .name = "error_message"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_hostHandler = {
    .input = (const struct sbus_argument[]){
        {.type = "u", .name = "dp_flags"},
        {.type = "s", .name = "name"},
        {.type = "s", .name = "alias"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "q", .name = "dp_error"},
        {.type = "u", .name = "error"},
        {.type = "s", .name = "error_message"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_pamHandler = {
    .input = (const struct sbus_argument[]){
        {.type = "issssssuayuayiu", .name = "pam_data"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "uua(uay)", .name = "pam_response"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_sudoHandler = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "q", .name = "dp_error"},
        {.type = "u", .name = "error"},
        {.type = "s", .name = "error_message"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_monitor_RegisterService = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "name"},
        {.type = "q", .name = "version"},
        {.type = "q", .name = "type"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {.type = "q", .name = "monitor_version"},
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_nss_MemoryCache_InvalidateAllGroups = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_nss_MemoryCache_InvalidateAllInitgroups = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_nss_MemoryCache_InvalidateAllUsers = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_nss_MemoryCache_InvalidateGroupById = {
    .input = (const struct sbus_argument[]){
        {.type = "u", .name = "gid"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_nss_MemoryCache_UpdateInitgroups = {
    .input = (const struct sbus_argument[]){
        {.type = "s", .name = "user"},
        {.type = "s", .name = "domain"},
        {.type = "au", .name = "groups"},
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_service_clearEnumCache = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_service_clearMemcache = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_service_goOffline = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_service_resInit = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_service_resetOffline = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_service_rotateLogs = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

const struct sbus_method_arguments
_sbus_sss_args_sssd_service_sysbusReconnect = {
    .input = (const struct sbus_argument[]){
        {NULL}
    },
    .output = (const struct sbus_argument[]){
        {NULL}
    }
};

