/*
   SSSD - cmd2str util

   Copyright (C) Petr Cech <pcech@redhat.com> 2015

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

#include "sss_client/sss_cli.h"
#include "util/sss_cli_cmd.h"
#include "util/util.h"

const char *sss_cmd2str(enum sss_cli_command cmd)
{
    switch (cmd) {
    /* null */
    case SSS_CLI_NULL:
        return "SSS_CLI_NULL";

    /* version */
    case SSS_GET_VERSION:
        return "SSS_GET_VERSION";

    /* passwd */
    case SSS_NSS_GETPWNAM:
        return "SSS_NSS_GETPWNAM";
    case SSS_NSS_GETPWUID:
        return "SSS_NSS_GETPWUID";
    case SSS_NSS_SETPWENT:
        return "SSS_NSS_SETPWENT";
    case SSS_NSS_GETPWENT:
        return "SSS_NSS_GETPWENT";
    case SSS_NSS_ENDPWENT:
        return "SSS_NSS_ENDPWENT";

    /* group */
    case SSS_NSS_GETGRNAM:
        return "SSS_NSS_GETGRNAM";
    case SSS_NSS_GETGRGID:
        return "SSS_NSS_GETGRGID";
    case SSS_NSS_SETGRENT:
        return "SSS_NSS_SETGRENT";
    case SSS_NSS_GETGRENT:
        return "SSS_NSS_GETGRENT";
    case SSS_NSS_ENDGRENT:
        return "SSS_NSS_ENDGRENT";
    case SSS_NSS_INITGR:
        return "SSS_NSS_INITGR";

#if 0
    /* aliases */
    case SSS_NSS_GETALIASBYNAME:
        return "SSS_NSS_GETALIASBYNAME";
    case SSS_NSS_GETALIASBYPORT:
        return "SSS_NSS_GETALIASBYPORT";
    case SSS_NSS_SETALIASENT:
        return "SSS_NSS_SETALIASENT";
    case SSS_NSS_GETALIASENT:
        return "SSS_NSS_GETALIASENT";
    case SSS_NSS_ENDALIASENT:
        return "SSS_NSS_ENDALIASENT";

    /* ethers */
    case SSS_NSS_GETHOSTTON:
        return "SSS_NSS_GETHOSTTON";
    case SSS_NSS_GETNTOHOST:
        return "SSS_NSS_GETNTOHOST";
    case SSS_NSS_SETETHERENT:
        return "SSS_NSS_SETETHERENT";
    case SSS_NSS_GETETHERENT:
        return "SSS_NSS_GETETHERENT";
    case SSS_NSS_ENDETHERENT:
        return "SSS_NSS_ENDETHERENT";

#endif
    /* hosts */
    case SSS_NSS_GETHOSTBYNAME:
        return "SSS_NSS_GETHOSTBYNAME";
    case SSS_NSS_GETHOSTBYNAME2:
        return "SSS_NSS_GETHOSTBYNAME2";
    case SSS_NSS_GETHOSTBYADDR:
        return "SSS_NSS_GETHOSTBYADDR";
    case SSS_NSS_SETHOSTENT:
        return "SSS_NSS_SETHOSTENT";
    case SSS_NSS_GETHOSTENT:
        return "SSS_NSS_GETHOSTENT";
    case SSS_NSS_ENDHOSTENT:
        return "SSS_NSS_ENDHOSTENT";

    /* netgroup */
    case SSS_NSS_SETNETGRENT:
        return "SSS_NSS_SETNETGRENT";
    case SSS_NSS_GETNETGRENT:
        return "SSS_NSS_GETNETGRENT";
    case SSS_NSS_ENDNETGRENT:
        return "SSS_NSS_ENDNETGRENT";

    /* networks */
    case SSS_NSS_GETNETBYNAME:
        return "SSS_NSS_GETNETBYNAME";
    case SSS_NSS_GETNETBYADDR:
        return "SSS_NSS_GETNETBYADDR";
    case SSS_NSS_SETNETENT:
        return "SSS_NSS_SETNETENT";
    case SSS_NSS_GETNETENT:
        return "SSS_NSS_GETNETENT";
    case SSS_NSS_ENDNETENT:
        return "SSS_NSS_ENDNETENT";

#if 0
    /* protocols */
    case SSS_NSS_GETPROTOBYNAME:
        return "SSS_NSS_GETPROTOBYNAME";
    case SSS_NSS_GETPROTOBYNUM:
        return "SSS_NSS_GETPROTOBYNUM";
    case SSS_NSS_SETPROTOENT:
        return "SSS_NSS_SETPROTOENT";
    case SSS_NSS_GETPROTOENT:
        return "SSS_NSS_GETPROTOENT";
    case SSS_NSS_ENDPROTOENT:
        return "SSS_NSS_ENDPROTOENT";

    /* rpc */
    case SSS_NSS_GETRPCBYNAME:
        return "SSS_NSS_GETRPCBYNAME";
    case SSS_NSS_GETRPCBYNUM:
        return "SSS_NSS_GETRPCBYNUM";
    case SSS_NSS_SETRPCENT:
        return "SSS_NSS_SETRPCENT";
    case SSS_NSS_GETRPCENT:
        return "SSS_NSS_GETRPCENT";
    case SSS_NSS_ENDRPCENT:
        return "SSS_NSS_ENDRPCENT";
#endif

    /* services */
    case SSS_NSS_GETSERVBYNAME:
        return "SSS_NSS_GETSERVBYNAME";
    case SSS_NSS_GETSERVBYPORT:
        return "SSS_NSS_GETSERVBYPORT";
    case SSS_NSS_SETSERVENT:
        return "SSS_NSS_SETSERVENT";
    case SSS_NSS_GETSERVENT:
        return "SSS_NSS_GETSERVENT";
    case SSS_NSS_ENDSERVENT:
        return "SSS_NSS_ENDSERVENT";

#if 0
    /* shadow */
    case SSS_NSS_GETSPNAM:
        return "SSS_NSS_GETSPNAM";
    case SSS_NSS_GETSPUID:
        return "SSS_NSS_GETSPUID";
    case SSS_NSS_SETSPENT:
        return "SSS_NSS_SETSPENT";
    case SSS_NSS_GETSPENT:
        return "SSS_NSS_GETSPENT";
    case SSS_NSS_ENDSPENT:
        return "SSS_NSS_ENDSPENT";
#endif

    /* SUDO */
    case SSS_SUDO_GET_SUDORULES:
        return "SSS_SUDO_GET_SUDORULES";
    case SSS_SUDO_GET_DEFAULTS:
        return "SSS_SUDO_GET_DEFAULTS";

    /* autofs */
    case SSS_AUTOFS_SETAUTOMNTENT:
        return "SSS_AUTOFS_SETAUTOMNTENT";
    case SSS_AUTOFS_GETAUTOMNTENT:
        return "SSS_AUTOFS_GETAUTOMNTENT";
    case SSS_AUTOFS_GETAUTOMNTBYNAME:
        return "SSS_AUTOFS_GETAUTOMNTBYNAME";
    case SSS_AUTOFS_ENDAUTOMNTENT:
        return "SSS_AUTOFS_ENDAUTOMNTENT";

    /* SSH */
    case SSS_SSH_GET_USER_PUBKEYS:
        return "SSS_SSH_GET_USER_PUBKEYS";
    case SSS_SSH_GET_HOST_PUBKEYS:
        return "SSS_SSH_GET_HOST_PUBKEYS";

    /* PAM related calls */
    case SSS_PAM_AUTHENTICATE:
        return "SSS_PAM_AUTHENTICATE";
    case SSS_PAM_SETCRED:
        return "SSS_PAM_SETCRED";
    case SSS_PAM_ACCT_MGMT:
        return "SSS_PAM_ACCT_MGMT";
    case SSS_PAM_OPEN_SESSION:
        return "SSS_PAM_OPEN_SESSION";
    case SSS_PAM_CLOSE_SESSION:
        return "SSS_PAM_CLOSE_SESSION";
    case SSS_PAM_CHAUTHTOK:
        return "SSS_PAM_CHAUTHTOK";
    case SSS_PAM_CHAUTHTOK_PRELIM:
        return "SSS_PAM_CHAUTHTOK_PRELIM";
    case SSS_CMD_RENEW:
        return "SSS_CMD_RENEW";
    case SSS_PAM_PREAUTH:
        return "SSS_PAM_PREAUTH";

    /* PAC responder calls */
    case SSS_PAC_ADD_PAC_USER:
        return "SSS_PAC_ADD_PAC_USER";

    /* ID-SID mapping calls */
    case SSS_NSS_GETSIDBYNAME:
        return "SSS_NSS_GETSIDBYNAME";
    case SSS_NSS_GETSIDBYID:
        return "SSS_NSS_GETSIDBYID";
    case SSS_NSS_GETNAMEBYSID:
        return "SSS_NSS_GETNAMEBYSID";
    case SSS_NSS_GETIDBYSID:
        return "SSS_NSS_GETIDBYSID";
    case SSS_NSS_GETORIGBYNAME:
        return "SSS_NSS_GETORIGBYNAME";
    case SSS_NSS_GETORIGBYUSERNAME:
        return "SSS_NSS_GETORIGBYUSERNAME";
    case SSS_NSS_GETORIGBYGROUPNAME:
        return "SSS_NSS_GETORIGBYGROUPNAME";

    /* SUBID ranges */
    case SSS_NSS_GET_SUBID_RANGES:
        return "SSS_NSS_GET_SUBID_RANGES";

    default:
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Translation's string is missing for command [%#x].\n", cmd);
        return "UNKNOWN COMMAND";
    }
}
