#ifndef _SSSD_I18N_H
#define _SSSD_I18N_H

#include <locale.h>
#include <libintl.h>
#define _(STRING) gettext (STRING)
#include "config.h"

#endif
