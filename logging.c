/*
 * Syslog logging.
 *
 * Functions to log informational and warning messages through syslog.  There
 * are cases, such as when we queue changes, where we want to log the reason
 * but return success to kadmind or kpasswdd, which means that they won't log
 * anything.  In those cases, we log directly to syslog unless the syslog
 * configuration option is set to false.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <ldap.h>
#include <krb5/kadm5_hook_plugin.h>
#include <syslog.h>
#include "krb5sync.h"
#include "logerr.h"



/*
 * Log a message to syslog.  This is a helper function used to implement all
 * of the syslog logging functions.  If we can't allocate memory for the
 * message to log, we just do nothing, since these functions are only used for
 * supplemental logging.
 */
static void
log_syslog(kadm5_hook_modinfo *modinfo, int priority, const char *fmt,
           va_list args)
{
    char *message;
    int status;

    struct k5scfg * cx = (struct k5scfg*)modinfo;

    /* If configured not to log, do nothing. */
    if (cx->syslog == NULL)
        return;

    /* Log the message. */
    status = vasprintf(&message, fmt, args);
    if (status < 0)
        return;
    syslog(priority, "%s", message);
    free(message);
}


/*
 * Generate the functions for the various priority levels we use.
 */
#define SYSLOG_FUNCTION(name, type)                                     \
    void                                                                \
    sync_syslog_ ## name(kadm5_hook_modinfo *c, const char *f, ...)     \
    {                                                                   \
        va_list args;                                                   \
        va_start(args, f);                                              \
        log_syslog(c, LOG_ ## type, f, args);                           \
        va_end(args);                                                   \
    }
SYSLOG_FUNCTION(debug,   DEBUG)
SYSLOG_FUNCTION(info,    INFO)
SYSLOG_FUNCTION(notice,  NOTICE)
SYSLOG_FUNCTION(warning, WARNING)
