#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>


/*
 * Store a configuration, generic, or system error in the Kerberos context,
 * appending the strerror results to the message in the _system case and the
 * LDAP error string in the _ldap case.  Returns the error code set.
 */
krb5_error_code sync_error_config(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code sync_error_generic(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code sync_error_ldap(krb5_context, int, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 3, 4)));
krb5_error_code sync_error_system(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));

/* Log messages to syslog if configured to do so. */
void sync_syslog_debug(kadm5_hook_modinfo *, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
void sync_syslog_info(kadm5_hook_modinfo *, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
void sync_syslog_notice(kadm5_hook_modinfo *, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
void sync_syslog_warning(kadm5_hook_modinfo *, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));

