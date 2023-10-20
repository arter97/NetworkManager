/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2015 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nms-keyfile-writer.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#if WITH_NETPLAN
#include <net/if.h>
#include <netplan/parse.h>
#include <netplan/parse-nm.h>
#include <netplan/util.h>
#include <netplan/netplan.h>
#endif

#include "libnm-core-intern/nm-keyfile-internal.h"

#include "nms-keyfile-utils.h"
#include "nms-keyfile-reader.h"

#include "libnm-glib-aux/nm-io-utils.h"

/*****************************************************************************/

typedef struct {
    const char *keyfile_dir;
} WriteInfo;

static void
cert_writer(NMConnection                     *connection,
            GKeyFile                         *file,
            NMSetting8021x                   *setting,
            const NMSetting8021xSchemeVtable *vtable,
            WriteInfo                        *info,
            GError                          **error)
{
    const char            *setting_name = nm_setting_get_name(NM_SETTING(setting));
    NMSetting8021xCKScheme scheme;
    NMSetting8021xCKFormat format;
    const char            *path = NULL, *ext = "pem";

    scheme = vtable->scheme_func(setting);
    if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
        char       *tmp           = NULL;
        const char *accepted_path = NULL;

        path = vtable->path_func(setting);
        g_assert(path);

        if (g_str_has_prefix(path, info->keyfile_dir)) {
            const char *p = path + strlen(info->keyfile_dir);

            /* If the path is rooted in the keyfile directory, just use a
             * relative path instead of an absolute one.
             */
            if (*p == '/') {
                while (*p == '/')
                    p++;
                if (p[0]) {
                    /* If @p looks like an integer list, the following detection will fail too and
                     * we will file:// qualify the path below. We thus avoid writing a path string
                     * that would be interpreted as legacy binary format by reader. */
                    tmp = nm_keyfile_detect_unqualified_path_scheme(info->keyfile_dir,
                                                                    p,
                                                                    -1,
                                                                    FALSE,
                                                                    NULL);
                    if (tmp) {
                        nm_clear_g_free(&tmp);
                        accepted_path = p;
                    }
                }
            }
        }
        if (!accepted_path) {
            /* What we are about to write, must also be understood by the reader.
             * Otherwise, add a file:// prefix */
            tmp =
                nm_keyfile_detect_unqualified_path_scheme(info->keyfile_dir, path, -1, FALSE, NULL);
            if (tmp) {
                nm_clear_g_free(&tmp);
                accepted_path = path;
            }
        }

        if (!accepted_path)
            accepted_path = tmp = g_strconcat(NM_KEYFILE_CERT_SCHEME_PREFIX_PATH, path, NULL);
        nm_keyfile_plugin_kf_set_string(file, setting_name, vtable->setting_key, accepted_path);
        g_free(tmp);
    } else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PKCS11) {
        nm_keyfile_plugin_kf_set_string(file,
                                        setting_name,
                                        vtable->setting_key,
                                        vtable->uri_func(setting));
    } else if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
        GBytes       *blob;
        const guint8 *blob_data;
        gsize         blob_len;
        gboolean      success;
        GError       *local = NULL;
        char         *new_path;

        blob = vtable->blob_func(setting);
        g_assert(blob);
        blob_data = g_bytes_get_data(blob, &blob_len);

        if (vtable->format_func) {
            /* Get the extension for a private key */
            format = vtable->format_func(setting);
            if (format == NM_SETTING_802_1X_CK_FORMAT_PKCS12)
                ext = "p12";
        } else {
            /* DER or PEM format certificate? */
            if (blob_len > 2 && blob_data[0] == 0x30 && blob_data[1] == 0x82)
                ext = "der";
        }

        /* Write the raw data out to the standard file so that we can use paths
         * from now on instead of pushing around the certificate data.
         */
        new_path = g_strdup_printf("%s/%s-%s.%s",
                                   info->keyfile_dir,
                                   nm_connection_get_uuid(connection),
                                   vtable->file_suffix,
                                   ext);

        /* FIXME(keyfile-parse-in-memory): writer must not access/write to the file system before
         * being sure that the entire profile can be written and all circumstances are good to
         * proceed. That means, while writing we must only collect the blobs in-memory, and write
         * them all in the end together (or not at all). */
        success = nm_utils_file_set_contents(new_path,
                                             (const char *) blob_data,
                                             blob_len,
                                             0600,
                                             NULL,
                                             NULL,
                                             &local);
        if (success) {
            /* Write the path value to the keyfile.
             * We know, that basename(new_path) starts with a UUID, hence no conflict with "data:;base64,"  */
            nm_keyfile_plugin_kf_set_string(file,
                                            setting_name,
                                            vtable->setting_key,
                                            strrchr(new_path, '/') + 1);
        } else {
            nm_log_warn(LOGD_SETTINGS,
                        "keyfile: %s.%s: failed to write certificate to file %s: %s",
                        setting_name,
                        vtable->setting_key,
                        new_path,
                        local->message);
            g_error_free(local);
        }
        g_free(new_path);
    } else {
        /* scheme_func() returns UNKNOWN in all other cases. The only valid case
         * where a scheme is allowed to be UNKNOWN, is unsetting the value. In this
         * case, we don't expect the writer to be called, because the default value
         * will not be serialized.
         * The only other reason for the scheme to be UNKNOWN is an invalid cert.
         * But our connection verifies, so that cannot happen either. */
        g_return_if_reached();
    }
}

static gboolean
_handler_write(NMConnection         *connection,
               GKeyFile             *keyfile,
               NMKeyfileHandlerType  type,
               NMKeyfileHandlerData *type_data,
               void                 *user_data)
{
    if (type == NM_KEYFILE_HANDLER_TYPE_WRITE_CERT) {
        cert_writer(connection,
                    keyfile,
                    NM_SETTING_802_1X(type_data->cur_setting),
                    type_data->write_cert.vtable,
                    user_data,
                    type_data->p_error);
        return TRUE;
    }
    return FALSE;
}

static gboolean
_internal_write_connection(NMConnection                   *connection,
                           gboolean                        is_nm_generated,
                           gboolean                        is_volatile,
                           gboolean                        is_external,
                           const char                     *shadowed_storage,
                           gboolean                        shadowed_owned,
                           const char                     *keyfile_dir,
                           const char                     *profile_dir,
                           gboolean                        with_extension,
                           uid_t                           owner_uid,
                           pid_t                           owner_grp,
                           const char                     *existing_path,
                           gboolean                        existing_path_read_only,
                           NMTernary                       force_rename,
                           NMSKeyfileWriterAllowFilenameCb allow_filename_cb,
                           gpointer                        allow_filename_user_data,
                           char                          **out_path,
                           NMConnection                  **out_reread,
                           gboolean                       *out_reread_same,
                           #if WITH_NETPLAN
                           const char                     *rootdir,
                           #endif
                           GError                        **error)
{
    nm_auto_unref_keyfile GKeyFile *kf_file        = NULL;
    gs_free char                   *kf_content_buf = NULL;
    gsize                           kf_content_len;
    gs_free char                   *path = NULL;
    const char                     *id;
    WriteInfo                       info      = {0};
    gs_free_error GError           *local_err = NULL;
    int                             errsv;
    gboolean                        rename;
    gboolean                        rename_follow;
    int                             i_path;
    gs_unref_object NMConnection   *reread      = NULL;
    gboolean                        reread_same = FALSE;

    g_return_val_if_fail(!out_path || !*out_path, FALSE);
    g_return_val_if_fail(keyfile_dir && keyfile_dir[0] == '/', FALSE);

    nm_assert(_nm_connection_verify(connection, NULL) == NM_SETTING_VERIFY_SUCCESS);

    nm_assert(!shadowed_owned || shadowed_storage);

    rename = existing_path_read_only
             || (existing_path && !nm_utils_file_is_in_path(existing_path, keyfile_dir))
             || force_rename == NM_TERNARY_TRUE;

    /* Follow the connection.id upon change. */
    rename_follow = !rename && existing_path && force_rename == NM_TERNARY_DEFAULT;

    id = nm_connection_get_id(connection);
    nm_assert(id && *id);

    info.keyfile_dir = keyfile_dir;

    kf_file =
        nm_keyfile_write(connection, NM_KEYFILE_HANDLER_FLAGS_NONE, _handler_write, &info, error);
    if (!kf_file)
        return FALSE;

    if (is_nm_generated) {
        g_key_file_set_boolean(kf_file,
                               NM_KEYFILE_GROUP_NMMETA,
                               NM_KEYFILE_KEY_NMMETA_NM_GENERATED,
                               TRUE);
    }

    if (is_volatile) {
        g_key_file_set_boolean(kf_file,
                               NM_KEYFILE_GROUP_NMMETA,
                               NM_KEYFILE_KEY_NMMETA_VOLATILE,
                               TRUE);
    }

    if (is_external) {
        g_key_file_set_boolean(kf_file,
                               NM_KEYFILE_GROUP_NMMETA,
                               NM_KEYFILE_KEY_NMMETA_EXTERNAL,
                               TRUE);
    }

    if (shadowed_storage) {
        g_key_file_set_string(kf_file,
                              NM_KEYFILE_GROUP_NMMETA,
                              NM_KEYFILE_KEY_NMMETA_SHADOWED_STORAGE,
                              shadowed_storage);
    }

    if (shadowed_owned) {
        g_key_file_set_boolean(kf_file,
                               NM_KEYFILE_GROUP_NMMETA,
                               NM_KEYFILE_KEY_NMMETA_SHADOWED_OWNED,
                               TRUE);
    }

    kf_content_buf = g_key_file_to_data(kf_file, &kf_content_len, error);
    if (!kf_content_buf)
        return FALSE;

    if (!g_file_test(keyfile_dir, G_FILE_TEST_IS_DIR))
        (void) g_mkdir_with_parents(keyfile_dir, 0755);

    for (i_path = -2; i_path < 10000; i_path++) {
        gs_free char *path_candidate = NULL;
        gboolean      is_existing_path;

        if (i_path == -2) {
            if (!existing_path || rename || rename_follow)
                continue;
            path_candidate = g_strdup(existing_path);
        } else if (i_path == -1) {
            gs_free char *filename_escaped = NULL;

            filename_escaped = nm_keyfile_utils_create_filename(id, with_extension);
            path_candidate   = g_build_filename(keyfile_dir, filename_escaped, NULL);
        } else {
            gs_free char *filename_escaped = NULL;
            gs_free char *filename         = NULL;

            if (i_path == 0)
                filename = g_strdup_printf("%s-%s", id, nm_connection_get_uuid(connection));
            else
                filename =
                    g_strdup_printf("%s-%s-%d", id, nm_connection_get_uuid(connection), i_path);

            filename_escaped = nm_keyfile_utils_create_filename(filename, with_extension);

            path_candidate = g_strdup_printf("%s/%s", keyfile_dir, filename_escaped);
        }

        is_existing_path = existing_path && nm_streq(existing_path, path_candidate);

        if (is_existing_path && rename)
            continue;

        if (allow_filename_cb && !allow_filename_cb(path_candidate, allow_filename_user_data))
            continue;

        if (!is_existing_path) {
            if (g_file_test(path_candidate, G_FILE_TEST_EXISTS))
                continue;
        }

        path = g_steal_pointer(&path_candidate);
        break;
    }

    if (!path) {
        gs_free char *ss = NULL;

        /* this really should not happen, we tried hard to find an unused name... bail out. */
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "could not find suitable keyfile file name (%s already used)",
                    ss = ({
                        gs_free char *filename_escaped = NULL;

                        filename_escaped = nm_keyfile_utils_create_filename(id, with_extension);
                        g_build_filename(keyfile_dir, filename_escaped, NULL);
                    }));

        return FALSE;
    }

    if (out_reread || out_reread_same) {
        gs_free_error GError *reread_error = NULL;

        reread =
            nms_keyfile_reader_from_keyfile(kf_file, path, NULL, profile_dir, FALSE, &reread_error);

        if (!reread || !nm_connection_normalize(reread, NULL, NULL, &reread_error)) {
            nm_log_err(
                LOGD_SETTINGS,
                "BUG: the profile cannot be stored in keyfile format without becoming unusable: %s",
                reread_error->message);
            g_set_error(error,
                        NM_SETTINGS_ERROR,
                        NM_SETTINGS_ERROR_FAILED,
                        "keyfile writer produces an invalid connection: %s",
                        reread_error->message);
            nm_assert_not_reached();
            return FALSE;
        }

        if (out_reread_same) {
            reread_same =
                !!nm_connection_compare(reread, connection, NM_SETTING_COMPARE_FLAG_EXACT);

            nm_assert(reread_same
                      == nm_connection_compare(connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));
            nm_assert(reread_same == ({
                          gs_unref_hashtable GHashTable *_settings = NULL;

                          (nm_connection_diff(reread,
                                              connection,
                                              NM_SETTING_COMPARE_FLAG_EXACT,
                                              &_settings)
                           && !_settings);
                      }));
        }
    }

    nm_utils_file_set_contents(path, kf_content_buf, kf_content_len, 0600, NULL, NULL, &local_err);
    if (local_err) {
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "error writing to file '%s': %s",
                    path,
                    local_err->message);
        return FALSE;
    }

    if (chown(path, owner_uid, owner_grp) < 0) {
        errsv = errno;
        g_set_error(error,
                    NM_SETTINGS_ERROR,
                    NM_SETTINGS_ERROR_FAILED,
                    "error chowning '%s': %s (%d)",
                    path,
                    nm_strerror_native(errsv),
                    errsv);
        unlink(path);
        return FALSE;
    }

    /* In case of updating the connection and changing the file path,
     * we need to remove the old one, not to end up with two connections.
     */
    if (existing_path && !existing_path_read_only && !nm_streq(path, existing_path))
        unlink(existing_path);

    #if WITH_NETPLAN
    NetplanParser *npp      = NULL;
    NetplanState  *np_state = NULL;

    /* NETPLAN: write only non-temporary files to /etc/netplan/... */
    if (!is_volatile && !is_nm_generated && !is_external &&
        strstr(keyfile_dir, "/etc/NetworkManager/system-connections")) {
        g_autofree gchar *ssid = g_key_file_get_string(kf_file, "wifi", "ssid", NULL);
        g_autofree gchar *escaped_ssid = ssid ?
                                         g_uri_escape_string(ssid, NULL, TRUE) : NULL;
        g_autofree gchar *netplan_id = NULL;
        ssize_t netplan_id_size = 0;
        NetplanNetDefinition *netdef = NULL;
        NetplanStateIterator state_iter;
        const gchar* kf_path = path;

        if (existing_path && strstr(existing_path, "system-connections/netplan-")) {
            netplan_id = g_malloc0(strlen(existing_path));
            netplan_id_size = netplan_get_id_from_nm_filepath(existing_path, ssid, netplan_id, strlen(existing_path) - 1);
            if (netplan_id_size <= 0) {
                g_free(netplan_id);
                netplan_id = NULL;
            }
        }

        if (netplan_id && existing_path) {
            GFile* from = g_file_new_for_path(path);
            GFile* to = g_file_new_for_path(existing_path);
            g_file_copy(from, to, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL, NULL);
            kf_path = existing_path;
        }

        // push keyfile into libnetplan for parsing (using existing_path, if available,
        // to be able to extract the original netdef_id and override existing settings)
        npp = netplan_parser_new();

        if (!netplan_parser_load_keyfile(npp, kf_path, &local_err)) {
            g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
                         "netplan: YAML translation failed: %s", local_err->message);
            goto netplan_parser_error;
        }

        np_state = netplan_state_new();
        if (!netplan_state_import_parser_results(np_state, npp, &local_err)) {
            g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
                         "netplan: YAML validation failed: %s", local_err->message);
            goto netplan_error;
        }

        netplan_state_iterator_init(np_state, &state_iter);
        /* At this point we have a single netdef in the netplan state */
        netdef = netplan_state_iterator_next(&state_iter);

        if (!netdef) {
            g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
                         "netplan: Netplan state has no network definitions");
            goto netplan_error;
        }

        if (!netplan_netdef_write_yaml(np_state, netdef, rootdir, &local_err)) {
            g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
                         "netplan: Failed to generate YAML: %s", local_err->message);
            goto netplan_error;
        }

        /* Delete same connection-profile provided by legacy netplan plugin.
         * TODO: drop legacy connection handling after 24.04 LTS */
        g_autofree gchar* legacy_path = NULL;
        legacy_path = g_strdup_printf("/etc/netplan/NM-%s.yaml", nm_connection_get_uuid (connection));
        if (g_file_test(legacy_path, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
            g_debug("Deleting legacy netplan connection: %s", legacy_path);
            unlink(legacy_path);
        }

        /* Clear original keyfile in /etc/NetworkManager/system-connections/,
         * we've written the /etc/netplan/*.yaml file instead. */
        unlink(path);
        if (!generate_netplan(rootdir)) {
            g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
                         "netplan generate failed");
            goto netplan_error;
        }

        // Calculating the maximum space needed to store the new keyfile path
        ssize_t path_size = strlen(path) + strlen(nm_connection_get_uuid(connection)) + IF_NAMESIZE + 1;
        if (escaped_ssid)
            path_size += strlen(escaped_ssid);
        path_size += 50; // give some extra buffer, e.g. when going from  ConName to ConName.nmconnection

        g_free(path);
        path = g_malloc0(path_size);
        path_size = netplan_netdef_get_output_filename(netdef, ssid, path, path_size);

        if (path_size <= 0) {
            g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
                         "netplan: couldn't determine the keyfile path");
            goto netplan_error;
        }

        if (rootdir) {
            char* final_path = g_build_path(G_DIR_SEPARATOR_S, rootdir, path, NULL);
            g_free(path);
            path = final_path;
        }

        netplan_state_clear(&np_state);
        netplan_parser_clear(&npp);

        /* re-read again: this time the connection profile newly generated by netplan in /run/... */
        if (   out_reread
            || out_reread_same) {
            gs_free_error GError *reread_error = NULL;

            //XXX: why does the _from_keyfile function behave differently?
            //reread = nms_keyfile_reader_from_keyfile (kf_file, path, NULL, profile_dir, FALSE, &reread_error);
            reread = nms_keyfile_reader_from_file (path, profile_dir, NULL, NULL, NULL, NULL, NULL, NULL, &reread_error);

            if (   !reread
                || !nm_connection_normalize (reread, NULL, NULL, &reread_error)) {
                nm_log_err (LOGD_SETTINGS, "BUG: the profile cannot be stored in keyfile format without becoming unusable: %s", reread_error->message);
                g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
                             "keyfile writer produces an invalid connection: %s",
                             reread_error->message);
                nm_assert_not_reached ();
                return FALSE;
            }

            if (out_reread_same) {
                reread_same = !!nm_connection_compare (reread, connection, NM_SETTING_COMPARE_FLAG_EXACT);

                nm_assert (reread_same == nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));
                nm_assert (reread_same == ({
                                                gs_unref_hashtable GHashTable *_settings = NULL;

                                                (   nm_connection_diff (reread, connection, NM_SETTING_COMPARE_FLAG_EXACT, &_settings)
                                                 && !_settings);
                                           }));
            }
        }
    }
    #endif

    NM_SET_OUT(out_reread, g_steal_pointer(&reread));
    NM_SET_OUT(out_reread_same, reread_same);
    NM_SET_OUT(out_path, g_steal_pointer(&path));

    return TRUE;

#if WITH_NETPLAN
netplan_error:
    netplan_state_clear(&np_state);
netplan_parser_error:
    netplan_parser_clear(&npp);
    return FALSE;
#endif
}

gboolean
nms_keyfile_writer_connection(NMConnection                   *connection,
                              gboolean                        is_nm_generated,
                              gboolean                        is_volatile,
                              gboolean                        is_external,
                              const char                     *shadowed_storage,
                              gboolean                        shadowed_owned,
                              const char                     *keyfile_dir,
                              const char                     *profile_dir,
                              const char                     *existing_path,
                              gboolean                        existing_path_read_only,
                              NMTernary                       force_rename,
                              NMSKeyfileWriterAllowFilenameCb allow_filename_cb,
                              gpointer                        allow_filename_user_data,
                              char                          **out_path,
                              NMConnection                  **out_reread,
                              gboolean                       *out_reread_same,
                              GError                        **error)
{
    return _internal_write_connection(connection,
                                      is_nm_generated,
                                      is_volatile,
                                      is_external,
                                      shadowed_storage,
                                      shadowed_owned,
                                      keyfile_dir,
                                      profile_dir,
                                      TRUE,
                                      nm_utils_get_nm_uid(),
                                      nm_utils_get_nm_gid(),
                                      existing_path,
                                      existing_path_read_only,
                                      force_rename,
                                      allow_filename_cb,
                                      allow_filename_user_data,
                                      out_path,
                                      out_reread,
                                      out_reread_same,
                                      #if WITH_NETPLAN
                                      NULL,
                                      #endif
                                      error);
}

gboolean
nmtst_keyfile_writer_test_connection(NMConnection  *connection,
                                     const char    *keyfile_dir,
                                     uid_t          owner_uid,
                                     pid_t          owner_grp,
                                     char         **out_path,
                                     NMConnection **out_reread,
                                     gboolean      *out_reread_same,
                                     GError       **error)
{
    #if WITH_NETPLAN
    gchar *rootdir = g_strdup(keyfile_dir);
    if (g_str_has_suffix (keyfile_dir, "/run/NetworkManager/system-connections")) {
        rootdir[strlen(rootdir)-38] = '\0'; /* 38 = strlen("/run/NetworkManager/...") */
    }
    #endif
    return _internal_write_connection(connection,
                                      FALSE,
                                      FALSE,
                                      FALSE,
                                      NULL,
                                      FALSE,
                                      keyfile_dir,
                                      keyfile_dir,
                                      FALSE,
                                      owner_uid,
                                      owner_grp,
                                      NULL,
                                      FALSE,
                                      FALSE,
                                      NULL,
                                      NULL,
                                      out_path,
                                      out_reread,
                                      out_reread_same,
                                      #if WITH_NETPLAN
                                      rootdir,
                                      #endif
                                      error);
}
