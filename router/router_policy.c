
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/wait.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#define API "https://nubeware.ai/api/sd_security/firewall/policy"
#define CA "/etc/ssl/certs/ca-certificates.crt"
#define POLICY "/tmp/nubeware-policy.json"
#define STATE "/etc/nubeware-domains"
#define BACKUP "/tmp/nubeware-dhcp.backup"

#define MAX_DOMAINS 32
#define MAX_DOMAIN_LEN 253

struct domain_list {
    char domain[MAX_DOMAINS][MAX_DOMAIN_LEN + 1];
    int count;
};


struct wifi_settings {
    int present;
    int enabled;
    int channel;
    char ssid[33];
    char password[64];
};


static int execute(const char *const args[])
{
    pid_t pid = fork();
    int status;

    if (pid < 0)
        return -1;

    if (pid == 0) {
        execvp(args[0], (char *const *)args);
        _exit(127);
    }

    if (waitpid(pid, &status, 0) < 0)
        return -1;

    return WIFEXITED(status) &&
           WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int valid_domain(const char *s)
{
    size_t len = strlen(s);
    size_t label = 0;
    int dots = 0;

    if (len < 3 || len > MAX_DOMAIN_LEN)
        return 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = s[i];

        if (c == '.') {
            if (!label || label > 63 || s[i - 1] == '-')
                return 0;
            dots++;
            label = 0;
        } else {
            if (!(c >= 'a' && c <= 'z') &&
                !(c >= '0' && c <= '9') &&
                c != '-')
                return 0;

            if (label == 0 && c == '-')
                return 0;

            label++;
        }
    }

    return dots > 0 && label > 0 &&
           label <= 63 && s[len - 1] != '-';
}

static int add_domain(struct domain_list *list,
                      const char *domain)
{
    if (!valid_domain(domain))
        return -1;

    for (int i = 0; i < list->count; i++)
        if (!strcmp(list->domain[i], domain))
            return 0;

    if (list->count >= MAX_DOMAINS)
        return -1;

    strcpy(list->domain[list->count++], domain);
    return 0;
}

static int compare_domains(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static void sort_domains(struct domain_list *list)
{
    qsort(list->domain, list->count,
          sizeof(list->domain[0]), compare_domains);
}

static int same_domains(const struct domain_list *a,
                        const struct domain_list *b)
{
    if (a->count != b->count)
        return 0;

    for (int i = 0; i < a->count; i++)
        if (strcmp(a->domain[i], b->domain[i]))
            return 0;

    return 1;
}

static int download_policy(void)
{
    const char *const args[] = {
        "wget",
        "--user=wr940n-001",
        "--password=Dali12345",
        "--ca-certificate=" CA,
        "--timeout=20",
        "-O", POLICY,
        API,
        NULL
    };

    return execute(args);
}

static int parse_wifi(struct blob_attr *root,
                      struct wifi_settings *wifi)
{
    enum {
        W_ENABLED,
        W_SSID,
        W_PASSWORD,
        W_CHANNEL,
        W_ENCRYPTION,
        W_MAX
    };

    static const struct blobmsg_policy fields[W_MAX] = {
        [W_ENABLED] = {"enabled", BLOBMSG_TYPE_BOOL},
        [W_SSID] = {"ssid", BLOBMSG_TYPE_STRING},
        [W_PASSWORD] = {"password", BLOBMSG_TYPE_STRING},
        [W_CHANNEL] = {"channel", BLOBMSG_TYPE_INT32},
        [W_ENCRYPTION] = {"encryption", BLOBMSG_TYPE_STRING}
    };

    static const struct blobmsg_policy root_fields[] = {
        {"wifi", BLOBMSG_TYPE_TABLE}
    };

    struct blob_attr *root_tb[1] = {0};
    struct blob_attr *tb[W_MAX] = {0};

    blobmsg_parse(root_fields, 1, root_tb,
                  blobmsg_data(root),
                  blobmsg_data_len(root));

    if (!root_tb[0])
        return 0; /* Wi-Fi no especificado */

    blobmsg_parse(fields, W_MAX, tb,
                  blobmsg_data(root_tb[0]),
                  blobmsg_data_len(root_tb[0]));

    for (int i = 0; i < W_MAX; i++)
        if (!tb[i])
            return -1;

    const char *ssid = blobmsg_get_string(tb[W_SSID]);
    const char *key = blobmsg_get_string(tb[W_PASSWORD]);
    const char *enc = blobmsg_get_string(tb[W_ENCRYPTION]);

    size_t slen = strlen(ssid);
    size_t klen = strlen(key);

    if (slen < 1 || slen > 32 ||
        klen < 8 || klen > 63 ||
        strcmp(enc, "psk2") != 0)
        return -1;

    for (size_t i = 0; i < slen; i++)
        if ((unsigned char)ssid[i] < 32)
            return -1;

    for (size_t i = 0; i < klen; i++)
        if ((unsigned char)key[i] < 32)
            return -1;

    int channel = (int)blobmsg_get_u32(tb[W_CHANNEL]);
    if (channel < 1 || channel > 11)
        return -1;

    wifi->present = 1;
    wifi->enabled = blobmsg_get_bool(tb[W_ENABLED]);
    wifi->channel = channel;

    strcpy(wifi->ssid, ssid);
    strcpy(wifi->password, key);

    return 0;
}


static int parse_policy(struct domain_list *list,struct wifi_settings *wifi)
{
    FILE *f = fopen(POLICY, "rb");
    char json[8192];
    size_t n;

    if (!f)
        return -1;

    n = fread(json, 1, sizeof(json) - 1, f);
    if (ferror(f) || !feof(f)) {
        fclose(f);
        return -1;
    }

    fclose(f);
    json[n] = '\0';

    struct blob_buf b = {};
    blob_buf_init(&b, 0);

    if (!blobmsg_add_json_from_string(&b, json)) {
        blob_buf_free(&b);
        return -1;
    }

enum {
    POLICY_REVISION,
    POLICY_DOMAINS,
    __POLICY_MAX
};

static const struct blobmsg_policy fields[__POLICY_MAX] = {
    [POLICY_REVISION] = {
        .name = "revision",
        .type = BLOBMSG_TYPE_INT32
    },
    [POLICY_DOMAINS] = {
        .name = "blocked_domains",
        .type = BLOBMSG_TYPE_ARRAY
    }
};

struct blob_attr *tb[__POLICY_MAX] = {0};

blobmsg_parse(
    fields,
    __POLICY_MAX,
    tb,
    blobmsg_data(b.head),
    blobmsg_data_len(b.head)
);

struct blob_attr *array = tb[POLICY_DOMAINS];
struct blob_attr *revision = tb[POLICY_REVISION];

    if (!array || !revision ||
        blobmsg_type(array) != BLOBMSG_TYPE_ARRAY ||
        blobmsg_type(revision) != BLOBMSG_TYPE_INT32) {
        blob_buf_free(&b);
        return -1;
    }

    printf("Revision: %u\n",
           blobmsg_get_u32(revision));

    struct blob_attr *item;
    int rem;
    int result = 0;

    blobmsg_for_each_attr(item, array, rem) {
        if (blobmsg_type(item) != BLOBMSG_TYPE_STRING ||
            add_domain(list, blobmsg_get_string(item))) {
            result = -1;
            break;
        }
    }

    if (result == 0 && parse_wifi(b.head, wifi) != 0)
    result = -1;

    blob_buf_free(&b);
    sort_domains(list);
    return result;
}

static int load_state(struct domain_list *list)
{
    FILE *f = fopen(STATE, "r");
    char line[512];

    if (!f)
        return access(STATE, F_OK) != 0 ? 0 : -1;

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';

        if (add_domain(list, line)) {
            fclose(f);
            return -1;
        }
    }

    int error = ferror(f);
    fclose(f);
    sort_domains(list);

    return error ? -1 : 0;
}

static int save_state(const struct domain_list *list)
{
    FILE *f = fopen(STATE ".tmp", "w");

    if (!f)
        return -1;

    for (int i = 0; i < list->count; i++)
        fprintf(f, "%s\n", list->domain[i]);

    if (fclose(f))
        return -1;

    return rename(STATE ".tmp", STATE);
}

static int copy_file(const char *src, const char *dst)
{
    char buf[4096];
    FILE *in = fopen(src, "rb");
    if (!in) return -1;

    FILE *out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }

    size_t n;
    int error = 0;

    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            error = 1;
            break;
        }
    }

    if (ferror(in)) error = 1;
    if (fclose(out)) error = 1;
    fclose(in);

    return error ? -1 : 0;
}

static int modify_uci(const char *operation,
                      const char *domain)
{
    char value[300];

    /* dnsmasq: responder con dirección nula */
    snprintf(value, sizeof(value),
        "dhcp.@dnsmasq[0].address=/%s/#", domain);

    const char *const args[] = {
        "uci", operation, value, NULL
    };

    return execute(args);
}

static int commit_uci(void)
{
    const char *const args[] = {
        "uci", "commit", "dhcp", NULL
    };
    return execute(args);
}

static int restart_dnsmasq(void)
{
    const char *const args[] = {
        "/etc/init.d/dnsmasq", "restart", NULL
    };
    return execute(args);
}

static int apply_policy(struct domain_list *newlist)
{
    struct domain_list old = {};

    if (load_state(&old))
        return -1;

    if (same_domains(&old, newlist)) {
        puts("Politica sin cambios");
        return 0;
    }

    if (copy_file("/etc/config/dhcp", BACKUP))
        return -1;

    for (int i = 0; i < old.count; i++) {
        if (modify_uci("del_list", old.domain[i]))
            goto rollback;
    }

    for (int i = 0; i < newlist->count; i++) {
        if (modify_uci("add_list", newlist->domain[i]))
            goto rollback;
    }

    if (commit_uci() || restart_dnsmasq())
        goto rollback;

    if (save_state(newlist)) {
        fprintf(stderr, "No se pudo guardar el estado\n");
        goto rollback;
    }

    unlink(BACKUP);
    puts("Politica aplicada correctamente");
    return 0;

rollback:
    fprintf(stderr, "Error: restaurando configuracion DNS\n");

    if (copy_file(BACKUP, "/etc/config/dhcp") == 0) {
        const char *const revert[] = {
            "uci", "revert", "dhcp", NULL
        };
        execute(revert);
        restart_dnsmasq();
    }

    unlink(BACKUP);
    return -1;
}



static int uci_set(const char *option,
                   const char *value)
{
    char argument[384];

    if (snprintf(argument, sizeof(argument),
                 "%s=%s", option, value)
        >= (int)sizeof(argument))
        return -1;

    const char *const args[] = {
        "uci", "set", argument, NULL
    };

    return execute(args);
}

static int wifi_reload(void)
{
    const char *const args[] = {
        "wifi", "reload", NULL
    };

    return execute(args);
}

static int apply_wifi(const struct wifi_settings *wifi)
{
    char channel[8];

    if (!wifi->present)
        return 0;

    snprintf(channel, sizeof(channel),
             "%d", wifi->channel);

    /* Respaldo temporal para recuperación */
    if (copy_file("/etc/config/wireless",
                  "/tmp/wireless.backup"))
        return -1;

    if (uci_set("wireless.radio0.disabled",
                wifi->enabled ? "0" : "1") ||
        uci_set("wireless.radio0.channel",
                channel) ||
        uci_set("wireless.default_radio0.disabled", "0") ||
        uci_set("wireless.default_radio0.mode", "ap") ||
        uci_set("wireless.default_radio0.network", "lan") ||
        uci_set("wireless.default_radio0.ssid",
                wifi->ssid) ||
        uci_set("wireless.default_radio0.encryption",
                "psk2") ||
        uci_set("wireless.default_radio0.key",
                wifi->password))
        goto rollback;

    const char *const commit[] = {
        "uci", "commit", "wireless", NULL
    };

    if (execute(commit) || wifi_reload())
        goto rollback;

    unlink("/tmp/wireless.backup");
    puts("[WiFi] Configuracion aplicada");
    return 0;

rollback:
    fprintf(stderr, "[WiFi] Restaurando configuracion\n");

    if (copy_file("/tmp/wireless.backup",
                  "/etc/config/wireless") == 0) {
        const char *const revert[] = {
            "uci", "revert", "wireless", NULL
        };
        execute(revert);
        wifi_reload();
    }

    unlink("/tmp/wireless.backup");
    return -1;
}


int main(void)
{
    struct domain_list list = {};
    struct wifi_settings wifi = {};


    puts("[Nubeware] Consultando politica");

    if (download_policy()) {
        fprintf(stderr, "Error de conexion HTTPS\n");
        return 1;
    }

    if (parse_policy(&list, &wifi)) {
        fprintf(stderr, "JSON invalido\n");
        return 1;
    }

    printf("Dominios: %d\n", list.count);

    for (int i = 0; i < list.count; i++)
        printf("Bloqueo: %s\n", list.domain[i]);

    if (apply_wifi(&wifi) != 0) {
        fprintf(stderr, "Error al aplicar configuración WiFi\n");
        return 1;
    }

    return apply_policy(&list) == 0 ? 0 : 1;
}
