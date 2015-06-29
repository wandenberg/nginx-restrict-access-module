#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t    ngx_http_restrict_access_pre_config(ngx_conf_t *cf);
ngx_int_t    ngx_http_restrict_access_post_config(ngx_conf_t *cf);
void        *ngx_http_restrict_access_create_loc_conf(ngx_conf_t *cf);
char        *ngx_http_restrict_access_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
ngx_int_t    ngx_http_restrict_access_remote_hostname_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t    ngx_http_restrict_access_handler(ngx_http_request_t *r);
ngx_int_t    ngx_http_restrict_access_check_permission(ngx_http_request_t *r);
ngx_str_t   *ngx_http_restrict_access_create_str(ngx_pool_t *pool, uint len);
ngx_str_t   *ngx_http_restrict_access_get_hostname(struct sockaddr *addr, ngx_pool_t *pool);
ngx_str_t   *ngx_http_restrict_access_get_host_ip(ngx_str_t *hostname, struct sockaddr *addr, ngx_pool_t *pool);
static char *ngx_http_restrict_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


typedef struct {
    ngx_uint_t        deny;                   /* unsigned  deny:1; */
    ngx_uint_t        reverse_dns_check;
    ngx_regex_t      *host_regexp;
} ngx_http_restrict_access_rule_t;


typedef struct {
    ngx_array_t                    *rules;    /* array of ngx_http_restrict_access_rule_t */
    ngx_http_complex_value_t       *address;
} ngx_http_restrict_access_loc_conf_t;


static ngx_http_variable_t  ngx_http_restrict_access_vars[] = {
    { ngx_string("restrict_access_remote_hostname"),
      NULL,
      ngx_http_restrict_access_remote_hostname_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_command_t ngx_http_restrict_access_commands[] = {
    { ngx_string("allow_host"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE12,
      ngx_http_restrict_access_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("deny_host"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE12,
      ngx_http_restrict_access_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("restrict_access_address"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_restrict_access_loc_conf_t, address),
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_restrict_access_module_ctx = {
    ngx_http_restrict_access_pre_config,        /* preconfiguration */
    ngx_http_restrict_access_post_config,       /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */
    ngx_http_restrict_access_create_loc_conf,   /* create location configuration */
    ngx_http_restrict_access_merge_loc_conf     /* merge location configuration */
};


ngx_module_t ngx_http_restrict_access_module = {
    NGX_MODULE_V1,
    &ngx_http_restrict_access_module_ctx,       /* module context */
    ngx_http_restrict_access_commands,          /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_http_restrict_access_pre_config(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_restrict_access_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_restrict_access_post_config(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_restrict_access_handler;

    return NGX_OK;
}


static char *
ngx_http_restrict_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_restrict_access_loc_conf_t *ralcf = conf;

    ngx_uint_t                           all;
    ngx_str_t                           *value, host_pattern = ngx_string(".*");
    ngx_http_restrict_access_rule_t     *rule;
    u_char                               errstr[NGX_MAX_CONF_ERRSTR];
    ngx_regex_compile_t                 *rc = NULL;

    value = cf->args->elts;

    all = (value[1].len == 3 && ngx_strcmp(value[1].data, "all") == 0);

    if (ralcf->rules == NULL) {
        ralcf->rules = ngx_array_create(cf->pool, 4, sizeof(ngx_http_restrict_access_rule_t));
        if (ralcf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(ralcf->rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    if (!all) {
        host_pattern.len = value[1].len;
        host_pattern.data = value[1].data;
    }

    if ((rc = ngx_pcalloc(cf->pool, sizeof(ngx_regex_compile_t))) == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_restrict_access_module: unable to allocate memory to compile host pattern");
        return NGX_CONF_ERROR;
    }

    rc->pattern = host_pattern;
    rc->pool = cf->pool;
    rc->err.len = NGX_MAX_CONF_ERRSTR;
    rc->err.data = errstr;

    if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_http_restrict_access_module: unable to compile host pattern %V", &host_pattern);
        return NGX_CONF_ERROR;
    }

    rule->host_regexp = rc->regex;
    rule->deny = (value[0].data[0] == 'd') ? 1 : 0;
    rule->reverse_dns_check = (cf->args->nelts > 2) ? !(value[2].len == 14 && ngx_strcmp(value[2].data, "no_reverse_dns") == 0) : 1;

    return NGX_CONF_OK;
}


void *
ngx_http_restrict_access_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_restrict_access_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_restrict_access_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->rules = NULL;
    conf->address = NULL;

    return conf;
}


char *
ngx_http_restrict_access_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_restrict_access_loc_conf_t  *prev = parent;
    ngx_http_restrict_access_loc_conf_t  *conf = child;

    if (conf->rules == NULL) {
        conf->rules = prev->rules;
    }

    if (conf->address == NULL) {
        conf->address = prev->address;
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_restrict_access_remote_hostname_variable(ngx_http_request_t *r, ngx_http_variable_value_t *var, uintptr_t data)
{
    ngx_str_t                           *hostname;

    if (var->len > 0) {
        return NGX_OK;
    }

    if ((hostname = ngx_http_restrict_access_get_hostname(r->connection->sockaddr, r->pool)) != NULL) {
        var->len = hostname->len;
        var->data = hostname->data;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_restrict_access_handler(ngx_http_request_t *r)
{
    ngx_http_restrict_access_loc_conf_t *ralcf = ngx_http_get_module_loc_conf(r, ngx_http_restrict_access_module);

    if (ralcf->rules != NULL) {
        return ngx_http_restrict_access_check_permission(r);
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_restrict_access_check_permission(ngx_http_request_t *r)
{
    ngx_http_restrict_access_loc_conf_t *ralcf = ngx_http_get_module_loc_conf(r, ngx_http_restrict_access_module);
    ngx_str_t                           *hostname, *ip;
    ngx_uint_t                           i;
    ngx_http_restrict_access_rule_t     *rule;
    ngx_str_t                            vv_address = ngx_null_string;
    struct sockaddr                     *sockaddr = r->connection->sockaddr;
    ngx_addr_t                           address;
    ngx_str_t                           *addr_text = &r->connection->addr_text;

    if (ralcf->address) {
        ngx_http_complex_value(r, ralcf->address, &vv_address);
        if (vv_address.len > 0) {
            if (ngx_parse_addr(r->pool, &address, vv_address.data, vv_address.len) == NGX_OK) {
                sockaddr = address.sockaddr;
                addr_text = &vv_address;
            }
        }
    }

    if ((hostname = ngx_http_restrict_access_get_hostname(sockaddr, r->pool)) != NULL) {

        rule = ralcf->rules->elts;
        for (i = 0; i < ralcf->rules->nelts; i++) {
            if (ngx_regex_exec(rule[i].host_regexp, hostname, NULL, 0) != NGX_REGEX_NO_MATCHED) {
                if (rule[i].reverse_dns_check) {

                    if ((ip = ngx_http_restrict_access_get_host_ip(hostname, sockaddr, r->pool)) != NULL) {
                        if (ngx_strncmp(ip->data, addr_text->data, addr_text->len) == 0) {
                            return (rule[i].deny) ? NGX_HTTP_FORBIDDEN : NGX_OK;
                        }
                    } else {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_restrict_access_module: was not possible to get ip for hostname '%V'", hostname);
                    }

                    return NGX_HTTP_FORBIDDEN;

                } else {
                    return (rule[i].deny) ? NGX_HTTP_FORBIDDEN : NGX_OK;
                }
            }
        }

    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_restrict_access_module: was not able to get hostname for address '%V'", &r->connection->addr_text);
    }

    return NGX_HTTP_FORBIDDEN;
}


ngx_str_t *
ngx_http_restrict_access_create_str(ngx_pool_t *pool, uint len)
{
    ngx_str_t *aux = (ngx_str_t *) ngx_pcalloc(pool, sizeof(ngx_str_t) + len + 1);

    if (aux != NULL) {
        aux->data = (u_char *) (aux + 1);
        aux->len = len;
        ngx_memset(aux->data, '\0', len + 1);
    }

    return aux;
}


ngx_str_t *
ngx_http_restrict_access_get_hostname(struct sockaddr *addr, ngx_pool_t *pool)
{
    char                hostname_buf[NI_MAXHOST];
    ngx_str_t          *hostname = NULL;
    socklen_t           len = (addr->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

    if (getnameinfo(addr, len, hostname_buf, NI_MAXHOST, NULL, 0, NI_NAMEREQD) == 0) {
        if ((hostname = ngx_http_restrict_access_create_str(pool, ngx_strlen(hostname_buf))) != NULL) {
            ngx_memcpy(hostname->data, hostname_buf, hostname->len);
        }
    }

    return hostname;
}


ngx_str_t *
ngx_http_restrict_access_get_host_ip(ngx_str_t *hostname, struct sockaddr *addr, ngx_pool_t *pool)
{
    struct hostent     *host;
    char                host_ip[INET_ADDRSTRLEN];
    ngx_str_t          *ip = NULL;

    if ((host = gethostbyname2((char *) hostname->data, addr->sa_family)) != NULL) {
        if (inet_ntop(addr->sa_family, host->h_addr_list[0], host_ip, INET_ADDRSTRLEN) != NULL) {
            if ((ip = ngx_http_restrict_access_create_str(pool, ngx_strlen(host_ip))) != NULL) {
                ngx_memcpy(ip->data, host_ip, ip->len);
            }
        }
    }

    return ip;
}
