/*
 * Copyright (C) Jerome Loyet <jerome at loyet dot net>
 */

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_sticky_misc.h"

#if (NGX_UPSTREAM_CHECK_MODULE)
#include "ngx_http_upstream_check_handler.h"
#endif


/* define a peer */
typedef struct {
    ngx_http_upstream_rr_peer_t *rr_peer;
    ngx_str_t                    digest;
} ngx_http_sticky_peer_t;

/* the configuration structure */
typedef struct {
    ngx_http_upstream_srv_conf_t  uscf;
    ngx_str_t                     cookie_name;
    ngx_str_t                     cookie_domain;
    ngx_str_t                     cookie_path;
    time_t                        cookie_expires;
    unsigned                      cookie_secure:1;
    unsigned                      cookie_httponly:1;
    unsigned                      transfer_cookie:1;
    ngx_str_t                     transfer_delim;
    ngx_str_t                     hmac_key;
    ngx_http_sticky_misc_hash_pt  hash;
    ngx_http_sticky_misc_hmac_pt  hmac;
    ngx_http_sticky_misc_text_pt  text;
    ngx_uint_t                    no_fallback;
    ngx_uint_t                    hide_cookie;
    ngx_http_sticky_peer_t       *peers;
} ngx_http_sticky_srv_conf_t;


/* the configuration loc structure */
typedef struct {
    ngx_uint_t  no_fallback;
    ngx_uint_t  hide_cookie;
} ngx_http_sticky_loc_conf_t;


/* the custom sticky struct used on each request */
typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t   rrp;
    ngx_event_get_peer_pt              get_rr_peer;
    int                                selected_peer;
    ngx_http_sticky_srv_conf_t        *sticky_conf;
    ngx_http_sticky_loc_conf_t        *loc_conf;
    ngx_http_request_t                *request;
    ngx_str_t                          cookie_route;
} ngx_http_sticky_peer_data_t;


static ngx_int_t ngx_http_init_sticky_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_get_sticky_peer(ngx_peer_connection_t *pc, void *data);
static ngx_int_t ngx_http_sticky_header_filter(ngx_http_request_t *r);
static char *ngx_http_sticky_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_sticky_create_conf(ngx_conf_t *cf);
static char *ngx_http_sticky_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void *ngx_http_sticky_create_loc_conf(ngx_conf_t *cf);
static char *ngx_conf_set_noargs_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

static ngx_command_t  ngx_http_sticky_commands[] = {

    { ngx_string("sticky"),
      NGX_HTTP_UPS_CONF|NGX_CONF_ANY,
      ngx_http_sticky_set,
      0,
      0,
      NULL },

    { ngx_string("sticky_no_fallback"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_conf_set_noargs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sticky_hide_cookie"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_conf_set_noargs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sticky_loc_conf_t, hide_cookie),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_sticky_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_sticky_create_conf,           /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_sticky_create_loc_conf,       /* create location configuration */
    ngx_http_sticky_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_sticky_module = {
    NGX_MODULE_V1,
    &ngx_http_sticky_module_ctx, /* module context */
    ngx_http_sticky_commands,    /* module directives */
    NGX_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    NULL,                        /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    NULL,                        /* exit process */
    NULL,                        /* exit master */
    NGX_MODULE_V1_PADDING
};


/*
 * function called by the upstream module to init itself
 * it's called once per instance
 */
ngx_int_t
ngx_http_init_upstream_sticky(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_rr_peers_t  *rr_peers;
    ngx_http_sticky_srv_conf_t    *conf;
    ngx_uint_t                     i;

    /* call the RR module on which the sticky module is based */
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    rr_peers = us->peer.data;

    /* do nothing if there's only one peer */
    if (rr_peers->number <= 1 || rr_peers->single) {
        return NGX_OK;
    }

    /* tell the upstream module to call ngx_http_init_sticky_peer() */
    us->peer.init = ngx_http_init_sticky_peer;

    conf = ngx_http_conf_upstream_srv_conf(us, ngx_http_sticky_module);

    /* if 'index', no need to alloc and generate digest */
    if (!conf->hash && !conf->hmac && !conf->text) {
        conf->peers = NULL;
        return NGX_OK;
    }

    /* create our own upstream indexes */
    conf->peers = ngx_pcalloc(cf->pool,
                              sizeof(ngx_http_sticky_peer_t) * rr_peers->number);
    if (conf->peers == NULL) {
        return NGX_ERROR;
    }

    /* parse each peer and generate digest if necessary */
    for (i = 0; i < rr_peers->number; i++) {
        conf->peers[i].rr_peer = &rr_peers->peer[i];

        if (conf->hmac) {
            /* generate hmac */
            conf->hmac(cf->pool,
                       rr_peers->peer[i].server.data,
                       rr_peers->peer[i].server.len,
                       &conf->hmac_key,
                       &conf->peers[i].digest);

        } else if (conf->text) {
            /* generate text */
            conf->text(cf->pool,
                       rr_peers->peer[i].server.data,
                       rr_peers->peer[i].server.len,
                       &conf->peers[i].digest);

        } else {
            /* generate hash */
            conf->hash(cf->pool,
                       rr_peers->peer[i].server.data,
                       rr_peers->peer[i].server.len,
                       &conf->peers[i].digest);
        }
    }

    return NGX_OK;
}


/*
 * function called by the upstream module when it inits each peer
 * it's called once per request
 */
static ngx_int_t
ngx_http_init_sticky_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_sticky_peer_data_t  *iphp;
    ngx_http_sticky_srv_conf_t   *scf;
    ngx_table_elt_t             *ck;
    ngx_str_t                     route;
    ngx_uint_t                    i;
    ngx_int_t                     n;
    u_char                       *p;

    /* allocate our custom sticky struct */
    iphp = ngx_palloc(r->pool, sizeof(ngx_http_sticky_peer_data_t));
    if (iphp == NULL) {
        return NGX_ERROR;
    }

    /* attach it to the request->upstream->peer.data */
    r->upstream->peer.data = &iphp->rrp;

    /* call the RR init to set up the round-robin logic */
    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    /* override the get callback */
    r->upstream->peer.get = ngx_http_get_sticky_peer;

    /* patch the top header filter if needed */
    if (ngx_http_top_header_filter != ngx_http_sticky_header_filter) {
        ngx_http_next_header_filter = ngx_http_top_header_filter;
        ngx_http_top_header_filter  = ngx_http_sticky_header_filter;
    }

    iphp->get_rr_peer    = ngx_http_upstream_get_round_robin_peer;
    iphp->selected_peer  = -1;
    iphp->sticky_conf    = ngx_http_conf_upstream_srv_conf(us,
                                           ngx_http_sticky_module);
    iphp->loc_conf       = ngx_http_get_module_loc_conf(r,
                                           ngx_http_sticky_module);
    iphp->request        = r;
    iphp->cookie_route.data = NULL;
    iphp->cookie_route.len  = 0;

    ngx_http_set_ctx(r, iphp, ngx_http_sticky_module);

    /*
     * 1) Use the new signature for ngx_http_parse_multi_header_lines()
     * 2) We pass `r`, a pointer to `r->headers_in.cookie`,
     *    the cookie name, and store the cookie value in `route`.
     */
    scf = iphp->sticky_conf;
    ck = ngx_http_parse_multi_header_lines(r,
                                           &r->headers_in.cookie,
                                           &scf->cookie_name,
                                           &route);
    if (ck != NULL) {
        /* a route cookie was found; let's try matching a peer */
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "[sticky/init_sticky_peer] got cookie route=%V, let's try to find a matching peer",
                      &route);

        /* if transfer_cookie is on, strip off any portion after transfer_delim */
        if (scf->transfer_cookie) {
            p = ngx_strnstr(route.data,
                            (char *) scf->transfer_delim.data,
                            route.len);
            if (p != NULL) {
                route.len = p - route.data;
            }
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[sticky/init_sticky_peer] extract route \"%V\"", &route);
        }

        iphp->cookie_route.data = route.data;
        iphp->cookie_route.len  = route.len;

        /* if using hash/hmac/text, compare route to each peer's digest */
        if (scf->hash || scf->hmac || scf->text) {

            if (!scf->peers) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "[sticky/init_sticky_peer] internal peers struct has not been set");
                return NGX_OK;
            }

            for (i = 0; i < iphp->rrp.peers->number; i++) {
                if (scf->peers[i].digest.len != route.len || route.len <= 0) {
                    continue;
                }
                if (!ngx_strncmp(scf->peers[i].digest.data, route.data, route.len)) {
                    iphp->selected_peer = i;
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "[sticky/init_sticky_peer] the route \"%V\" matches peer at index %ui",
                        &route, i);
                    return NGX_OK;
                }
            }

        } else {
            /* if using hash=index, just parse route as an integer */
            n = ngx_atoi(route.data, route.len);
            if (n == NGX_ERROR) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "[sticky/init_sticky_peer] unable to convert \"%V\" to an integer route",
                    &route);
            } else if (n >= 0 && n < (ngx_int_t) iphp->rrp.peers->number) {
                iphp->selected_peer = n;
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "[sticky/init_sticky_peer] the route \"%V\" matches peer index %i",
                    &route, n);
                return NGX_OK;
            }
        }

        /* nothing matched; fall back to normal RR */
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "[sticky/init_sticky_peer] cookie route \"%V\" does not match any peer",
            &route);
        return NGX_OK;
    }

    /* cookie not found at all */
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "[sticky/init_sticky_peer] route cookie not found");
    return NGX_OK;
}


/*
 * function called by the upstream module to choose the next peer
 * called at least once per request
 */
static ngx_int_t
ngx_http_get_sticky_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_sticky_peer_data_t  *iphp = data;
    ngx_http_sticky_srv_conf_t   *conf = iphp->sticky_conf;
    ngx_http_sticky_loc_conf_t   *loc_conf = iphp->loc_conf;
    ngx_int_t                     selected_peer = -1;
    time_t                        now = ngx_time();
    uintptr_t                     m = 0;
    ngx_uint_t                    n = 0, i;
    ngx_http_upstream_rr_peer_t  *peer = NULL;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0,
        "[sticky/get_sticky_peer] get sticky peer, try: %ui, n_peers: %ui, no_fallback: %ui/%ui",
        pc->tries, iphp->rrp.peers->number, conf->no_fallback, loc_conf->no_fallback);

    /* has sticky module already chosen a valid peer? */
    if (iphp->selected_peer >= 0
        && iphp->selected_peer < (ngx_int_t) iphp->rrp.peers->number
        && !iphp->rrp.peers->single)
    {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0,
            "[sticky/get_sticky_peer] let's try the selected peer (%i)",
            iphp->selected_peer);

        n = iphp->selected_peer / (8 * sizeof(uintptr_t));
        m = (uintptr_t)1 << (iphp->selected_peer % (8 * sizeof(uintptr_t)));

        /* has this peer not already been tried? */
        if (!(iphp->rrp.tried[n] & m)) {
            peer = &iphp->rrp.peers->peer[iphp->selected_peer];

            /* if no_fallback is set at upstream or location level */
            if (conf->no_fallback || loc_conf->no_fallback) {

                /* if peer is down */
                if (peer->down) {
                    ngx_log_error(NGX_LOG_NOTICE, pc->log, 0,
                        "[sticky/get_sticky_peer] selected peer is down, no_fallback is flagged");
                    return NGX_BUSY;
                }

                /* if fail_timeout has elapsed, reset fails */
                if (now - peer->accessed > peer->fail_timeout) {
                    peer->fails = 0;
                }

                /* if peer is still failed */
                if (peer->max_fails > 0 && peer->fails >= peer->max_fails) {
                    ngx_log_error(NGX_LOG_NOTICE, pc->log, 0,
                        "[sticky/get_sticky_peer] selected peer is failed, no_fallback is flagged");
                    return NGX_BUSY;
                }
            }

            /* ensure peer is not down */
            if (!peer->down) {

                if (peer->max_fails == 0 || peer->fails < peer->max_fails) {
                    selected_peer = (ngx_int_t) n;

                } else if (now - peer->accessed > peer->fail_timeout) {
                    /* timed out, reset fails and use it */
                    peer->fails = 0;
                    selected_peer = (ngx_int_t) n;

                } else {
                    /* can't use it, mark as tried */
                    iphp->rrp.tried[n] |= m;
                }
            }
        }
    }

    /* if we found a valid sticky peer, use it */
    if (peer && selected_peer >= 0) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0,
            "[sticky/get_sticky_peer] using peer index %i", selected_peer);

#if defined(nginx_version) && (nginx_version >= 1009000)
        iphp->rrp.current = peer;
#else
        iphp->rrp.current = iphp->selected_peer;
#endif
        pc->cached = 0;
        pc->connection = NULL;
        pc->sockaddr  = peer->sockaddr;
        pc->socklen   = peer->socklen;
        pc->name      = &peer->name;

        iphp->rrp.tried[n] |= m;

    } else {
        /* fallback to normal round-robin */
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0,
            "[sticky/get_sticky_peer] no sticky peer selected, fallback to RR");

        if (conf->no_fallback || loc_conf->no_fallback) {
            ngx_log_error(NGX_LOG_NOTICE, pc->log, 0,
                "[sticky/get_sticky_peer] no_fallback is in effect; returning NGX_BUSY");
            return NGX_BUSY;
        }

        ngx_int_t ret = iphp->get_rr_peer(pc, &iphp->rrp);
        if (ret != NGX_OK) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                "[sticky/get_sticky_peer] round_robin_peer returned %i", ret);
            return ret;
        }

        /* find which peer was chosen, so we can set the sticky cookie */
        for (i = 0; i < iphp->rrp.peers->number; i++) {
            if (iphp->rrp.peers->peer[i].sockaddr == pc->sockaddr
                && iphp->rrp.peers->peer[i].socklen == pc->socklen)
            {
                if (conf->hash || conf->hmac || conf->text) {
                    iphp->cookie_route.data =
                        ngx_pnalloc(iphp->request->pool,
                                    conf->peers[i].digest.len + 1);
                    if (iphp->cookie_route.data == NULL) {
                        return NGX_ERROR;
                    }
                    (void) ngx_cpystrn(iphp->cookie_route.data,
                                       conf->peers[i].digest.data,
                                       conf->peers[i].digest.len + 1);
                    iphp->cookie_route.len = conf->peers[i].digest.len;
                } else {
                    /* numeric index mode */
                    ngx_uint_t tmp = i;
                    iphp->cookie_route.len = 0;
                    do {
                        iphp->cookie_route.len++;
                    } while (tmp /= 10);

                    iphp->cookie_route.data =
                        ngx_pcalloc(iphp->request->pool,
                                    sizeof(u_char)*(iphp->cookie_route.len + 1));
                    if (iphp->cookie_route.data == NULL) {
                        break;
                    }
                    ngx_snprintf(iphp->cookie_route.data,
                                 iphp->cookie_route.len, "%d", i);
                    iphp->cookie_route.len =
                        ngx_strlen(iphp->cookie_route.data);
                }

                ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                    "[sticky/get_sticky_peer] preset cookie \"%V\" value=\"%V\" index=%ui",
                    &conf->cookie_name, &iphp->cookie_route, i);
                break;
            }
        }
    }

    /* reset selection so if upstream tries again, we do normal logic */
    iphp->selected_peer = -1;

    return NGX_OK;
}


/*
 * Function called when a handler generates a response
 * to set (or hide) the sticky cookie
 */
static ngx_int_t
ngx_http_sticky_header_filter(ngx_http_request_t *r)
{
    ngx_http_sticky_peer_data_t  *ctx;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *elt, *sc;
    ngx_str_t                     transfer_cookie;
    ngx_str_t                     result_cookie;
    u_char                       *p;
    size_t                        len;

    ctx = ngx_http_get_module_ctx(r, ngx_http_sticky_module);
    if (ctx == NULL || ctx->cookie_route.data == NULL) {
        return ngx_http_next_header_filter(r);
    }

    /* If transfer_cookie is set, we might check upstream's Set-Cookie lines */
    if (ctx->sticky_conf->transfer_cookie) {
        /* modernized signature; returns a pointer if found, or NULL if not */
        sc = ngx_http_parse_set_cookie_lines(r,
                                             &r->upstream->headers_in.cookie,
                                             &ctx->sticky_conf->cookie_name,
                                             &transfer_cookie);
        if (sc == NULL) {
            ngx_str_null(&transfer_cookie);
        }
    }

    /* remove any old Set-Cookie with our cookie_name from the output headers */
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "[sticky/ngx_http_sticky_header_filter] cleaning old Set-Cookie");
    part = &r->headers_out.headers.part;
    elt  = part->elts;
    for (ngx_uint_t i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            elt  = part->elts;
            i = 0;
        }

        if (ngx_strncasecmp(elt[i].key.data, (u_char *)"set-cookie", 10) == 0
            && ngx_strncasecmp(elt[i].value.data,
                               ctx->sticky_conf->cookie_name.data,
                               ctx->sticky_conf->cookie_name.len) == 0
            && elt[i].value.data[ctx->sticky_conf->cookie_name.len] == '=')
        {
            elt[i].hash = 0; /* effectively remove it */
        }
    }

    /* if cookie is not hidden at upstream or location level, we set it */
    if (!ctx->sticky_conf->hide_cookie && !ctx->loc_conf->hide_cookie) {

        if (ctx->sticky_conf->transfer_cookie && transfer_cookie.len != 0) {
            /* combine route + delimiter + original cookie */
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[sticky/ngx_http_sticky_header_filter] add transfer cookie");
            len = ctx->cookie_route.len
                  + ctx->sticky_conf->transfer_delim.len
                  + transfer_cookie.len;
            result_cookie.data = ngx_palloc(r->pool, len);
            if (result_cookie.data == NULL) {
                return NGX_ERROR;
            }
            p = ngx_copy(result_cookie.data,
                         ctx->cookie_route.data,
                         ctx->cookie_route.len);
            p = ngx_copy(p,
                         ctx->sticky_conf->transfer_delim.data,
                         ctx->sticky_conf->transfer_delim.len);
            (void) ngx_copy(p, transfer_cookie.data, transfer_cookie.len);
            result_cookie.len = len;

        } else {
            /* just set our route as the cookie value */
            result_cookie = ctx->cookie_route;
        }

        /* actually set the cookie header in the response */
        ngx_http_sticky_misc_set_cookie(r,
            &ctx->sticky_conf->cookie_name,
            &result_cookie,
            &ctx->sticky_conf->cookie_domain,
            &ctx->sticky_conf->cookie_path,
            ctx->sticky_conf->cookie_expires,
            ctx->sticky_conf->cookie_secure,
            ctx->sticky_conf->cookie_httponly
        );

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "[sticky/ngx_http_sticky_header_filter] set cookie \"%V\"=\"%V\"",
            &ctx->sticky_conf->cookie_name, &result_cookie);
    }

    return ngx_http_next_header_filter(r);
}


/*
 * Function called when the sticky command is parsed in the config
 */
static char *
ngx_http_sticky_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t   *upstream_conf;
    ngx_http_sticky_srv_conf_t     *sticky_conf;
    ngx_uint_t                      i;
    ngx_str_t                       tmp;
    ngx_str_t name     = ngx_string("route");
    ngx_str_t domain   = ngx_string("");
    ngx_str_t path     = ngx_string("/");
    ngx_str_t hmac_key = ngx_string("");
    ngx_str_t delimiter= ngx_string(" ");
    time_t expires     = NGX_CONF_UNSET;
    unsigned secure    = 0;
    unsigned httponly  = 0;
    unsigned transfer  = 0;

    ngx_http_sticky_misc_hash_pt hash = NGX_CONF_UNSET_PTR;
    ngx_http_sticky_misc_hmac_pt hmac = NULL;
    ngx_http_sticky_misc_text_pt text = NULL;
    ngx_uint_t no_fallback = 0;
    ngx_uint_t hide_cookie = 0;

    /* parse all elements */
    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *value = cf->args->elts;

        if ((u_char *) ngx_strstr(value[i].data, "name=") == value[i].data) {
            if (value[i].len <= sizeof("name=") - 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "a value must be provided to \"name=\"");
                return NGX_CONF_ERROR;
            }
            name.len  = value[i].len - ngx_strlen("name=");
            name.data = (u_char *)(value[i].data + sizeof("name=") - 1);
            continue;
        }

        if ((u_char *)ngx_strstr(value[i].data, "domain=") == value[i].data) {
            if (value[i].len <= ngx_strlen("domain=")) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "a value must be provided to \"domain=\"");
                return NGX_CONF_ERROR;
            }
            domain.len  = value[i].len - ngx_strlen("domain=");
            domain.data = (u_char *)(value[i].data + sizeof("domain=") - 1);
            continue;
        }

        if ((u_char *)ngx_strstr(value[i].data, "path=") == value[i].data) {
            if (value[i].len <= ngx_strlen("path=")) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "a value must be provided to \"path=\"");
                return NGX_CONF_ERROR;
            }
            path.len  = value[i].len - ngx_strlen("path=");
            path.data = (u_char *)(value[i].data + sizeof("path=") - 1);
            continue;
        }

        if ((u_char *)ngx_strstr(value[i].data, "expires=") == value[i].data) {
            if (value[i].len <= sizeof("expires=") - 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "a value must be provided to \"expires=\"");
                return NGX_CONF_ERROR;
            }
            tmp.len  = value[i].len - ngx_strlen("expires=");
            tmp.data = (u_char *)(value[i].data + sizeof("expires=") - 1);
            expires = ngx_parse_time(&tmp, 1);
            if (expires == NGX_ERROR || expires < 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid value for \"expires=\"");
                return NGX_CONF_ERROR;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "secure", 6) == 0
            && value[i].len == 6)
        {
            secure = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "httponly", 8) == 0
            && value[i].len == 8)
        {
            httponly = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "transfer", 8) == 0
            && value[i].len == 8)
        {
            transfer = 1;
            continue;
        }

        if ((u_char *)ngx_strstr(value[i].data, "delimiter=") == value[i].data) {
            if (value[i].len <= ngx_strlen("delimiter=")) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "a value must be provided to \"delimiter=\"");
                return NGX_CONF_ERROR;
            }
            delimiter.len = value[i].len - ngx_strlen("delimiter=");
            delimiter.data = ngx_pcalloc(cf->pool, delimiter.len + 1);
            if (delimiter.data == NULL) {
                return NGX_CONF_ERROR;
            }
            ngx_memcpy(delimiter.data,
                       (u_char *)(value[i].data + sizeof("delimiter=") - 1),
                       delimiter.len);
            delimiter.data[delimiter.len] = '\0';
            continue;
        }

        if ((u_char *)ngx_strstr(value[i].data, "text=") == value[i].data) {
            /* only hash or hmac can be used, not both */
            if (hmac || hash != NGX_CONF_UNSET_PTR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "please choose between \"hash=\", \"hmac=\" and \"text=\"");
                return NGX_CONF_ERROR;
            }
            if (value[i].len <= sizeof("text=") - 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "a value must be provided to \"text=\"");
                return NGX_CONF_ERROR;
            }

            tmp.len  = value[i].len - ngx_strlen("text=");
            tmp.data = (u_char *)(value[i].data + sizeof("text=") - 1);

            if (ngx_strncmp(tmp.data, "raw", sizeof("raw") - 1) == 0) {
                text = ngx_http_sticky_misc_text_raw;
                continue;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "wrong value for \"text=\": raw");
            return NGX_CONF_ERROR;
        }

        if ((u_char *)ngx_strstr(value[i].data, "hash=") == value[i].data) {
            if (hmac || text) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "please choose between \"hash=\", \"hmac=\" and \"text=\"");
                return NGX_CONF_ERROR;
            }
            if (value[i].len <= sizeof("hash=") - 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "a value must be provided to \"hash=\"");
                return NGX_CONF_ERROR;
            }

            tmp.len  = value[i].len - ngx_strlen("hash=");
            tmp.data = (u_char *)(value[i].data + sizeof("hash=") - 1);

            if (ngx_strncmp(tmp.data, "index", sizeof("index") - 1) == 0) {
                hash = NULL;
                continue;
            }
            if (ngx_strncmp(tmp.data, "md5", sizeof("md5") - 1) == 0) {
                hash = ngx_http_sticky_misc_md5;
                continue;
            }
            if (ngx_strncmp(tmp.data, "sha1", sizeof("sha1") - 1) == 0) {
                hash = ngx_http_sticky_misc_sha1;
                continue;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "wrong value for \"hash=\": index, md5 or sha1");
            return NGX_CONF_ERROR;
        }

        if ((u_char *)ngx_strstr(value[i].data, "hmac=") == value[i].data) {
            if (hash != NGX_CONF_UNSET_PTR || text) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "please choose between \"hash=\", \"hmac=\" and \"text\"");
                return NGX_CONF_ERROR;
            }
            if (value[i].len <= sizeof("hmac=") - 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "a value must be provided to \"hmac=\"");
                return NGX_CONF_ERROR;
            }

            tmp.len  = value[i].len - ngx_strlen("hmac=");
            tmp.data = (u_char *)(value[i].data + sizeof("hmac=") - 1);

            if (ngx_strncmp(tmp.data, "md5", sizeof("md5") - 1) == 0) {
                hmac = ngx_http_sticky_misc_hmac_md5;
                continue;
            }
            if (ngx_strncmp(tmp.data, "sha1", sizeof("sha1") - 1) == 0) {
                hmac = ngx_http_sticky_misc_hmac_sha1;
                continue;
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "wrong value for \"hmac=\": md5 or sha1");
            return NGX_CONF_ERROR;
        }

        if ((u_char *)ngx_strstr(value[i].data, "hmac_key=") == value[i].data) {
            if (value[i].len <= ngx_strlen("hmac_key=")) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "a value must be provided to \"hmac_key=\"");
                return NGX_CONF_ERROR;
            }

            hmac_key.len  = value[i].len - ngx_strlen("hmac_key=");
            hmac_key.data = (u_char *)(value[i].data + sizeof("hmac_key=") - 1);
            continue;
        }

        if (ngx_strncmp(value[i].data, "no_fallback",
                        sizeof("no_fallback") - 1) == 0)
        {
            no_fallback = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "hide_cookie",
                        sizeof("hide_cookie") - 1) == 0)
        {
            hide_cookie = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid argument (%V)", &value[i]);
        return NGX_CONF_ERROR;
    }

    /* if no hashing style was specified, default to MD5 */
    if (hash == NGX_CONF_UNSET_PTR && hmac == NULL && text == NULL) {
        hash = ngx_http_sticky_misc_md5;
    }

    if (hmac_key.len > 0 && hash != NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"hmac_key=\" is meaningless without \"hmac\". Remove it or set hmac=md5/sha1.");
        return NGX_CONF_ERROR;
    }

    if (hmac_key.len == 0 && hmac != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "please specify \"hmac_key=\" when using \"hmac\"");
        return NGX_CONF_ERROR;
    }

    /* ensure we set hash to NULL if it was never changed */
    if (hash == NGX_CONF_UNSET_PTR) {
        hash = NULL;
    }

    /* save the sticky parameters */
    sticky_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_sticky_module);
    sticky_conf->cookie_name    = name;
    sticky_conf->cookie_domain  = domain;
    sticky_conf->cookie_path    = path;
    sticky_conf->cookie_expires = expires;
    sticky_conf->cookie_secure  = secure;
    sticky_conf->cookie_httponly= httponly;
    sticky_conf->transfer_cookie= transfer;
    sticky_conf->transfer_delim = delimiter;
    sticky_conf->hash           = hash;
    sticky_conf->hmac           = hmac;
    sticky_conf->text           = text;
    sticky_conf->hmac_key       = hmac_key;
    sticky_conf->no_fallback    = no_fallback;
    sticky_conf->hide_cookie    = hide_cookie;
    sticky_conf->peers          = NULL; /* ensure null initially */

    upstream_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    /*
     * ensure no other upstream init module is set
     * (we rely on round-robin)
     */
    if (upstream_conf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "You can't use sticky with another upstream module");
        return NGX_CONF_ERROR;
    }

    /* configure the upstream to call us */
    upstream_conf->peer.init_upstream = ngx_http_init_upstream_sticky;
    upstream_conf->flags = NGX_HTTP_UPSTREAM_CREATE
                         | NGX_HTTP_UPSTREAM_MAX_FAILS
                         | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                         | NGX_HTTP_UPSTREAM_DOWN
                         | NGX_HTTP_UPSTREAM_WEIGHT;

    return NGX_CONF_OK;
}


static void *
ngx_http_sticky_create_conf(ngx_conf_t *cf)
{
    ngx_http_sticky_srv_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sticky_srv_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    return conf;
}

static void *
ngx_http_sticky_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_sticky_loc_conf_t  *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->no_fallback = NGX_CONF_UNSET_UINT;
    conf->hide_cookie = NGX_CONF_UNSET_UINT;
    return conf;
}

static char *
ngx_http_sticky_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sticky_loc_conf_t *prev = parent;
    ngx_http_sticky_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->no_fallback, prev->no_fallback, 0);
    ngx_conf_merge_uint_value(conf->hide_cookie, prev->hide_cookie, 0);

    if (conf->no_fallback > 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "no_fallback must be 0 or 1");
        return NGX_CONF_ERROR;
    }
    if (conf->hide_cookie > 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "hide_cookie must be 0 or 1");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


static char *
ngx_conf_set_noargs_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char               *p = conf;
    ngx_uint_t         *fp;
    ngx_conf_post_t    *post;

    fp = (ngx_uint_t *) (p + cmd->offset);

    if (*fp != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    *fp = 1;

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, fp);
    }

    return NGX_CONF_OK;
}
