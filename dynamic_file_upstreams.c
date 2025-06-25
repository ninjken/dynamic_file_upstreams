/* use ngx_http_upstream_zone_module.c and ngx_http_auth_basic_module.c
   and ngx_http_upstream.c as references */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifndef NGX_HTTP_UPSTREAM_ZONE
#error NGX_HTTP_UPSTREAM_ZONE must be enabled
#endif

typedef struct {
    ngx_array_t                      upstreams;     /* ngx_dynamic_file_upstream_t */
} ngx_dynamic_file_upstreams_t;

typedef struct {
    ngx_str_t                        name;          /* upstream name */
    ngx_array_t                      servers;       /* ngx_http_upstream_server_t */
} ngx_dynamic_file_upstream_t;


/* function declarations */
static void *dynamic_file_upstreams_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ngx_dynamic_file_upstreams_init_process(ngx_cycle_t *cycle);
static char *set_dynamic_file_upstreams_timer(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_dynamic_file_upstreams_handler(ngx_event_t *ev);
static ngx_int_t ngx_dynamic_file_upstreams_parse(ngx_file_t *file, ngx_dynamic_file_upstreams_t *upstreams);
static ngx_int_t ngx_dynamic_file_upstreams_parse_upstreams(const u_char *buf, size_t size, ngx_log_t *log, ngx_dynamic_file_upstreams_t *upstreams);
static ngx_http_upstream_srv_conf_t *ngx_dynamic_file_upstreams_find_upstream_srv_conf(
    ngx_http_upstream_main_conf_t *umcf, ngx_str_t upstream);
static void ngx_http_upstream_rr_peers_print(ngx_log_t *log);
static ngx_int_t ngx_dynamic_file_upstreams_update_rr_peers(const ngx_dynamic_file_upstreams_t *upstreams, ngx_log_t *log);


static ngx_event_t ngx_dynamic_file_upstreams_timer;
time_t ngx_dynamic_file_upstreams_file_mtime;


/* upstreams_file /path/to/file interval=t */
static ngx_command_t ngx_dynamic_file_upstreams_commands[] = {
    { ngx_string("upstreams_file"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE12,
        set_dynamic_file_upstreams_timer,
        0,
        0,
        NULL },

    ngx_null_command
};


typedef struct {
    ngx_str_t upstreams_file;
    ngx_msec_t interval;
} dynamic_file_upstreams_main_conf_t;

/* module context */
static ngx_http_module_t ngx_dynamic_file_upstreams_module_ctx = {
    NULL,                                       /* preconfiguration */
    NULL,                                       /* postconfiguration */

    dynamic_file_upstreams_create_main_conf,    /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    NULL,                                       /* create location configuration */
    NULL                                        /* merge location configuration */
};

/* module */
ngx_module_t ngx_dynamic_file_upstreams_module = {
    NGX_MODULE_V1,
    &ngx_dynamic_file_upstreams_module_ctx,     /* module context */
    ngx_dynamic_file_upstreams_commands,        /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    ngx_dynamic_file_upstreams_init_process,    /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static void*
dynamic_file_upstreams_create_main_conf(ngx_conf_t *cf) {
    dynamic_file_upstreams_main_conf_t *mcf;
    
    mcf = ngx_pcalloc(cf->pool, sizeof(dynamic_file_upstreams_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    return mcf;
}


static ngx_int_t
ngx_dynamic_file_upstreams_init_process(ngx_cycle_t *cycle)
{
    dynamic_file_upstreams_main_conf_t *mcf;

    if (ngx_worker != 0) {
        return NGX_OK;  /* only the master process should set the timer */
    }

    mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_dynamic_file_upstreams_module);
    if (mcf == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "context for dynamic upstreams file not exist");
        return NGX_ERROR;
    }

    if (mcf->upstreams_file.len == 0) {
        ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Dynamic upstreams file not set");
        return NGX_OK;
    }

    ngx_dynamic_file_upstreams_file_mtime = 0;
    ngx_memzero(&ngx_dynamic_file_upstreams_timer, sizeof(ngx_event_t));
    ngx_dynamic_file_upstreams_timer.handler = ngx_dynamic_file_upstreams_handler;
    ngx_dynamic_file_upstreams_timer.data = mcf;
    ngx_dynamic_file_upstreams_timer.log = cycle->log;
    ngx_add_timer(&ngx_dynamic_file_upstreams_timer, mcf->interval);
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Dynamic file upstreams timer started, upstreams file %V, interval: %T ms",
        &mcf->upstreams_file, mcf->interval);

    return NGX_OK;
}

static char *
set_dynamic_file_upstreams_timer(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    dynamic_file_upstreams_main_conf_t *mcf;
    ngx_int_t i;
    u_char *cp;

    mcf = ngx_http_cycle_get_module_main_conf(cf->cycle, ngx_dynamic_file_upstreams_module);
    ngx_memzero(mcf, sizeof(dynamic_file_upstreams_main_conf_t));

    if (cf->args->nelts < 2 || cf->args->nelts > 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "upstreams_file directive requires 1 or 2 arguments");
        return NGX_CONF_ERROR;
    }

    ngx_str_t *value = cf->args->elts;
    mcf->upstreams_file.data = value[1].data;
    mcf->upstreams_file.len = value[1].len;
    if (mcf->upstreams_file.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "upstreams_file directive requires a valid file path");
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        cp = ngx_strlchr(value[2].data, value[2].data + value[2].len, '=');
        if (cp == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid interval \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
        if (ngx_strncmp(value[2].data, "interval", ngx_strlen("interval")) != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid interval \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
        i = ngx_atoi(cp + 1, value[2].len - ngx_strlen("interval") -1);
        if (i == NGX_ERROR || i < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid interval \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        mcf->interval = i * 1000;
    } else {
        mcf->interval = 60 * 1000;
    }

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
        "dynamic upstreams file, \"%V\", interval %T ms",
        &mcf->upstreams_file, mcf->interval);

    return NGX_CONF_OK;
}


static void
ngx_dynamic_file_upstreams_handler(ngx_event_t *ev)
{
    dynamic_file_upstreams_main_conf_t *mcf = ev->data;
    ngx_file_t file;
    time_t mtime;
    ngx_dynamic_file_upstreams_t upstreams;

    file.name = mcf->upstreams_file;
    if (ngx_file_info(file.name.data, &file.info) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ev->log, 0, "Dynamic upstreams file not found, \"%V\"", &file.name);
        return;
    }

    mtime = ngx_file_mtime(&file.info);
    if (mtime == ngx_dynamic_file_upstreams_file_mtime) {
        ngx_log_error(NGX_LOG_DEBUG, ev->log, 0, "Dynamic upstreams file mtime unchanged, skip processing");
        return;
    }

    file.log = ev->log;
    if (NGX_ERROR == ngx_dynamic_file_upstreams_parse(&file, &upstreams)) {
        ngx_log_error(NGX_LOG_DEBUG, ev->log, 0, "Dynamic upstreams file parse failed, \"%V\"", &file.name);
        return;
    }

    ngx_http_upstream_rr_peers_print(ev->log);
    if (NGX_ERROR == ngx_dynamic_file_upstreams_update_rr_peers(&upstreams, ev->log)) {
        ngx_log_error(NGX_LOG_ERR, ev->log, 0, "Failed to update rr peers from dynamic upstreams file \"%V\"", &file.name);
    } else {
        ngx_dynamic_file_upstreams_file_mtime = mtime;
        ngx_log_error(NGX_LOG_DEBUG, ev->log, 0, "Dynamic upstreams handler called");
    }
    ngx_http_upstream_rr_peers_print(ev->log);

    if (!ngx_exiting) {
        ngx_add_timer(ev, mcf->interval);
    } else {
        ngx_log_error(NGX_LOG_DEBUG, ev->log, 0, "Dynamic file upstreams timer stopped due to exiting");
    }
}


static ngx_int_t
ngx_dynamic_file_upstreams_parse(ngx_file_t *file, ngx_dynamic_file_upstreams_t *upstreams)
{
    off_t size;
    u_char *buf;
    ssize_t n;
    ngx_log_t *log = file->log;

    size = ngx_file_size(&file->info);
    if (size == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "dynamic upstreams file is empty, skip processing");
        return NGX_ERROR;
    }

    file->fd = ngx_open_file(file->name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "Failed to open dynamic upstreams file \"%V\"", &file->name);
        goto ERROR;
    }

    buf = ngx_pcalloc(ngx_cycle->pool, size + 1);
    if (buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "Failed to allocate memory for dynamic upstreams file buffer");
        return NGX_ERROR;
    }

    n = ngx_read_file(file, buf, size, 0);
    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "Failed to read dynamic upstreams file \"%V\"", &file->name);
        goto ERROR;
    }

    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "Failed to close dynamic upstreams file \"%V\"", &file->name);
        goto ERROR;
    }
    file->fd = NGX_INVALID_FILE;

    if (n > 0) {
        buf[n] = '\0';  // Null-terminate the buffer
        ngx_log_error(NGX_LOG_DEBUG, log, 0, "Dynamic upstreams file content: %s", buf);
        if (NGX_ERROR == ngx_dynamic_file_upstreams_parse_upstreams(buf, n, log, upstreams)) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "Failed to parse dynamic upstreams file \"%V\"", &file->name);
            goto ERROR;
        }
    }

    ngx_pfree(ngx_cycle->pool, buf);
    return NGX_OK;

ERROR:
    if (buf != NULL) {
        ngx_pfree(ngx_cycle->pool, buf);
    }

    if (file->fd != NGX_INVALID_FILE) {
        ngx_close_file(file->fd);
    }
    return NGX_ERROR;
}


static ngx_int_t
ngx_dynamic_file_upstreams_parse_upstreams(const u_char *buf, size_t size, ngx_log_t *log, ngx_dynamic_file_upstreams_t *ups)
{
    ngx_dynamic_file_upstream_t *up;
    ngx_http_upstream_server_t *server;

    /* create a fake upstream */
    if (NGX_ERROR == ngx_array_init(&ups->upstreams, ngx_cycle->pool, 4, sizeof(ngx_dynamic_file_upstream_t))) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "Failed to initialize upstreams array");
        return NGX_ERROR;
    }

    /* create a fake server */
    up = ngx_array_push(&ups->upstreams);
    ngx_str_set(&up->name, "test_upstream");
    if (NGX_ERROR == ngx_array_init(&up->servers, ngx_cycle->pool, 1, sizeof(ngx_http_upstream_server_t))) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "Failed to initialize upstream servers array");
        return NGX_ERROR;
    }

    /* server 1, backup */
    server = ngx_array_push(&up->servers);
    ngx_memzero(server, sizeof(ngx_http_upstream_server_t));
    ngx_str_set(&server->name, "127.0.0.1:8080");
    server->naddrs = 1;
    server->addrs = ngx_palloc(ngx_cycle->pool, sizeof(ngx_addr_t));
    ngx_str_set(&server->addrs->name, "127.0.0.1:8080");
    if (ngx_parse_addr(ngx_cycle->pool, server->addrs, (u_char *)"127.0.0.1", ngx_strlen("127.0.0.1")) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "failed to parse address %s", "127.0.0.1");
        return NGX_ERROR;
    }
    server->weight = 1;
    server->max_conns = 100;
    server->max_fails = 5;
    server->fail_timeout = 60;
    server->slow_start = 5000;
    server->down = 0;
    /* create a fake upstream end */
    return NGX_OK;
}


static ngx_http_upstream_srv_conf_t *
ngx_dynamic_file_upstreams_find_upstream_srv_conf(ngx_http_upstream_main_conf_t *umcf, ngx_str_t name)
{
    ngx_uint_t i;
    ngx_http_upstream_srv_conf_t **uscfp;

    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (name.len != uscfp[i]->host.len || ngx_strncasecmp(name.data, uscfp[i]->host.data, name.len) != 0) {
            continue;
        }

        return uscfp[i];
    }

    return NULL;
}


/* code is largely copied from ngx_http_upstream_init_round_robin */
static ngx_int_t ngx_dynamic_file_upstreams_init_peers(
    ngx_http_upstream_rr_peers_t *peers,
    ngx_dynamic_file_upstream_t *upstream,
    ngx_log_t *log)
{
    ngx_http_upstream_rr_peers_t *backup, *old_backup;
    ngx_http_upstream_rr_peer_t *peer, *old_peer, *old_backup_peer, **peerp, *opeer;
    ngx_http_upstream_server_t *server;
    ngx_uint_t i, j;
    ngx_uint_t n, w, t;
    ngx_int_t has_backup;

    n = 0;
    w = 0;
    t = 0;
    has_backup = 0;
    server = upstream->servers.elts;
    for (i = 0; i < upstream->servers.nelts; i++) {
        if (server[i].backup) {
            has_backup = 1;
            continue;
        }
        n += server[i].naddrs;
        w += server[i].naddrs * server[i].weight;
        if (!server[i].down) {
            t += server[i].naddrs;
        }
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "no servers in upstream \"%V\"",
                      &upstream->name);
        return NGX_ERROR;
    }



    peer = ngx_slab_calloc(peers->shpool, sizeof(ngx_http_upstream_rr_peer_t) * n);
    if (peer == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "failed to allocate memory for upstream \"%V\" servers",
                      &upstream->name);
        return NGX_ERROR;
    }
    
    ngx_http_upstream_rr_peers_wlock(peers)
    if (has_backup) {
        peers->single = 0;
    } else {
        peers->single = (n == 1);
    }
    peers->number = n;
    peers->weighted = (w != n);
    peers->total_weight = w;
    peers->tries = t;

    n = 0;
    w = 0;
    t = 0;

    old_peer = peers->peer;
    peerp = &peers->peer;
    for (i = 0; i < upstream->servers.nelts; i++) {
        if (server[i].backup) {
            continue;
        }

        for (j = 0; j < server[i].naddrs; j++) {
            peer[n].sockaddr = server[i].addrs[j].sockaddr;
            peer[n].socklen = server[i].addrs[j].socklen;
            peer[n].name = server[i].addrs[j].name;
            peer[n].weight = server[i].weight;
            peer[n].effective_weight = server[i].weight;
            peer[n].current_weight = 0;
            peer[n].max_conns = server[i].max_conns;
            peer[n].max_fails = server[i].max_fails;
            peer[n].fail_timeout = server[i].fail_timeout;
            peer[n].down = server[i].down;
            peer[n].server = server[i].name;

            *peerp = &peer[n];
            peerp = &peer[n].next;
            n++;
        }
    }

    /* copy stat data from existing peers */
    for (peer = peers->peer; peer; peer = peer->next) {
        for (opeer = old_peer; opeer; opeer = opeer->next) {
            if (peer->name.len == opeer->name.len &&
                ngx_strncmp(peer->name.data, opeer->name.data, peer->name.len) == 0 &&
                ngx_memcmp(peer->sockaddr, opeer->sockaddr, opeer->socklen) == 0 &&
                peer->socklen == opeer->socklen) {
                    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                        "Copying existing peer data for %V", &peer->name);
                    peer->conns = opeer->conns;
                    peer->fails = opeer->fails;
                    peer->accessed = opeer->accessed;
                    peer->checked = opeer->checked;
                    peer->slow_start = opeer->slow_start;
                    peer->start_time = opeer->start_time;
                    #if (NGX_HTTP_SSL)
                    peer->ssl_session = opeer->ssl_session;
                    peer->ssl_session_len = opeer->ssl_session_len;
                    #endif
                    break;
            }
        }
    }

    ngx_http_upstream_rr_peers_unlock(peers);

    /* do the same for backup servers */
    n = 0;
    w = 0;
    t = 0;

    if (has_backup) {
        for (i = 0; i < upstream->servers.nelts; i++) {
            if (!server[i].backup) {
                continue;
            }
    
            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;
    
            if (!server[i].down) {
                t += server[i].naddrs;
            }
        }
    }

    if (n == 0) {
        backup = peers->next;
        if (backup) {
            old_backup_peer = backup->peer;
            ngx_slab_free(peers->shpool, backup);
        } else {
            old_backup_peer = NULL;
        }
        peers->next = NULL;
        goto FINISH;
    }

    if (peers->next != NULL) {
        backup = peers->next;
        old_backup_peer = backup->peer;
    } else {
        backup = ngx_slab_calloc(peers->shpool, sizeof(ngx_http_upstream_rr_peers_t));
        if (backup == NULL) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "failed to allocate memory for upstream \"%V\" backup servers",
                          &upstream->name);
            return NGX_ERROR;
        }
        old_backup_peer = NULL;
    }

    peer = ngx_slab_calloc(peers->shpool, sizeof(ngx_http_upstream_rr_peer_t) * n);
    if (peer == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "failed to allocate memory for upstream \"%V\" backup server",
                      &upstream->name);
        ngx_slab_free(peers->shpool, backup);
        return NGX_ERROR;
    }

    /* put backup initialization logic here, so that memory allocation failures above do
       not affect existing backup servers */
    if (backup != peers->next) {
        backup->name = peers->name;
        backup->shpool = peers->shpool;
        peers->next = backup;
        old_backup_peer = NULL;
    }

    ngx_http_upstream_rr_peers_wlock(backup);
    backup->single = 0;
    backup->number = n;
    backup->weighted = (w != n);
    backup->total_weight = w;
    backup->tries = t;
    backup->name = &upstream->name;

    peerp = &backup->peer;
    n = 0;
    for (i = 0; i < upstream->servers.nelts; i++) {
        if (!server[i].backup) {
            continue;
        }

        for (j = 0; j < server[i].naddrs; j++) {
            peer[n].sockaddr = server[i].addrs[j].sockaddr;
            peer[n].socklen = server[i].addrs[j].socklen;
            peer[n].name = server[i].addrs[j].name;
            peer[n].weight = server[i].weight;
            peer[n].effective_weight = server[i].weight;
            peer[n].current_weight = 0;
            peer[n].max_conns = server[i].max_conns;
            peer[n].max_fails = server[i].max_fails;
            peer[n].fail_timeout = server[i].fail_timeout;
            peer[n].down = server[i].down;
            peer[n].server = server[i].name;

            *peerp = &peer[n];
            peerp = &peer[n].next;
            n++;
        }
    }

    /* again, copy stat data from existing backup peers */
    for (peer = backup->peer; peer; peer = peer->next) {
        for (opeer = old_backup_peer; opeer; opeer = opeer->next) {
            if (peer->name.len == opeer->name.len &&
                ngx_strncmp(peer->name.data, opeer->name.data, peer->name.len) == 0 &&
                ngx_memcmp(peer->sockaddr, opeer->sockaddr, opeer->socklen) == 0 &&
                peer->socklen == opeer->socklen) {
                    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                        "Copying existing peer data for backup server %V", &peer->name);
                    peer->conns = opeer->conns;
                    peer->fails = opeer->fails;
                    peer->accessed = opeer->accessed;
                    peer->checked = opeer->checked;
                    peer->slow_start = opeer->slow_start;
                    peer->start_time = opeer->start_time;
                    #if (NGX_HTTP_SSL)
                    peer->ssl_session = opeer->ssl_session;
                    peer->ssl_session_len = opeer->ssl_session_len;
                    #endif
                    break;
            }
        }
    }

    ngx_http_upstream_rr_peers_unlock(backup)

FINISH:

    /* release memory from old peers */
    while (old_peer) {
        if (old_peer->server.data) {
            ngx_slab_free(peers->shpool, old_peer->server.data);
        }

        if (old_peer->name.data) {
            ngx_slab_free(peers->shpool, old_peer->name.data);
        }

        if (old_peer->sockaddr) {
            ngx_slab_free(peers->shpool, old_peer->sockaddr);
        }

        opeer = old_peer->next;
        ngx_slab_free(peers->shpool, old_peer);
        old_peer = opeer;
    }

    while (old_backup_peer) {
        if (old_backup_peer->server.data) {
            ngx_slab_free(peers->shpool, old_backup_peer->server.data);
        }

        if (old_backup_peer->name.data) {
            ngx_slab_free(peers->shpool, old_backup_peer->name.data);
        }

        if (old_backup_peer->sockaddr) {
            ngx_slab_free(peers->shpool, old_backup_peer->sockaddr);
        }

        opeer = old_backup_peer->next;
        ngx_slab_free(peers->shpool, old_backup_peer);
        old_peer = opeer;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_dynamic_file_upstreams_update_rr_peers(const ngx_dynamic_file_upstreams_t *upstreams, ngx_log_t *log) {
    ngx_http_upstream_main_conf_t *umcf;
    ngx_http_upstream_srv_conf_t *uscf;
    ngx_dynamic_file_upstream_t *dfup;
    ngx_http_upstream_rr_peers_t *peers;
    ngx_str_t name;
    ngx_uint_t i;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_upstream_module);
    if (umcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "main conf of ngx_http_upstream_module not found");
        return NGX_ERROR;
    }

    dfup = upstreams->upstreams.elts;
    for (i = 0; i < upstreams->upstreams.nelts; i++) {
        name = dfup[i].name;
        uscf = ngx_dynamic_file_upstreams_find_upstream_srv_conf(umcf, name);
        if (uscf == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "Upstream \"%V\" srv conf found, skip", &name);
            continue;
        }

        if (uscf->peer.data == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "No existing peers data for upstream \"%V\"", &name);
            continue;
        }
        peers = uscf->peer.data;

        if (uscf->shm_zone == NULL) {
            ngx_log_error(NGX_LOG_WARN, log, 0, "No shared memory zone for upstream \"%V\"", &name);
            continue;
        }

        if (ngx_dynamic_file_upstreams_init_peers(peers, &dfup[i], log) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "Failed to initialize peers for upstream \"%V\"", &name);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


#ifdef NGX_DEBUG
static void
ngx_http_upstream_rr_peers_print(ngx_log_t *log)
{
    ngx_http_upstream_main_conf_t *umcf;
    ngx_http_upstream_srv_conf_t **uscfp;
    ngx_http_upstream_rr_peers_t *peers;
    ngx_http_upstream_rr_peer_t *peer;
    ngx_uint_t i;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        peers = uscfp[i]->peer.data;
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "Upstream: %V", &uscfp[i]->host);
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "Peers count: %ui", peers->number);
        for (peer = peers->peer; peer; peer = peer->next) {
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "name: %V", &peer->name);
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "server: %V", &peer->server);
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "weight: %i", peer->weight);
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "conns: %ui", peer->conns);
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "max_conns: %ui", peer->max_conns);
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "max_fails: %ui", peer->max_fails);
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "fail_timeout: %T", peer->fail_timeout);
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "current_weight: %i", peer->current_weight);
        }
        if (peers->next) {
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "Backup server count: %ui", peers->next->number);
            peer = peers->next->peer;
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "Backup Peer: %V", &peer->server);
        }
    }
    
}
#else
static void
ngx_http_upstream_rr_peers_print(ngx_log_t *log) {}
#endif