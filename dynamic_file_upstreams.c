/* use ngx_http_upstream_zone_module.c and ngx_http_auth_basic_module.c
   and ngx_http_upstream.c as references */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* function declarations */
static void *dynamic_file_upstreams_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ngx_dynamic_file_upstreams_init_process(ngx_cycle_t *cycle);
static char *set_dynamic_file_upstreams_timer(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_dynamic_file_upstreams_handler(ngx_event_t *ev);
static ngx_int_t ngx_dynamic_file_upstreams_check_then_parse(ngx_str_t path, ngx_pool_t *pool, ngx_log_t *log);
static ngx_int_t ngx_dynamic_file_upstreams_parse(u_char *buf, size_t size, ngx_log_t *log);


static ngx_event_t ngx_dynamic_file_upstreams_timer;
time_t ngx_dynamic_file_upstreams_file_mtime;

/* upstreams_file /path/to/file interval(seconds) */
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
    ngx_pool_t *pool;
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
        i = ngx_atoi(value[2].data, value[2].len);
        if (i == NGX_ERROR || i < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid interval \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        mcf->interval = i * 1000;
    } else {
        mcf->interval = 60 * 1000;
    }
    mcf->pool = cf->cycle->pool;

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
        "dynamic upstreams file, \"%V\", interval %T ms",
        &mcf->upstreams_file, mcf->interval);

    return NGX_CONF_OK;
}


static void
ngx_dynamic_file_upstreams_handler(ngx_event_t *ev)
{
    dynamic_file_upstreams_main_conf_t *mcf = ev->data;

    ngx_dynamic_file_upstreams_check_then_parse(mcf->upstreams_file, mcf->pool, ev->log);
    ngx_log_error(NGX_LOG_DEBUG, ev->log, 0, "Dynamic upstreams handler called");
    if (!ngx_exiting) {
        ngx_add_timer(ev, mcf->interval);
    } else {
        ngx_log_error(NGX_LOG_DEBUG, ev->log, 0, "Dynamic file upstreams timer stopped due to exiting");
    }
}

static ngx_int_t
ngx_dynamic_file_upstreams_check_then_parse(ngx_str_t path, ngx_pool_t *pool, ngx_log_t *log)
{
    ngx_file_t fi;
    time_t mtime;
    off_t size;
    u_char *buf;
    ssize_t n;

    fi.name = path;
    fi.log = log;
    if (ngx_file_info(path.data, &fi.info) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "Dynamic upstreams file not found, \"%V\"", &path);
        return NGX_ERROR;
    }

    mtime = ngx_file_mtime(&fi.info);
    if (mtime == ngx_dynamic_file_upstreams_file_mtime) {
        ngx_log_error(NGX_LOG_DEBUG, log, 0, "Dynamic upstreams file mtime unchanged, skip processing");
        return NGX_OK;
    }

    size = ngx_file_size(&fi.info);
    if (size == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "dynamic upstreams file is empty, skip processing");
        return NGX_ERROR;
    }

    buf = ngx_pcalloc(pool, size + 1);
    if (buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "Failed to allocate memory for dynamic upstreams file buffer");
        return NGX_ERROR;
    }

    fi.fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fi.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "Failed to open dynamic upstreams file \"%V\"", &path);
        goto ERROR;
    }


    n = ngx_read_file(&fi, buf, size, 0);
    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "Failed to read dynamic upstreams file \"%V\"", &path);
        goto ERROR;
    }

    if (ngx_close_file(fi.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "Failed to close dynamic upstreams file \"%V\"", &path);
        goto ERROR;
    }

    if (n > 0) {
        buf[n] = '\0';  // Null-terminate the buffer
        ngx_log_error(NGX_LOG_DEBUG, log, 0, "Dynamic upstreams file content: %s", buf);
        if (ngx_dynamic_file_upstreams_parse(buf, n, log) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "Failed to parse dynamic upstreams file \"%V\"", &path);
            goto ERROR;
        }
    }

    ngx_dynamic_file_upstreams_file_mtime = mtime;
    ngx_log_error(NGX_LOG_NOTICE, log, 0, "Dynamic upstreams file \"%V\" updated", &path);
    return NGX_OK;

ERROR:
    if (buf != NULL) {
        ngx_pfree(pool, buf);
    }
    if (fi.fd != NGX_INVALID_FILE) {
        ngx_close_file(fi.fd);
    }
    return NGX_ERROR;
}


static ngx_int_t
ngx_dynamic_file_upstreams_parse(u_char *buf, size_t size, ngx_log_t *log) {
    return NGX_OK;
}


// static ngx_int_t
// ngx_dynamic_file_upstreams_update_rr_peers() {
//     // maybe update ngx_http_upstream_main_conf_t?
//     return NGX_OK;
// }