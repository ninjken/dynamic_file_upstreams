/* use ngx_http_upstream_zone_module.c and ngx_http_auth_basic_module.c
   and ngx_http_upstream.c as references */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* function declarations */
static void *dynamic_file_upstreams_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ngx_dynamic_file_upstreams_init_process(ngx_cycle_t *cycle);
static char *set_ngx_dynamic_file_upstreams_timer(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_dynamic_file_upstreams_handler(ngx_event_t *ev);

static ngx_event_t ngx_dynamic_file_upstreams_timer;
time_t ngx_dynamic_file_upstreams_file_mtime;

/* upstreams_file /path/to/file interval(seconds) */
static ngx_command_t ngx_dynamic_file_upstreams_commands[] = {
    { ngx_string("upstreams_file"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE12,
        set_ngx_dynamic_file_upstreams_timer,
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


static ngx_int_t ngx_dynamic_file_upstreams_init_process(ngx_cycle_t *cycle)
{
    if (ngx_worker != 0) {
        return NGX_OK;  /* only the master process should set the timer */
    }
    dynamic_file_upstreams_main_conf_t *mcf;

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
    return NGX_OK;
}

static char *
set_ngx_dynamic_file_upstreams_timer(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    dynamic_file_upstreams_main_conf_t *mcf;
    ngx_int_t i;

    mcf = ngx_http_cycle_get_module_main_conf(cf->cycle, ngx_dynamic_file_upstreams_module);

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

    ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
        "dynamic upstreams file, \"%V\", interval %T ms",
        &mcf->upstreams_file, mcf->interval);

    return NGX_CONF_OK;
}


void
ngx_dynamic_file_upstreams_handler(ngx_event_t *ev)
{
    dynamic_file_upstreams_main_conf_t *mcf = ev->data;
    time_t mtime;

    ngx_file_info_t file_info;
    if (ngx_file_info(mcf->upstreams_file.data, &file_info) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ev->log, 0, "Dynamic upstreams file not found, \"%V\"", &mcf->upstreams_file);
        ngx_add_timer(ev, mcf->interval);
        return;
    }

    mtime = ngx_file_mtime(&file_info);
    if (mtime != ngx_dynamic_file_upstreams_file_mtime) {
        ngx_dynamic_file_upstreams_file_mtime = mtime;
        ngx_log_error(NGX_LOG_INFO, ev->log, 0, "Dynamic upstreams file changed, \"%V\", mtime is %T", &mcf->upstreams_file, ngx_dynamic_file_upstreams_file_mtime);
        // read and parse the file here
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, 0, "Dynamic upstreams handler called");
    ngx_add_timer(ev, mcf->interval);
}

/* stop the timer on reload or exit */