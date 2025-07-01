## Table of Contents
- Name
- Description
- Synopsis
- Directives
- Status
- Caveats and Limitations
- Compatibiliy with Nginx version
- Installation
- Author
- See Also
 
## Name
ngx_dynamic_file_upstreams_module

## Description
Nginx is a famous high permormance reverse proxy and HTTP server. However, its conspicuous lack of ability to modify its configuration at runtime (without reloading) makes it unfit for highly dynamic HTTP environments. Dynamic upstream support, for instance, is one of the common difficulties. There are already some very good solutions to address dynamic upstreams problem

1. `balancer_by_lua` from the [ngx_lua module](http://github.com/openresty/lua-nginx-module] is a powerful way to set upstream servers in lua script
2. [ngx_dynamic_upstream](https://github.com/cubicdaiya/ngx_dynamic_upstream) module exposes HTTP API for upstream modification
3. [nginx-upsync-module](https://github.com/weibocom/nginx-upsync-module) achieves this by making use of Consul/Etcd

This module takes a file-based approach and have nginx parse an upstreams text file when it is changed and reload upstreams automatically.

## Synopsis
Nginx configuration

```nginx
http {
    upstream test_upstream {
        zone test 256k;
        server 1.2.3.4:8080 weight=1 max_conns=100;
        server 1.2.3.4:8082 fail_timeout=1m weight=1 max_conns=100;
        server 5.6.7.8 down;
    }

    upstreams_file /opt/nginx/test_upstreams_file interval=15s;

    server {
        listen 8090;
        location / {
            proxy_pass http://test_upstream;
        }
    }
}
```

with */opt/nginx/test_upstream_file*

```txt
upstream test_upstream {
    #this is a demonstration file
    server 127.0.0.1:8080 weight=1 max_conns=100;
    server 127.0.0.1:8082 weight=1 fail_timeout=1m max_conns=1000;
    server unix:/tmp/backend3 down;
}
```

the format of upstreams file is basically the same as Nginx upstream block, except that only server line is allowed (zone and upstream selection algo are disallowed).

## Directives

`upstreams_file /path/to/upstreams_file interval=t`

## Caveats and Limitations
In order for the new upstreams to work, `zone` directive must be present in the original nginx upstream configuration, since the implementation uses shared memory to share upstream information across worker processes.

- Compatibiliy with Nginx version
- Installation
- Author
- See Also



