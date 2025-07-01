## Table of Contents
- Name
- Description
- Status
- Synopsis
- Directives
- Caveats and Limitations
- Compatibiliy with Nginx version
- Installation
- Author
- See Also
 
## Name
ngx_dynamic_file_upstreams_module

## Description
Nginx is a famous high permormance reverse proxy and HTTP server. However, its conspicuous lack of ability to modify its configuration at runtime (without reloading) makes it unfit for highly dynamic HTTP environments. Dynamic upstream support is one of the common difficulties. There are already some very good solutions to address this difficulty

1. `balancer_by_lua` from the [ngx_lua module](http://github.com/openresty/lua-nginx-module) is a powerful way to set upstream servers in lua script
2. [ngx_dynamic_upstream](https://github.com/cubicdaiya/ngx_dynamic_upstream) module exposes HTTP API for upstream modification
3. [nginx-upsync-module](https://github.com/weibocom/nginx-upsync-module) achieves this by making use of Consul/Etcd

ngx_dynamic_file_upstreams_module, however, takes a file-based approach and have nginx parse an upstreams text file when it is modified and automatically reload upstreams defined in it.

## Status
this module is not production-ready yet, more work wants to be done

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
    server 127.0.0.1:8082 weight=1 fail_timeout=1m max_conns=1000 backup;
    server unix:/tmp/backend3 down;
}

upstream test_upsteam2 {
    ...
}
```

the format of upstreams file is basically the same as Nginx upstream block, except that only *server* line is allowed (zone and upstream load-balance method are disallowed).

## Directives

`upstreams_file /path/to/upstreams_file interval=time`

where time is any valid time interval supported by Nginx, see https://nginx.org/en/docs/syntax.html#time.

The default unit is second.

## Caveats and Limitations
First and foremost, only upstreams which are already defined in the original Nginx configuration can be specified in the upstream file. Namely, one cannot add new upstreams at runtime.
Secondly, file-based dynamic upstreams relies on upstream 'zone' feature(shared memory across worker processes). Therefore, the `zone` directive must be present in the original nginx upstream block. If not, new upstream configuration will be skipped with a warn nginx log message.

Note that currently load balance method 'ramdom' is not working, since it involves some extra initialization step than other methods.

## Compatibiliy with Nginx version
Tested with Nginx version 1.29.0 on Linux, earlier versions should work just fine. Windows platform is not yet tested.

## Installation
Please follow standard module compilation step

    ./auto/configure --add-module=/path/to/module_dir

or

    ./auto/configure --add-dynamic-module=/path/to/module_dir

then

    make

For dynamic module build, there will be *ngx_dynamic_file_upstreams_module.so* in folder objs/ which can be loaded by nginx via 'load_module' directive.

## Author
ninjken endeavourken@outlook.com

Please raise issues if you find any problem :-).

## TODO
- support random load-balance method
- add standard Nginx tests




