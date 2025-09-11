# the same with upstream_with_zone.t but without "zone" directive

# besides, worker_processes is set to auto, in order to see whether

# worker processes get updated upstreams correctly

###############################################################################
use v5.36;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib "$FindBin::Bin/../../../nginx-tests/lib";
use Test::Nginx;

use IO::Handle;
STDERR->autoflush(1);
STDOUT->autoflush(1);

my $t = Test::Nginx->new()->has(qw/http proxy/);

$t->write_file_expand( 'nginx.conf', <<'EOF' );

%%TEST_GLOBALS%%

worker_processes auto;

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstreams_file %%TESTDIR%%/test_upstream interval=6s;

    upstream backend_servers {
        server 127.0.0.1:8081;
    }

    server {
        listen 127.0.0.1:8080;

        location / {
            proxy_pass http://backend_servers/;
        }
    }

    server {
        listen       127.0.0.1:8081-8082;

        location / {
            return 200 "$server_addr:$server_port";
        }
    }
}

EOF

$t->write_file( "test_upstream", <<'EOF' );

upstream backend_servers {
    server 127.0.0.1:8082;
    server 1.2.3.4:9990 backup;
    server 1.2.3.4:9991 down;
}

EOF

$t->try_run('test ipv4')->plan(2);

like( http_get('/'), qr/127.0.0.1:8081/, 'initially 8081' );

sleep 7;

like( http_get('/'), qr/127.0.0.1:8082/, 'dynamic upstream file parsed' );
