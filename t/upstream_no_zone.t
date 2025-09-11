# basic test without zone directive and two worker processes, so that we know that
# both worker processes can update the upstreams from the file.

###############################################################################

use v5.36;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib "$FindBin::Bin/../../../nginx-tests/lib";
use Test::Nginx;

use IO::Handle;
STDERR->autoflush(1);
STDOUT->autoflush(1);

my $t = Test::Nginx->new()->has(qw/http proxy unix/);

$t->write_file_expand( 'nginx.conf', <<'EOF' );

%%TEST_GLOBALS%%

daemon off;

worker_processes 2;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstreams_file %%TESTDIR%%/test_upstream interval=3s;

    upstream backend_servers {
        server 127.0.0.1:8081;
        server 1.2.3.4:8000 backup;
    }

    server {
        listen 127.0.0.1:8080;

        location / {
            proxy_pass http://backend_servers/;
        }
    }

    server {
        listen       127.0.0.1:8081-8082;
        listen       unix:/tmp/dynamic_upstream.sock;

        location / {
            return 200 "$server_addr:$server_port";
        }
    }
}

EOF

$t->write_file( "test_upstream", <<'EOF' );

upstream backend_servers {
    server 127.0.0.1:8082;
    server 1.2.3.4:9991 down;
    server 1.2.3.4:9990 backup;
}

EOF


$t->try_run('test ipv4')->plan(3);

like( http_get('/'), qr/127.0.0.1:8081/, 'initially 8081' );

sleep 4;

like( http_get('/'), qr/127.0.0.1:8082/, 'dynamic upstream file parsed' );

sleep 4;

# update dynamic upstream file again
$t->write_file( "test_upstream", <<'EOF' );

upstream backend_servers {
    server unix:/tmp/dynamic_upstream.sock;
}

EOF
sleep 4;

like( http_get('/'), qr!unix:/tmp/dynamic_upstream.sock!, 'dynamic upstream file modified' );
