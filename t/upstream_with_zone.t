use v5.36;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib "$FindBin::Bin/lib";
use Test::Nginx;

use IO::Handle;
STDERR->autoflush(1);
STDOUT->autoflush(1);

my $t = Test::Nginx->new()->has(qw/http proxy unix/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

  upstreams_file test_upstream interval=6s;

    upstream backend_servers {
        zone backend_zone 64k;
        server 127.0.0.1:8081;
    }

    server {
        listen 8080;

        location / {
            proxy_pass http://backend_servers/;
        }
    }

    server {
        listen       127.0.0.1:8081-8082;
        listen       unix:/tmp/unix.sock;

        location / {
            return 200 "$server_addr:$server_port";
        }
    }
}

EOF

$t->write_file("test_upstream", <<'EOF');

upstream backend_servers {
    server 127.0.0.1:8082;
    server unix:/tmp/unix.sock;
    server 1.2.3.4:9990 backup;
    server 1.2.3.4:9991 down;
}

EOF

$t->try_run('ipv4')->plan(12);

# tests with inet socket

my $socket = IO::Socket::INET->new(
			Proto => 'tcp',
			PeerAddr => '127.0.0.1:' . 8081,
		);
like(http_get('/', {
    socket => $socket
}), qr/404 Not Found/, 'initially 8081 is not in upstream');
