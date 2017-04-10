#!/usr/bin/env perl
use Mojolicious::Lite;

# Documentation under "/perldoc"
plugin 'PODRenderer';

# Template with browser-side code
get '/' => 'index';

# WebSocket log service
websocket '/log' => sub {
    my $c = shift;
    my $ua = Mojo::UserAgent->new;
    my $res = 'ws://echo.websocket.org';

    $ua->websocket($res => sub {
        my ($ua, $tx) = @_;
        return unless $tx->is_websocket;

        $tx->on(finish => sub {
            my ($tx, $code, $reason) = @_;
            $tx->finish;
        });

        $tx->on(message => sub {
            my ($tx, $msg) = @_;
            $tx->emit('resend', $msg);
    #       $tx->finish;
        });

        $tx->on(echo => sub {
            my ($tx, $msg) = @_;
            $tx->send('ho-ho!');
    #       $tx->finish;
        });
        $tx->send('ho-ho!');

    });

    $c->on(resend => sub {
        my ($c, $msg) = @_;
        $c->app->log->debug($msg.'+');
    });

    $c->tx->emit('echo', '123');

};

app->start;
__DATA__

@@ index.html.ep
<!doctype html><html>
  <head><title>Mojolicious Log</title></head>
  <body>
    <br/>
    <script>

      // This needs a "Moz" prefix to work in Firefox
      var ws = new WebSocket('<%= url_for('log')->to_abs %>');

      // Incoming WebSocket messages
      ws.onmessage = function(event) {
        document.body.innerHTML += event.data + '<br/>';
      };
    </script>
  </body>
</html>
