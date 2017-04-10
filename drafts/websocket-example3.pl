#!/usr/bin/env perl
use Mojolicious::Lite;

# Documentation under "/perldoc"
plugin 'PODRenderer';

# Template with browser-side code
get '/' => 'index';

# WebSocket log service
websocket '/log' => sub {
    my $self = shift;

    my $c = $self;

    my $i = 1;
    my $id = Mojo::IOLoop->recurring(1 => sub {
        $c->send('tik-tak #'.$i);
        $i++;
#        $c->finish if $i++ == 25;
    });

    $c->on(finish => sub { Mojo::IOLoop->remove($id) });
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
