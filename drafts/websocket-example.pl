#!/usr/bin/env perl
use Mojolicious::Lite;

# Documentation under "/perldoc"
plugin 'PODRenderer';

# Template with browser-side code
get '/' => 'index';

# WebSocket log service
websocket '/log' => sub {
  my $self = shift;

  # Subscribe to "message" event of Mojo::Log
  my $cb = $self->app->log->on(message => sub {
    my ($log, $level, @message) = @_;

    # Send message via WebSocket
    $self->send("[$level] @message");
  });

  # Unsubscribe again from "message" event of Mojo::Log
  $self->on(finish => sub {
    my $self = shift;
    $self->app->log->unsubscribe(message => $cb);
  });
};

app->start;
__DATA__

@@ index.html.ep
<!doctype html><html>
  <head><title>Mojolicious Log</title></head>
  <body>
    <%= link_to 'New window' => '/perldoc', target => '_blank' %>
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
