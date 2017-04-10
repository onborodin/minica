#!/usr/bin/env perl
# ABSTRACT: A simple message broker using Mojolicious WebSockets
# USAGE: ./socket.pl daemon
#
# Try the demo and read the explanation on the page before reading the code.
#
# Copyright 2015 Doug Bell (<preaction@cpan.org>)
#
# This is free software; you can redistribute it and/or modify it under
# the same terms as the Perl 5 programming language system itself.

use Mojolicious::Lite;
use Scalar::Util qw( refaddr );

my $id = 0;
my %topics;

=method add_topic_subscriber

    $c->add_topic_subscriber( $topic );

Add the current connection as a subscriber to the given topic. Connections can
be subscribed to only one topic, but they will receive all messages to
child topics as well.

=cut

helper add_topic_subscriber => sub {
    my ( $self, $topic ) = @_;
    $topics{ $topic }{ refaddr $self } = $self;
    return;
};

=method remove_topic_subscriber

    $c->remote_topic_subscriber( $topic );

Remove the current connection from the given topic. Must be called to clean up
the state.

=cut

helper remove_topic_subscriber => sub {
    my ( $self, $topic ) = @_;
    delete $topics{ $topic }{ refaddr $self };
    return;
};

=method publish_topic_message

    $c->publish_topic_message( $topic, $message );

Publish a message on the given topic. The message will be sent once to any subscriber
of this topic or any child topics.

=cut

helper publish_topic_message => sub {
    my ( $self, $topic, $message ) = @_;
    my @parts = split m{/}, $topic;
    my @topics = map { join '/', @parts[0..$_] } 0..$#parts;
    for my $topic ( @topics ) {
        $_->send( $message ) for values %{ $topics{ $topic } };
    }
    return;
};

any '/' => 'index';

=route /sub/*topic

Establish a WebSocket to subscribe to the given C<topic>. Messages published
to the topic or any child topics will be sent to this subscriber.

=cut

websocket '/sub/*topic' => sub {
    my ( $c ) = @_;
    Mojo::IOLoop->stream($c->tx->connection)->timeout(1200);

    my $topic = $c->stash( 'topic' );
    $c->add_topic_subscriber( $topic );

    $c->on( finish => sub {
        my ( $c ) = @_;
        $c->remove_topic_subscriber( $topic );
    } );
} => 'sub';

=route /pub/*topic

Establish a WebSocket to publish to the given C<topic>. Messages published to
the topic will be sent to all subscribers to the topic or any parent topics.

=cut

websocket '/pub/*topic' => sub {
    my ( $c ) = @_;
    Mojo::IOLoop->stream($c->tx->connection)->timeout(1200);

    my $topic = $c->stash( 'topic' );
    $c->on( message => sub {
        my ( $c, $message ) = @_;
        $c->publish_topic_message( $topic, $message );
    } );
} => 'pub';

app->start;

__DATA__

@@ layouts/standard.html.ep

<!DOCTYPE html>
<html>
  <head>
    <title>
      %= title
    </title>
    <script src="//ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>
    <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" />
    <style>
        .log p { margin: 0; }
    </style>
  </head>
  <body>
    %= content
  </body>
</html>

@@ index.html.ep

% layout 'standard';
% title 'Mojolicious Message Broker';

<div class="container">

    <div class="row">
        <div class="col-md-12">
            <h1>Pure-Mojolicious Message Broker</h1>
        </div>
    </div>

    <div class="row">
        <div class="col-md-6">

            <p>WebSockets are a powerful tool, enabling many features previously
            impossible, difficult, or ugly for web developers to implement. Where
            once only an HTTP request could get data from a server, now a persistent
            socket can allow the server to send updates without the client needing
            to specifically request it.</p>

            <p>WebSockets do not need to be a communication channel purely
            between browser and server. The Mojolicious web framework has
            excellent support for WebSockets. Using that support, we can
            communicate between different server processes. This solves the
            problem with client-to-client communication in a parallelized web
            server where all clients may not be connected to the same server
            process. The server processes can use a central message broker to
            coordinate and pass messages from one client to another.</p>

            <p>This is a message broker that enables a simple publish/subscribe
            messaging pattern. A single socket is either a subscription to all
            messages on a topic, or a publishing socket allowed to send messages
            to that topic.</p>

        </div>
        <div class="col-md-6">

            <p>Requesting a WebSocket from the URL <code>/sub/leela</code>
            creates a subscription to the topic "leela". Requesting a WebSocket
            from the URL <code>/pub/leela</code> allows sending messages to the
            "leela" topic, which are then received by all the subscribers.</p>

            <p>Topics are heirarchical to allow for broad subscriptions without
            requring more sockets. A subscription to the topic "wong" receives
            all messages published to the topic "wong" or any child topic like
            "wong/amy" or "wong/leo"</p>

            <p>This is free software; you can redistribute it and/or modify it
            under the same terms as the Perl 5 programming language system
            itself.</p>

            <p><a href="https://gist.github.com/2078d33d87b126621e45"><strong>See the code</strong></a></p>

        </div>
    </div>

    <div class="row">

        <div class="col-md-6">
            <h2>Subscribe</h2>
            <p>Type in a topic and press Enter to subscribe to that topic.</p>

            <form id="sub-form">
                <div id="sub-topic-field" class="form-group">
                    <label for="sub-topic">Topic: </label>
                    <div class="input-group">
                        <span class="input-group-addon">/</span>
                        <input type="text" id="sub-topic" class="form-control" />
                        <span class="input-group-btn">
                            <button class="btn btn-primary">Subscribe</button>
                        </span>
                    </div>
                </div>
            </form>
            <div id="sub-log" class="log"></div>
        </div>

        <div class="col-md-6">
            <h2>Publish</h2>

            <p>Once you're subscribed, type in a topic and a message to send a message
            on that topic.</p>

            <form id="pub-form">
                <div id="pub-topic-field" class="form-group has-feedback">
                    <label for="pub-topic">Topic: </label>
                    <div class="input-group">
                        <span class="input-group-addon">/</span>
                        <span class="glyphicon glyphicon-warning-sign form-control-feedback" aria-hidden="true"></span>
                        <span class="glyphicon glyphicon-ok-sign form-control-feedback" aria-hidden="true"></span>
                        <input type="text" id="pub-topic" class="form-control" />
                    </div>
                </div>
                <div class="form-group">
                    <label for="message">Message: </label>
                    <div class="input-group">
                        <input type="text" id="message" class="form-control" />
                        <span class="input-group-btn">
                            <button class="btn btn-primary">Publish</button>
                        </span>
                    </div>
                </div>
            </form>
            <div id="pub-log" class="log"></div>
        </div>

    </div>

</div>

%= javascript begin

    var pub_ws;
    var pub_topic;
    var sub_ws;
    var sub_topic;

    function send_message() {
        var message = $( '#message' ).val();
        pub_ws.send( message );
        $( '#pub-log' ).prepend( '<p>' + message + '</p>' );
    }

    function publish ( event ) {
        event.preventDefault();
        var new_topic = $( '#pub-topic' ).val();
        if ( pub_topic != new_topic ) {
            $( '#pub-log' ).prepend( '<p>### Publishing on /' + new_topic + '</p>' );
            pub_ws = new WebSocket( '<%= url_for('pub')->to_abs %>' + new_topic );
            pub_ws.onopen = function () {
                send_message();
                pub_topic = new_topic;
                $( '#pub-topic-field' ).addClass( 'has-success' );
            };
            pub_ws.onclose = function ( ) {
                pub_topic = undefined;
                pub_ws = undefined;
                $( '#pub-log' ).prepend( '<p>### Disconnected</p>' );
                $( '#pub-topic-field' ).removeClass( 'has-success' );
            };
        }
        else {
            send_message();
        }
    }

    function subscribe ( event ) {
        event.preventDefault();
        var new_topic = $( '#sub-topic' ).val();
        if ( sub_topic != new_topic ) {
            $( '#sub-log' ).prepend( '<p>### Subscribed to /' + new_topic + '</p>' );
            sub_ws = new WebSocket( '<%= url_for('sub')->to_abs %>' + new_topic );
            sub_ws.onopen = function ( event ) {
                $( '#sub-topic-field' ).addClass( 'has-success' );
            };
            sub_ws.onmessage = function ( event ) {
                $( '#sub-log' ).prepend( '<p>' + event.data + '</p>' );
            };
            sub_ws.onclose = function ( ) {
                sub_topic = undefined;
                sub_ws = undefined;
                $( '#sub-log' ).prepend( '<p>### Disconnected</p>' );
                $( '#sub-topic-field' ).removeClass( 'has-success' );
            };
            sub_topic = new_topic;
        }
    }

    $(function(){
        $( '#pub-form' ).on( 'submit', publish );
        $( '#sub-form' ).on( 'submit', subscribe );
    });

% end

