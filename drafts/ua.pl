#!/usr/local/bin/perl

use 5.010;
use Mojo::UserAgent;
use Mojo::IOLoop;

my $ua = Mojo::UserAgent->new;

my $res = 'ws://echo.websocket.org';
#my $res = 'ws://127.0.0.1:3000/log';

$ua->websocket($res => sub {

    my ($ua, $tx) = @_;

    print "websocket handshake failed!\n" and return unless $tx->is_websocket;

    $tx->on(finish => sub {
        my ($tx, $code, $reason) = @_;
#        Mojo::IOLoop->remove($id);
        $tx->finish;
    });

    $tx->on(message => sub {
        my ($tx, $msg) = @_;
        print "websocket message: $msg\n";
#        $tx->finish;
    });

    my $i = 1;

    my $id = Mojo::IOLoop->recurring(1 => sub {
        $tx->send('tik-tak #'.$i);
        $i++;
        $tx->finish if $i == 12;
    });


#    $c->on(finish => sub { Mojo::IOLoop->remove($id) });

});

Mojo::IOLoop->start unless Mojo::IOLoop->is_running;
#EOF





