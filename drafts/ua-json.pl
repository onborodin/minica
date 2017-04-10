#!/usr/local/bin/perl 
use strict; 
use Mojo::UserAgent; 
use Data::Dumper; 

my $t = Mojo::UserAgent->new; 
my $tx = $t->post('http://localhost:5100/hello' => json => {  a => '1', b => '2'}); 
my $res = $tx->res->body; 
printf "result = %s\n ",Dumper($res); 
#EOF
