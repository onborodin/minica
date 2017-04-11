#!/usr/local/bin/perl

use utf8;
use strict;
use warnings;

my $child_pid = fork();


if ($child_pid == 0) {

    open (my $STDOUT_OLD, '>&', STDOUT);
    open (STDOUT, '>', 'daemon.log');

    foreach(1..5) {
        print "p($$) c($child_pid) child is working\n";
        sleep(1);
    }

}




#if(defined $child_pid && $child_pid > 0) {
#    ## Parent
##    wait();
##    print "p($$) c($child_pid) child finished, exiting\n";
#} else {
#    ## Child
#
##    open (my $LOG, '>>', 'log.txt');
##    select $LOG;
##    pwd ("/");
#    open (my $STDOUT_OLD, '>&', STDOUT);
#    open (STDOUT, '>>', 'daemon.log');
#
##    open (my $STDERR_OLD, '>&', STDERR);
##    open (STDOUT, '>>', '/dev/null');
#
#    foreach(1..5) {
#        print "p($$) c($child_pid) child is working\n";
#        sleep(1);
#    }
#}
#EOF

