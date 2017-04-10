#
# $Id$
#
#---------------------------------------
# --- Model :: Users --
#---------------------------------------

package MiniCA::Model::Users;


use strict;
use warnings;
use utf8;
use Encode qw(encode decode);

use open qw/:std :utf8/;
use Mojo::Util qw(b64_decode);

binmode(STDOUT,':utf8');


sub new {
    my ($class, $app, $pwFile) = @_;
    my $self = { app => $app, 
		 pwFile => $pwFile,
                 masterUser => 'master'
    };
    bless $self, $class;
    return $self;
}

sub hello {
    my $self = shift;
    return 'Hello!';
}

sub app {
    my $self = shift;
    return $self->{app};
}

sub masterUser {
    my $self = shift;
    return $self->{masterUser};
}

sub pwFile {
    my ($self, $pwFile)  = @_;
    $self->{pwFile} = $pwFile if $pwFile;
    return $self->{pwFile};
}

sub newHT {
    my $self = shift;
    my $passwd_file = $self->pwFile;
    return Apache::Htpasswd->new($passwd_file);
}

sub auth {
    my ($self, $username, $password) = @_;
    my $ht = $self->newHT;;
    return 1 if $ht->htCheckPassword($username, $password);
    return undef;
}

sub create {
    my ($self, $username, $password, $name) = @_;
    return undef unless $username;
    return undef unless $password;
    return undef unless $name;
    my $ht = $self->newHT;;
    return undef unless $ht->htpasswd($username, $password);
    return undef unless $ht->writeInfo($username, $name);
    return 1;
}

sub delete {
    my ($self, $username) = @_;
    return undef unless $username;
    my $ht = $self->newHT;;
    return 1 if $ht->htDelete($username);
    return undef;
}

sub exist {
    my ($self, $username) = @_;
    return undef unless $username;
    my $ht = $self->newHT;;
    return 1 if $ht->fetchPass($username);
    return undef;
}

sub password {
    my ($self, $username, $password) = @_;
    return undef unless $username;
    my $ht = $self->newHT;
    return $ht->htpasswd($username, $password, {'overwrite' => 1}) if $password;
    return $ht->fetchPass($username);
}

sub info {
    my ($self, $username, $info) = @_;
    return undef unless $username;
    my $ht = $self->newHT;
    return $ht->writeInfo($username, $info) if $info;
    return decode('utf8', $ht->fetchInfo($username));
}

sub list {
    my $self = shift;
    my $ht = $self->newHT;
    return $ht->fetchUsers;
}


1;

#EOF
