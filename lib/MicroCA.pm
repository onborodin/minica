#
# $Id$
#
package MicroCA;

use utf8;
use lib '/usr/local/share/microca/lib';
use Mojo::Base 'Mojolicious';
use Mojo::File;
use Mojo::Home;
use Mojo::Util qw(b64_encode b64_decode md5_sum);
use Config::Simple;
use MicroCA::Model::Users;
use MicroCA::Model::CA;


sub startup {
    my $self = shift;

    my $appfile = Mojo::File->new(__FILE__);

    $self->home(Mojo::Home->new("/tmp")->to_abs);
    $self->moniker('microca');

    #--- read configuratin from file ---
    my $cfgfile = "/usr/local/etc/microca/microca.conf";

    my $cfg = Config::Simple->new;
    $cfg->syntax('simple');
    $cfg->read($cfgfile);

    my $db_driver = $cfg->param('db_driver') || 'SQLite';
    my $db_host = $cfg->param('db_host') || '';
    my $db_port = $cfg->param('db_port') || '';
    my $db_name = $cfg->param('db_name') || '/var/db/microca/microca.db';

    my $dsn = "DBI:$db_driver:database=$db_name;host=$db_host;port=$db_port";

    my $db_username = $cfg->param('db_username')  || '';
    my $db_password = $cfg->param('db_password') || '';

    my $pwdfile = $cfg->param('pwdfile') || '/var/db/microca/microca.pw';
    my $datadir = $cfg->param('datadir') || '/usr/local/share/microca';
    my $pidfile = $cfg->param('pidfile') || '/var/run/microca/microca.pid';
    my $logfile = $cfg->param('logfile') || '/var/log/microca/microca.log';
    my $dbdir = $cfg->param('dbdir') || '/var/db/microca';


    my $owner = $cfg->param('user') || 'root';
    my $group = $cfg->param('group') || 'wheel';
    my $verbose = $cfg->param('verbose') || 'info';
    my $ipv4listen = $cfg->param('ipv4listen') || '127.0.0.1:5100';
    my $ipv6listen = $cfg->param('ipv6listen') || '[::1]:5100';

    my $tlscert = $cfg->param('tlscert') || undef;
    my $tlskey = $cfg->param('tlskey') || undef;
    my $tlsca = $cfg->param('tlsca') || undef;

    $self->config(
        pwdfile => $pwdfile,
        db_username => $db_username,
        db_password => $db_password,
        dsn => $dsn,
        datadir => $datadir,
        logfile => $logfile,
        pidfile => $pidfile,
        verbose => $verbose,
        dbdir => $dbdir,
        owner => $owner,
        group => $group,
        ipv4listen => $ipv4listen,
        ipv6listen => $ipv6listen
    );

    $self->config(
        tlscert => $tlscert,
        tlskey => $tlskey
    ) if ($tlscert && $tlskey);

    $self->config(
        tlsca => $tlsca
    ) if $tlsca;


    #---------------------------------
    #--- add model as state helper ---
    #---------------------------------
    $self->helper(users => sub {
        state $users = MicroCA::Model::Users->new($self, $self->config('pwdfile'));
    });

    $self->helper(ca => sub {
        state $ca = MicroCA::Model::CA->new($self,
                                             $self->config('dsn'),
                                             $self->config('db_username'),
                                             $self->config('db_password')
        );
    });

    #---------------------
    #--- define router ---
    #---------------------
    my $r = $self->routes;

    $r->add_condition(request => sub {
          my ($route, $c, $captures, $expect) = @_;
          my $request = $c->req->param('request');
          return undef unless defined $request;
          return undef unless defined $expect;
          return 1 if $request eq $expect;
          return undef;
    });

    # --- root ---
    $r->any('/')->to('main#start');

    # --- human auth ---
    $r->any('/login')->to('main#login');
    $r->any('/logout')->to('main#logout');

    $r->get('/docs')->to('main#doc');

    # --- users ---
    $r->get('/users')->to('main#userList');

    $r->post('/users')->over(request => 'user-create')->to('main#userCreate');
    $r->post('/users')->over(request => 'user-delete')->to('main#userDelete');
    $r->post('/users')->over(request => 'user-chpwd')->to('main#userChpwd');
    $r->post('/users')->over(request => 'user-chname')->to('main#userChname');


    $r->post('/users')->over(request => 'user-delete-form')->to('main#userDeleteForm');
    $r->post('/users')->over(request => 'user-chpwd-form')->to('main#userChpwdForm');
    $r->post('/users')->over(request => 'user-chname-form')->to('main#userChnameForm');

    # --- ca certs ----
    $r->get('/cacerts')->to('main#cacertList');

    $r->post('/cacerts')->over(request => 'cacert-create')->to('main#cacertCreate');
    $r->post('/cacerts')->over(request => 'cacert-delete')->to('main#cacertDelete');
    $r->post('/cacerts')->over(request => 'cacert-import')->to('main#cacertImport');
    $r->post('/cacerts')->over(request => 'cacert-revoke')->to('main#cacertRevoke');
    $r->post('/cacerts')->over(request => 'cacert-unrevoke')->to('main#cacertUnRevoke');
    $r->post('/cacerts')->over(request => 'cacert-show')->to('main#cacertShow');
    $r->post('/cacerts')->over(request => 'cacert-download')->to('main#cacertDownload');

    $r->post('/cacerts')->over(request => 'cacert-revoke-form')->to('main#cacertRevokeForm');
    $r->post('/cacerts')->over(request => 'cacert-unrevoke-form')->to('main#cacertUnRevokeForm');
    $r->post('/cacerts')->over(request => 'cacert-delete-form')->to('main#cacertDeleteForm');
    $r->post('/cacerts')->over(request => 'cacert-show-form')->to('main#cacertShowForm');
    $r->post('/cacerts')->over(request => 'cacert-download-form')->to('main#cacertDownloadForm');

    $r->post('/cacerts')->to('main#postError');

    # --- ca certs ----
    $r->get('/certs')->to('main#certListForm');
    $r->post('/certs')->over(request => 'cert-list')->to('main#certList');
    $r->post('/certs')->over(request => 'cert-create')->to('main#certCreate');
    $r->post('/certs')->over(request => 'cert-revoke')->to('main#certRevoke');
    $r->post('/certs')->over(request => 'cert-unrevoke')->to('main#certUnRevoke');
    $r->post('/certs')->over(request => 'cert-delete')->to('main#certDelete');
    $r->post('/certs')->over(request => 'cert-show')->to('main#certShow');
    $r->post('/certs')->over(request => 'cert-select')->to('main#certSelect');
    $r->post('/certs')->over(request => 'cert-download')->to('main#certDownload');
    $r->post('/certs')->over(request => 'cert-import')->to('main#certImport');

    $r->post('/certs')->over(request => 'cert-revoke-form')->to('main#certRevokeForm');
    $r->post('/certs')->over(request => 'cert-unrevoke-form')->to('main#certUnRevokeForm');
    $r->post('/certs')->over(request => 'cert-delete-form')->to('main#certDeleteForm');
    $r->post('/certs')->over(request => 'cert-show-form')->to('main#certShowForm');
    $r->post('/certs')->over(request => 'cert-download-form')->to('main#certDownloadForm');

    # --- crls ----
    $r->get('/crls')->to('main#crlListForm');

    $r->post('/crls')->over(request => 'crl-list')->to('main#crlList');

    $r->post('/crls')->over(request => 'crl-create')->to('main#crlCreate');
    $r->post('/crls')->over(request => 'crl-delete')->to('main#crlDelete');
    $r->post('/crls')->over(request => 'crl-show')->to('main#crlShow');
    $r->post('/crls')->over(request => 'crl-download')->to('main#crlDownload');

    $r->post('/crls')->over(request => 'crl-delete-form')->to('main#crlDeleteForm');
    $r->post('/crls')->over(request => 'crl-show-form')->to('main#crlShowForm');
    $r->post('/crls')->over(request => 'crl-download-form')->to('main#crlDownloadForm');

    $r->post('/certs')->to('main#postError');

    # --- hello ---
    $r->websocket('/wshello')->to('main#wshello');
    $r->any('/hello')->to('main#hello');

    # --- default ---
    $r->any('/*some')->to('main#login');
    #---------------------
    #--- add app hooks ---
    #---------------------
    $self->hook(before_dispatch => sub {
        my $c = shift;
        my $next_req_id = md5_sum(localtime(time).rand(1024));

        #--- log all request ---
        my $remote_ip = $c->tx->remote_address;
        $c->app->log->info($remote_ip.' '.$c->req->method.' '.$c->req->url->to_abs->to_string);

        $c->stash(next_req_id => $next_req_id);
    });

    $self->hook(after_dispatch => sub {
        my $c = shift;
        $c->app->log->debug('request => '. $c->req->param('request')) if $c->req->param('request');
    });

    $self->hook(after_render => sub {
        my ($c, $output, $format) = @_;
        $c->session('curr_req_id' => $c->stash('next_req_id'));

        #--- log target request ---
        my $remote_ip = $c->tx->remote_address;
        $c->app->log->info($remote_ip.' '.$c->req->method.' '.$c->req->url->to_abs->to_string);
    });
}

1;
#EOF
