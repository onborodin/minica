#
# $Id$
#

#-------------------------------------------
#--- Controller :: Main ---
#-------------------------------------------

package MiniCA::Controller::Main;

use utf8;
use strict;

use Mojo::Base 'Mojolicious::Controller';
use Mojo::Util qw(b64_encode b64_decode md5_sum dumper url_escape);
use Mojo::JSON qw(encode_json decode_json);
use Apache::Htpasswd;

use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::CA;
use Crypt::OpenSSL::X509;

use Encode qw(decode encode decode_utf8 encode_utf8);


sub start {
  my $self = shift;
  $self->redirect_to('/login') unless $self->isAuth($self);
  $self->render(template => 'start');
}

sub login {
    my $self = shift;
    my $req = $self->req;

    my $username = $req->body_params->param('username') || '';
    my $password = $req->body_params->param('password') || '';

    if ($self->app->users->auth($username, $password)) {
        $self->session(username => $username);
        $self->app->log->info("Login success of user $username.");
        $self->render(template => 'start');
    } else {
        $self->app->log->info("Login failed of user $username.");
        my $lc = $self->session('lc') || 0;
        $lc++;
        $self->session(lc => $lc);
        my $message = "Login attempt $lc. You can tray again." if $lc > 1;
        $self->render(template => 'login', message => $message || "");
    }
}

sub logout {
    my $self = shift;
    $self->disAuth($self);
    $self->redirect_to('/login');
}

sub decodeBasicAuth {
    my ($self, $headers) = @_;

    my $authStr = $headers->authorization;
    return (undef, undef) unless $authStr;
    my ($authType, $encAuthPair) = split / /, $authStr;
    return (undef, undef) unless ($authType eq 'Basic' && $encAuthPair);
    my ($username, $password) = split /:/, b64_decode($encAuthPair);
    return (undef, undef) unless ($username && $password);
    return ($username, $password);
}

sub isAuth  {
    my $self = shift;
    return 1 if $self->session('username');
    return undef;
}

sub disAuth {
    my $self = shift;
    return 1 if $self->session(expires => 1);
    return undef;
}

#------------------------------------------------
#--- USERS METHOD -------------------------------
#------------------------------------------------

sub userList {
    my $self = shift;

    $self->redirect_to('/login') unless $self->isAuth;

    my $message = '';
    my $mLevel = 'primary';

#    $self->cache_control->five_minutes;
#    $self->res->headers->cache_control('public, max-age=300');

    $self->res->headers->cache_control('private, max-age=0, no-cache');
    $self->render(template => 'user-list', message => $message, mLevel => $mLevel);
}

sub userDeleteForm {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $username = $self->req->param('username');
    my $rowid = $self->req->param('rowid');
    $self->render(template => 'user-delete-form',
                    username => $username,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}

sub userChpwdForm {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $username = $self->req->param('username');
    my $rowid = $self->req->param('rowid');
    $self->render(template => 'user-chpwd-form',
                    username => $username,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}

sub userChnameForm {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $username = $self->req->param('username');
    my $rowid = $self->req->param('rowid');
    $self->render(template => 'user-chname-form',
                    username => $username,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}

sub userCreate {
    my $self = shift;

    my $username = $self->req->param('username');
    my $password = $self->req->param('password');
    my $name = $self->req->param('name');

    my $masterpwd = $self->req->param('masterpwd');

    my $message = 'User have been added successfully';
    my $mLevel = 'success';
    my $valid = 1;

    my @users = $self->users->list;
    my $users = join ':', @users;

    do { $mLevel = 'warning'; 
         $message = 'Login aready exist.';
         $valid = undef;
    } if $users =~ m/$username/;

    do { $mLevel = 'alert'; 
         $message = 'Password must be at least 6 characters';
         $valid = undef;
    } if length($password) < 5;

    do { $mLevel = 'alert'; 
         $message = 'Fullname must be.';
         $valid = undef;
    } if length($name) eq 0;

    do { $mLevel = 'alert'; 
         $message = 'Login must be.';
         $valid = undef;
    } if length($username) eq 0;

    do { $mLevel = 'alert'; 
         $message = 'Master password incorrect';
         $valid = undef;
    } unless $self->app->users->auth($self->app->users->masterUser, $masterpwd);

    do { $mLevel = 'alert'; 
         $message = 'Do you forget input master password?';
         $valid = undef;
    } if length($masterpwd) eq 0;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    if ($valid) {
        do { $mLevel = 'alert';
            $message = 'Account added unsuccessfully.';
        } unless $self->users->create($username, $password, $name);
    }

    $self->render(template => 'user-create',
                    username => $username,
                    message => $message,
                    success => $valid,
                    valid => $valid);
}

sub userDelete {
    my $self = shift;

    my $username = $self->req->param('username');
    my $masterpwd = $self->req->param('masterpwd');
    my $rowid = $self->req->param('rowid');

    my $message = 'User have been delete successfully.';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    do { $mLevel = 'alert'; 
         $message = 'Master password incorrect';
         $valid = undef;
    } unless $self->app->users->auth($self->app->users->masterUser, $masterpwd);

    do { $mLevel = 'alert'; 
         $message = 'Do you forget input master password?';
         $valid = undef;
    } if length($masterpwd) eq 0;


    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    if ($valid) {
        do { $mLevel = 'alert'; 
            $message = 'User have been delete unsuccessfully.';
            $valid = undef;
        } unless $self->users->delete($username);
    }

    $self->render(template => 'user-delete',
                    username => $username,
                    message => $message,
                    mLevel => $mLevel,
                    success => $valid,
                    rowid => $rowid);
}

sub userChpwd {
    my $self = shift;

    my $username = $self->req->param('username');
    my $password = $self->req->param('password');
    my $masterpwd = $self->req->param('masterpwd');
    my $rowid = $self->req->param('rowid');

    my $message = 'Password changed successfully.';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Password must be at least 6 characters';
         $valid = undef;
    } if length ($password) < 5;

    do { $mLevel = 'alert'; 
         $message = 'Master password incorrect';
         $valid = undef;
    } unless $self->app->users->auth($self->app->users->masterUser, $masterpwd);

    do { $mLevel = 'alert'; 
         $message = 'Do you forget input master password?';
         $valid = undef;
    } if length($masterpwd) eq 0;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    if ($valid) {
        do { $mLevel = 'alert'; 
            $message = 'Password changed unsuccessfully.';
            $valid = undef;
        } unless $self->users->password($username, $password);
    }
    $self->render(template => 'user-chpwd',
                    username => $username,
                    message => $message,
                    mLevel => $mLevel,
                    success => $valid,
                    rowid => $rowid);
}

sub userChname {
    my $self = shift;

    my $username = $self->req->param('username');
    my $masterpwd = $self->req->param('masterpwd');
    my $name = $self->req->param('name');
    my $rowid = $self->req->param('rowid');

    my $message = 'Name changed successfully';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
            $message = 'Name must be';
            $valid = undef;
    } if length ($name) eq 0;

    do { $mLevel = 'alert'; 
            $message = 'Master password incorrect';
            $valid = undef;
    } unless $self->app->users->auth($self->app->users->masterUser, $masterpwd);

    do { $mLevel = 'alert'; 
            $message = 'Do you forget input master password?';
            $valid = undef;
    } if (length($masterpwd) eq 0);

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    if ($valid) {
        do { $mLevel = 'alert'; 
            $message = 'Name changed unsuccessfully.';
            $valid = undef;
        } unless $self->users->info($username, $name);
    }
    $self->render(template => 'user-chname',
                    username => $username,
                    message => $message,
                    mLevel => $mLevel,
                    success => $valid,
                    rowid => $rowid);
}

#---------------------------------------------
#--- CA CERTS OPERATION-----------------------
#---------------------------------------------

sub cacertList {
    my $self = shift;

    $self->redirect_to('/login') unless $self->isAuth;
    $self->render(template => 'cacert-list', message => '', mLevel => '');
}

sub cacertCreate {
    my $self = shift;

    my $id = undef;
    my $message = '';
    my $mLevel = '';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    do { 
        ($id, $message) = $self->app->ca->createCACert (
            keysize =>    $self->req->param('key_size'),
            lifeTime =>   $self->req->param('lifetime'),
            digestType =>   $self->req->param('digest_type'),
            cipher =>   $self->req->param('cipher_type'),
            password =>     $self->req->param('password'),
            C =>    $self->req->param('country'),
            ST =>   $self->req->param('state'),
            L =>    $self->req->param('locality'),
            O =>    $self->req->param('org'),
            OU =>   $self->req->param('org_unit'),
            CN =>   $self->req->param('common_name')
        );
    } if $valid;

    $self->render(template => 'cacert-create',
                    message => $message,
                    mLevel => '',
                    id => $id,
                    success => $valid);
}

sub cacertImport {
    my $self = shift;
    my $pem = $self->req->param('pem');
    my $cert = $self->req->param('cert');
    my $key = $self->req->param('key');
    my $password = $self->req->param('password');

    my $id = undef;
    my $message = 'Create successfully';
    my $mLevel = '';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    do {
        $pem = $pem || $cert."\n".$key;
            $mLevel = 'success';
            ($id, $message) = $self->app->ca->importCACert($pem, $pem, $password);
            do { $valid = 0; $mLevel = 'alert'; } unless $id;
    } if $valid;

    $self->render(template => 'cacert-create',
                    message => $message,
                    mLevel => $mLevel,
                    id => $id,
                    success => $valid);
}

sub cacertDeleteForm {
    my $self = shift;

    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    $self->render(template => 'cacert-delete-form',
                    id => $id,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}

sub cacertRevokeForm {
    my $self = shift;
    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    $self->render(template => 'cacert-revoke-form',
                    id => $id,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}

sub cacertUnRevokeForm {
    my $self = shift;

    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    $self->render(template => 'cacert-unrevoke-form',
                    id => $id,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}

sub cacertDownloadForm {
    my $self = shift;

    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    $self->render(template => 'cacert-download-form',
                    id => $id,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}

sub cacertShowForm {
    my $self = shift;

    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    $self->render(template => 'cacert-show-form',
                    id => $id,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}

sub cacertDelete {
    my $self = shift;

    my $id = $self->req->param('id');
    my $password = $self->req->param('password');
    my $rowid = $self->req->param('rowid');

    my $valid = 1;
    my $message = 'Certificate deleted';
    my $mLevel = '';

    do { $valid = 0;
         $message = 'Uncorrect private key password';
         $mLevel = 'alert'; } unless $self->verifyCAKeyPassword($id, $password);

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    do { $self->app->ca->deleteCACert($id); 
        $self->app->log->info("Delete CA record with id=$id");
    } if $valid;

    $self->render(template => 'cacert-delete',
                    message => $message,
                    id => $id,
                    rowid => $rowid,
                    mLevel => $mLevel,
                    success => $valid);
}

sub cacertRevoke {
    my $self = shift;

    my $id = $self->req->param('id');
    my $password = $self->req->param('password');
    my $rowid = $self->req->param('rowid');

    my $valid = 1;
    my $message = 'Certificate revoked successfully';
    my $mLevel = '';

    do { $valid = 0;
         $message = 'Uncorrect private key password';
         $mLevel = 'alert'; } unless $self->verifyCAKeyPassword($id, $password);

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    do { $self->app->ca->revokeCACert($id); } if $valid;

    $self->render(template => 'cacert-revoke',
                    message => $message,
                    id => $id,
                    rowid => $rowid,
                    mLevel => $mLevel,
                    success => $valid);
}

sub cacertUnRevoke {
    my $self = shift;

    my $id = $self->req->param('id');
    my $password = $self->req->param('password');
    my $rowid = $self->req->param('rowid');

    my $valid = 1;
    my $message = 'Certificate unrevoked successfully';
    my $mLevel = '';

    do { $valid = 0;
         $message = 'Uncorrect private key password';
         $mLevel = 'alert'; } unless $self->verifyCAKeyPassword($id, $password);

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    do { $self->app->ca->unrevokeCACert($id); } if $valid;

    $self->render(template => 'cacert-unrevoke',
                    message => $message,
                    id => $id,
                    rowid => $rowid,
                    mLevel => $mLevel,
                    success => $valid);
}

sub cacertDownload {
    my $self = shift;

    $self->redirect_to('/login') unless $self->isAuth;

    my $id = $self->req->param('id');
    my $cert = $self->app->ca->getCACert($id);
    my $key = $self->app->ca->getCAKey($id);
    my $subject = $self->app->ca->getCACertSubject($id);

    $subject = encode('UTF-8', $self->app->ca->stripDN($subject));

    $self->render_file(data => $cert."\n".$key, 
                       filename => "$subject.pem",
                       format => 'txt');
}

sub cacertShow {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $id = $self->req->param('id');
    $self->render(template => 'cacert-show',
                    id => $id,
                    message => $message,
                    success => $valid);
}

sub verifyCAKeyPassword {
    my ( $self, $id, $password) = @_;
    return undef unless $id;
    return undef unless $password;
    my $key = $self->app->ca->getCAKey($id);
    my $enckey = $self->app->ca->decryptKey($key, $password);
    return 1 if $enckey;
    return undef;
}


#---------------------------------------------
#--- LEAF CERTS ------------------------------
#---------------------------------------------

sub certListForm {
    my $self = shift;

    $self->redirect_to('/login') unless $self->isAuth;
    $self->render(template => 'cert-list-form')
}

sub certList {
    my $self = shift;

    my $issuerId = $self->req->param('issuer_id') || '';

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert';
         $message = 'Autentification expired';
         $valid = undef;
    } unless $self->isAuth;

    $self->render(template => 'cert-list',
                    message => $message,
                    issuerId => $issuerId,
                    mLevel => $mLevel,
                    success => $valid);
}

sub certDeleteForm {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert';
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');
    $self->render(template => 'cert-delete-form',
                    id => $id,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}

sub certRevokeForm {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');
    $self->render(template => 'cert-revoke-form',
                    id => $id,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}

sub certUnRevokeForm {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');
    $self->render(template => 'cert-unrevoke-form',
                    id => $id,
                    rowid => $rowid, 
                    message => $message,
                    success => $valid);
}

sub certDownloadForm {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');
    $self->render(template => 'cert-download-form',
                    id => $id,
                    rowid => $rowid, 
                    message => $message,
                    success => $valid);
}

sub certShowForm {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');
    $self->render(template => 'cert-show-form',
                    id => $id,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}


sub certCreate {
    my $self = shift;

    my $id = undef;
    my $message = '';
    my $mLevel = '';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    do { 
        ($id, $message) = $self->app->ca->createCert (
            issuerId => $self->req->param('issuer_id'),
            issuerPassword => $self->req->param('issuer_password'),
            C =>    $self->req->param('country'),
            ST =>   $self->req->param('state'),
            L =>    $self->req->param('locality'),
            O =>    $self->req->param('org'),
            OU =>   $self->req->param('org_unit'),
            CN =>   $self->req->param('common_name'),
            password =>     $self->req->param('password'),
            lifeTime =>   $self->req->param('lifetime'),
            cipherType =>   $self->req->param('cipher_type'),
            digestType =>   $self->req->param('digest_type'),
            keysize =>    $self->req->param('key_size'),
        );
    } if $valid;

    $self->render(template => 'cert-create',
                    message => $message,
                    mLevel => '',
                    id => $id,
                    success => $valid);
}

sub certShow {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $id = $self->req->param('id');
    $self->render(template => 'cert-show',
                    id => $id,
                    message => $message,
                    success => $valid);
}

sub certDelete {
    my $self = shift;

    my $id = $self->req->param('id');
    my $password = $self->req->param('password');
    my $rowid = $self->req->param('rowid');

    my $issuer_id = $self->app->ca->getCertIssuerID($id);
    my $subject = $self->app->ca->getCertSubject($id);

    my $valid = 1;
    my $message = 'Certificate deleted';
    my $mLevel = 'success';

    do { $valid = 0;
         $message = 'Uncorrect private key password';
         $mLevel = 'alert'; } unless $self->verifyCAKeyPassword($issuer_id, $password);

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;


    do { $self->app->ca->deleteCert($id); } if $valid;

    $self->render(template => 'cert-delete', 
                    message => $message,
                    id => $id,
                    rowid => $rowid,
                    mLevel => $mLevel,
                    success => $valid);
}

sub certRevoke {
    my $self = shift;

    my $id = $self->req->param('id');
    my $password = $self->req->param('password');
    my $rowid = $self->req->param('rowid');

    my $issuer_id = $self->app->ca->getCertIssuerID($id);
    my $subject = $self->app->ca->getCertSubject($id);

    my $valid = 1;
    my $message = "Cerificate revoked";
    my $mLevel = 'success';

    do { $valid = 0;
         $message = 'Uncorrect private key password';
         $mLevel = 'alert'; } unless $self->verifyCAKeyPassword($issuer_id, $password);

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;


    do { $self->app->ca->revokeCert($id); } if $valid;

    $self->render(template => 'cert-revoke', 
                    message => $message,
                    id => $id,
                    rowid => $rowid,
                    mLevel => $mLevel,
                    success => $valid);

}

sub certUnRevoke {
    my $self = shift;

    my $id = $self->req->param('id');
    my $password = $self->req->param('password');
    my $rowid = $self->req->param('rowid');

    my $issuer_id = $self->app->ca->getCertIssuerID($id);
    my $subject = $self->app->ca->getCertSubject($id);

    my $valid = 1;
    my $message = "Cerificate  unrevoked";
    my $mLevel = 'success';

    do { $valid = 0;
         $message = 'Uncorrect private key password';
         $mLevel = 'alert'; } unless $self->verifyCAKeyPassword($issuer_id, $password);

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    do { $self->app->ca->unrevokeCert($id); } if $valid;

    $self->render(template => 'cert-unrevoke', 
                    message => $message,
                    id => $id,
                    rowid => $rowid,
                    mLevel => $mLevel,
                    success => $valid);
}

sub certDownload {
    my $self = shift;

    $self->redirect_to('/login') unless $self->isAuth;

    my $id = $self->req->param('id');
    my $password = $self->req->param('password') || '';
    my $outpass = $self->req->param('outpass') || '';

    my $cert = $self->app->ca->getCert($id);
    my $key = $self->app->ca->getKey($id, $password, $outpass);

    my $name = $self->app->ca->getCertSubject($id);
    $name = $self->app->ca->stripDN($name);
    $name =~ s/ /_/g;
    $self->render_file(data => $cert."\n".$key, 
                       filename => "$name.pem",
                       format => 'txt');
}

sub doc {
    my $self = shift;
    $self->redirect_to('/login') unless $self->isAuth;
    $self->render(template => 'doc');
}

#---------------------------------------------
#--- CRL OPERATION --------------------------
#---------------------------------------------

sub crlListForm {
    my $self = shift;

    $self->redirect_to('/login') unless $self->isAuth;
    $self->render(template => 'crl-list-form')
}

sub crlList {
    my $self = shift;

    my $issuerId = $self->req->param('issuer_id') || '';

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert';
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    $self->render(template => 'crl-list',
                    message => $message,
                    issuerId => $issuerId,
                    mLevel => $mLevel,
                    success => $valid);
}


sub crlCreate {
    my $self = shift;

    my $issuerId = $self->req->param('issuer_id') || '';
    my $password = $self->req->param('issuer_password') || '';
    my $lifeTime = $self->req->param('lifetime') || '';
    my $digestType = $self->req->param('digest_type') || '';

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

#    do { $valid = 0;
#         $message = 'Uncorrect private key password';
#         $mLevel = 'alert'; } unless $self->verifyCAKeyPassword(
#                                                    issuerId => $issuerId,
#                                                    password => $password);

    do { $mLevel = 'alert';
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

#    my $issuerId = $param{issuerId};
#    my $lifeTime = $param{lifeTime} || '365';
#    my $digestType = $param{digestType} || 'sha256';
#    my $password = $param{password} || '';

    my $crlId = $self->app->ca->createCRL( issuerId => $issuerId, password => $password);

    $self->render(template => 'crl-create',
                    message => $message,
                    crlId => $crlId,
                    mLevel => $mLevel,
                    success => $valid);
}

sub crlDeleteForm {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert';
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');
    $self->render(template => 'crl-delete-form',
                    id => $id,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}


sub crlDownloadForm {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');
    $self->render(template => 'crl-download-form',
                    id => $id,
                    rowid => $rowid, 
                    message => $message,
                    success => $valid);
}

sub crlShowForm {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $id = $self->req->param('id');
    my $rowid = $self->req->param('rowid');
    $self->render(template => 'crl-show-form',
                    id => $id,
                    rowid => $rowid,
                    message => $message,
                    success => $valid);
}

sub crlShow {
    my $self = shift;

    my $message = 'Success story';
    my $mLevel = 'success';
    my $valid = 1;

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;

    my $id = $self->req->param('id');
    $self->render(template => 'crl-show',
                    id => $id,
                    message => $message,
                    success => $valid);
}

sub crlDelete {
    my $self = shift;

    my $id = $self->req->param('id');
    my $password = $self->req->param('password');
    my $rowid = $self->req->param('rowid');

    my $issuer_id = $self->app->ca->getCRLIssuerId($id);

    my $valid = 1;
    my $message = 'CRL deleted';
    my $mLevel = 'success';

    do { $valid = 0;
         $message = 'Uncorrect private key password';
         $mLevel = 'alert'; } unless $self->verifyCAKeyPassword($issuer_id, $password);

    do { $mLevel = 'alert'; 
         $message = 'Autentification expired';
         $valid = undef;
    }  unless $self->isAuth;


    do { $self->app->ca->deleteCRL($id); } if $valid;

    $self->render(template => 'crl-delete', 
                    message => $message,
                    id => $id,
                    rowid => $rowid,
                    mLevel => $mLevel,
                    success => $valid);
}


sub crlDownload {
    my $self = shift;

    $self->redirect_to('/login') unless $self->isAuth;

    my $id = $self->req->param('id');
    my $issuerId = $self->app->ca->getCRLIssuerId($id);
    my $name = $self->app->ca->getCACertSubject($issuerId);
    my $crl = $self->app->ca->getCRL($id);
    $name = $self->app->ca->stripDN($name);
    $name =~ s/ /_/g;
    $self->render_file(data => $crl, 
                       filename => "$name.crl",
                       format => 'txt');
}


#---------------------------------------------
#--- TEST OPERATION --------------------------
#---------------------------------------------

sub hello {
    my $self = shift;
    $self->render(text => 'Hello');
}

sub wshello {
    my $self = shift;
    $self->render(text => 'OK');
}

#-------------------------------------
#--- ERROR MESSAGE -------------------
#-------------------------------------

sub authError {
    my $self = shift;
    $self->res->code(401);
    $self->render(text => 'Auth Error');
}

sub postError {
    my $self = shift;
    $self->render(text => 'Hmm... Post mistake...');
}

1;
#EOF
