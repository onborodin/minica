#
# $Id$
#
#--------------------------------------
#--- Model :: CA ---
#--------------------------------------
package MiniCA::Model::CA;

use utf8;
use MIME::QuotedPrint qw(encode_qp decode_qp);
use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::CA;
use Crypt::OpenSSL::X509;
use Crypt::CBC;

use DBI;

use Mojo::Util qw(dumper b64_encode b64_decode sha1_sum md5_sum);
use Mojo::JSON qw(encode_json decode_json);

use Encode qw(decode encode decode_utf8 encode_utf8);
use MIME::QuotedPrint qw(encode_qp decode_qp);

#------------------------------------------
#--- Utils ----- --------------------------
#------------------------------------------

sub decode_oneline {
    my $oneline = shift;
    $oneline =~ s,\\x,=,g;
    return decode('utf-8', decode_qp($oneline));
}

#------------------------------------------
#--- CONSTRUCTOR --------------------------
#------------------------------------------

sub new {
    my ($class, $app, $dsn, $username, $password) = @_;
    my $self = { 
        app => $app,
        dsn => $dsn,
        username => $username,
        password => $password,
        dbschema => ""
    };
    bless $self, $class;
    return $self;
}

#----------------------------------------
#--- ACCESSORS --------------------------
#----------------------------------------

sub app {
    return shift->{app};
}

sub dsn {
    return shift->{dsn};
}

sub username {
    return shift->{username};
}

sub password {
    return shift->{password};
}

#-----------------------------------------
#--- UTILS -------------------------------
#-----------------------------------------

sub zuluTime {
    my ($self, $dayShift) = @_;
    $dayShift = 0 unless defined $dayShift;
    my ($sec, $min, $hour, $mday, $mon, $year) = gmtime(time()+$dayShift*3600*24);
    return sprintf('%04d%02d%02d%02d%02d%02dZ', $year+1900, $mon+1, $mday, $hour, $min, $sec);
}

sub fromZulu {
  my ($self, $date) = @_;
  return undef unless $date;
  #20180226163341Z
  #01234567890123
  my $year = substr $date, 0, 4;
  my $month = substr $date, 4, 2;
  my $day = substr $date, 6, 2;
  my $hour = substr $date, 8, 2;
  my $min = substr $date, 10, 2;
  my $sec = substr $date, 12, 2;

  return "$year/$month/$day $hour:$min:$sec";
}

sub toZulu {
  my ($self, $date) = @_;
  return undef unless $date;
  #2017/02/26 16:52:50
  #0123456789012345678
  my $year = substr $date, 0, 4;
  my $month = substr $date, 5, 2;
  my $day = substr $date, 8, 2;
  my $hour = substr $date, 11, 2;
  my $min = substr $date, 14, 2;
  my $sec = substr $date, 17, 2;
  return "$year$month$day$hour$min$sec"."Z";
}

sub dumpCert {
    my ($self, $cert) = @_;
    return undef unless $cert;
    return decode_oneline(Crypt::OpenSSL::CA::X509->parse($cert)->dump);
}

sub subject {
    my ($self, $cert) = @_;
    return undef unless $cert;
    return decode_oneline(Crypt::OpenSSL::CA::X509->parse($cert)->get_subject_DN->to_string);
}

sub getCertID {
    my ($self, $cert) = @_;
    return undef unless $cert;
    my $x509 = Crypt::OpenSSL::CA::X509->parse($cert);
    return sha1_sum($x509->get_public_key->to_PEM);
}

sub verifyPair {
    my ($self, $cert, $key, $password) = @_;
    return undef unless $cert;
    return undef unless $key;

    my $cakey;
    eval {
        $cakey = Crypt::OpenSSL::CA::PrivateKey->parse($key, -password => $password);
    };
    return (undef, 'Unable to parse or decript private key') if $@;

    my $x509;
    eval {
        $x509 = Crypt::OpenSSL::CA::X509->parse($cert);
    };
    return (undef, 'Unable to parse certificate') if $@;

    my $pubkeyFromCert = $x509->get_public_key->to_PEM;
    my $pubkeyFromKey = $cakey->get_public_key->to_PEM;

    return (1, 'Certificate and private key pair is correct') 
        if sha1_sum($pubkeyFromCert) eq sha1_sum($pubkeyFromKey);
    return (0, 'Certificate and private key pair from different pairs');
}

sub isSelfSign {
    my ($self, $cert) = @_;
    return undef unless $cert;
    my $x509;
    eval {
        $x509 = Crypt::OpenSSL::CA::X509->parse($cert);
    };
    return (undef, 'Unable to parse certificate') if $@;
    my $pubkey = $x509->get_public_key;
    eval {
        $x509->verify($pubkey);
    };
    return (0, 'Certificate is not self-signed') if $@;
    return (1, 'Certificate is self-signed');
}


sub decryptKey {
    my ($self, $key, $password) = @_;
    return undef unless $key;
    return undef unless $password;

    my $rsa;
    eval {
        $rsa = Crypt::OpenSSL::RSA->new_private_key($key, $password);
    };
    return undef if $@;
    return $rsa->get_private_key_string;
}

sub encryptKey {
    my ($self, $key, $password, $cipher) = @_;
    return undef unless $key;
    return undef unless $password;
    $cipher = 'AES256' unless $cipher;

    my $rsa;
    eval {
        $rsa = Crypt::OpenSSL::RSA->new_private_key($key);
    };
    return undef if $@;
    return $rsa->get_private_key_string($password, $cipher);
}


sub stripDN {
    my $self = shift;
    my $dn = shift;
    for my $n (split /\//, $dn) {
        my ($l, $r) = split /=/, $n;
        next unless $l;
        return $r if $l =~ /CN/;
    }
}


#-----------------------------------------
#--- CA CERT methods ---------------------
#-----------------------------------------

sub createCACert {
    my $self = shift;
    my %param = @_;

    my $keysize = $param{keysize} || 1024;
    my $lifeTime = $param{lifeTime} || 365*5;
    my $digestType = $param{digestType} || 'SHA256';
    my $password = $param{password} || '';
    my $cipherType = $param{cipherType} || 'AES256';

    my $country = $param{C} || 'US';
    my $state = $param{ST} || '';
    my $locality = $param{L} || '';
    my $org = $param{O} || '';
    my $orgUnit = $param{OU} || '';
    my $commonName = $param{CN} || 'Neo';

    my $subjectAltName = $param{SAN} || '';

    my $newRSA = Crypt::OpenSSL::RSA->generate_key($keysize);

    my $new_privkey = Crypt::OpenSSL::CA::PrivateKey->parse($newRSA->get_private_key_string());
    my $new_pubkey = Crypt::OpenSSL::CA::PublicKey->parse_RSA($newRSA->get_public_key_x509_string());

    my $new_x509 = Crypt::OpenSSL::CA::X509->new($new_pubkey);

    my @subj;
    do { push @subj, "C"; push @subj, $country; } if (length($country));
    do { push @subj, "ST"; push @subj, $state; } if (length($state));
    do { push @subj, "L"; push @subj, $locality; } if (length($locality));
    do { push @subj, "O"; push @subj, $org; } if (length($org));
    do { push @subj, "OU"; push @subj, $orgUnit; } if (length($orgUnit));
    do { push @subj, "CN"; push @subj, $commonName; } if (length($commonName));

    my $dn = Crypt::OpenSSL::CA::X509_NAME->new_utf8(@subj);
    $new_x509->set_subject_DN($dn);
    $new_x509->set_issuer_DN($dn);

    $new_x509->set_extension(basicConstraints => 'CA:TRUE', -critical => 1);
    $new_x509->set_extension(subjectKeyIdentifier => $new_pubkey->get_openssl_keyid);
    $new_x509->set_extension(keyUsage => 'digitalSignature,keyCertSign,cRLSign', -critical => 1);

    $new_x509->set_extension(authorityKeyIdentifier =>
                              { keyid  => $new_x509->get_subject_keyid,
                                issuer => $new_x509->get_issuer_DN,
                                serial => $new_x509->get_serial });

    $new_x509->set_extension(subjectAltName => $subjectAltName) if (length($subjectAltName));
    #$new_x509->set_extension(crlDistributionPoints => 'URI:'.$crlURL) if (length($crlURL));

    $new_x509->set_notBefore($self->zuluTime);
    $new_x509->set_notAfter($self->zuluTime($lifeTime));

    #--- encrypt private key ---
    my $key = $newRSA->get_private_key_string($password, $cipherType);

    #--- self sign cerificate ---
    my $cert = $new_x509->sign($new_privkey, $digestType);

    #--- insert the pair to db storage ---
    my $id = $self->insertCACert($cert, $key);
    return (undef, 'Storage error') unless $id;
    return ($id, 'Create success');
}

sub importCACert {
    my ($self, $cert, $key, $password, $cipher) = @_;
    $password = $password || '';
    $cipher = $cipher || 'AES256';
    my $rsa;
    eval { 
        $rsa = Crypt::OpenSSL::RSA->new_private_key($key, $password); 
    };
    return (undef, 'Cannot parse or decrypt private key') if $@;

    my $x509;
    eval {
        $x509 = Crypt::OpenSSL::CA::X509->parse($cert);
    };
    return (undef, 'Cannot parse certificate') if $@;

    my $pubkey = $x509->get_public_key;
    eval {
        $x509->verify($pubkey);
    };
    return (undef, 'Certificate is not self-signed') if $@;
    return (undef, 'Certificate and is not pair') 
        unless md5_sum($rsa->get_public_key_x509_string) eq md5_sum($x509->get_public_key->to_PEM);

    my $id = $x509->get_public_key->get_openssl_keyid;
    return (undef, 'Certificate exist in database') if $self->getCACert($id);

    #--- normalise certificate ---
    my $outcert = Crypt::OpenSSL::X509->new_from_string($cert)->as_string;

    #---  (re)encrypt private key to PKSC#5 ---
    my $outkey = $rsa->get_private_key_string($password, $cipher);

    my $id = $self->insertCACert($outcert, $outkey);
    return (undef, 'Storage error') unless $id;
    return ($id, 'Import successful');
}

sub insertCACert {
    my ($self, $cert, $key) = @_;
    return undef unless $cert;
    return undef unless $key;

    my $x509 = Crypt::OpenSSL::CA::X509->parse($cert);
    my $serial = $x509->get_serial;

    my $id = $serial.'::'.$x509->get_public_key->get_openssl_keyid;
    my $subject = decode_oneline($x509->get_subject_DN->to_string);
    my $issuer = decode_oneline($x509->get_issuer_DN->to_string);
    my $begindate = $self->app->ca->fromZulu($x509->get_notBefore);
    my $expiredate = $self->app->ca->fromZulu($x509->get_notAfter);
    $cert = b64_encode($cert, '');
    $key = b64_encode($key, '');

    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "insert into cacert (id, serial, subject, begindate, expiredate, cert, key)
                      values ('$id',
                              '$serial',
                              '$subject',
                              '$begindate',
                              '$expiredate',
                              '$cert',
                              '$key');";

    my $rows = $dbi->do($query);
    $dbi->disconnect;
    return undef unless $rows*1;
    return $id;
}

sub listCACert {
    my ($self, $id) = @_;
    my $selector = "where id = '$id'" if $id;
    $selector = $selector || '';
    my $db = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select id, serial, subject, begindate, expiredate, revokedate, revokereason from cacert $selector order by begindate;";
    my $sth = $db->prepare($query);
    my $rows = $sth->execute;
    my @a;
    while (my $row = $sth->fetchrow_hashref) {
        push @a, $row;
    }
    $sth->finish;
    $db->disconnect;
    return undef if $rows*1;;
    return \@a;
}

sub getCACert {
    my ($self, $id) = @_;
    return (undef, undef) unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select cert from cacert where id = '$id' limit 1;";
    my $sth = $dbi->prepare($query);
    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;
    my $cert = $row->{cert} || undef;
    $sth->finish;
    $dbi->disconnect;
    return b64_decode $cert;
}

sub getCAKey {
    my ($self, $id) = @_;
    return (undef, undef) unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select cert, key from cacert where id = '$id' limit 1;";
    my $sth = $dbi->prepare($query);
    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;
    my $key = $row->{key} || undef;
    $sth->finish;
    $dbi->disconnect;
    return b64_decode $key;
}


sub getCACertSubject {
    my ($self, $id) = @_;
    return (undef, undef) unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select subject from cacert where id = '$id' limit 1;";
    my $sth = $dbi->prepare($query);
    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;
    my $subject = $row->{subject} || undef;
    $sth->finish;
    $dbi->disconnect;
    return decode_oneline($subject);
}


sub deleteCACert {
    my ($self, $id) = @_;
    return undef unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "delete from cacert where id = '$id';";
    my $rows = $dbi->do($query);
    $dbi->disconnect;
    return $rows*1;
}

sub revokeCACert {
    my ($self, $id) = @_;
    return undef unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $revokedate = $self->fromZulu($self->zuluTime);
    my $query = "update cacert set revokedate = '$revokedate' where id = '$id';";
    my $rows = $dbi->do($query);
    $dbi->disconnect;
    return $rows*1;
}

sub unrevokeCACert {
    my ($self, $id) = @_;
    return undef unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "update cacert set revokedate = '' where id = '$id';";
    my $rows = $dbi->do($query);
    $dbi->disconnect;
    return $rows*1;
}


#-----------------------------------------
#--- LEAF CERT methods -------------------
#-----------------------------------------

sub getNextCertSerial {
    my ($self, $issuerId) = @_;

    my $db = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select serial+1 as nextserial from cert where issuer_id = '$issuerId' order by serial desc limit 1;";
    my $sth = $db->prepare($query);
    my $rows = $sth->execute;
    $row = $sth->fetchrow_hashref;
    my $serial = $row->{nextserial} || undef;
    $sth->finish;
    $db->disconnect;
    return $serial;
}

sub createCert {
    my $self = shift;
    my %param = @_;

    my $issuerId = $param{issuerId} || '';
    my $issuerPassword = $param{issuerPassword} || '';
    my $keysize = $param{keysize} || 1024;
    my $lifeTime = $param{lifeTime} || 365;
    my $digestType = $param{digestType} || 'SHA256';
    my $password = $param{password} || '12345';
    my $cipherType = $param{cipherType} || 'AES256';

    return (undef, 'Issuer ID is empty') unless $issuerId;
    return (undef, 'Issuer private key password is empty') unless $issuerPassword;

    my $issuerCert = $self->getCACert($issuerId);
    my $issuerKey = $self->getCAKey($issuerId);

    my $issuerX509 = Crypt::OpenSSL::CA::X509->parse($issuerCert);
    my $issuerDN = $issuerX509->get_subject_DN;

    my $issuerRSA;
    eval {
        $issuerRSA = Crypt::OpenSSL::RSA->new_private_key($issuerKey, $issuerPassword); 
    };
    return (undef, "Cannot parse or decrypt issuer private key") if $@;

    my $country = $param{C} || '';
    my $state = $param{ST} || '';
    my $locality = $param{L} || '';
    my $org = $param{O} || '';
    my $orgUnit = $param{OU} || '';
    my $commonName = $param{CN} || 'Neo';

    my $newRSA = Crypt::OpenSSL::RSA->generate_key($keysize);

    my $new_privkey = Crypt::OpenSSL::CA::PrivateKey->parse($newRSA->get_private_key_string());
    my $new_pubkey = Crypt::OpenSSL::CA::PublicKey->parse_RSA($newRSA->get_public_key_x509_string());

    my $new_x509 = Crypt::OpenSSL::CA::X509->new($new_pubkey);

    my @subj;
    do { push @subj, "C"; push @subj, $country; } if (length($country));
    do { push @subj, "ST"; push @subj, $state; } if (length($state));
    do { push @subj, "L"; push @subj, $locality; } if (length($locality));
    do { push @subj, "O"; push @subj, $org; } if (length($org));
    do { push @subj, "OU"; push @subj, $orgUnit; } if (length($orgUnit));
    do { push @subj, "CN"; push @subj, $commonName; } if (length($commonName));


    my $dn = Crypt::OpenSSL::CA::X509_NAME->new_utf8(@subj);
    $new_x509->set_subject_DN($dn);
    $new_x509->set_issuer_DN($issuerDN);

    $new_x509->set_extension('basicConstraints', 'CA:FALSE', -critical => 1);
    $new_x509->set_extension('subjectKeyIdentifier', $new_pubkey->get_openssl_keyid);

    # --- get issuer id for extension ---
    $new_x509->set_extension('authorityKeyIdentifier', 
            { keyid => $issuerX509->get_public_key->get_openssl_keyid });

    $new_x509->set_extension('keyUsage', 'digitalSignature,keyCertSign,cRLSign', -critical => 0);

    $new_x509->set_notBefore($self->zuluTime);
    $new_x509->set_notAfter($self->zuluTime($lifeTime));

    # --- get biggest sertificate serial from database + 1 ---
    my $serial = sprintf '0x%X', $self->getNextCertSerial($issuerId);
    $new_x509->set_serial($serial);

    my $key = $newRSA->get_private_key_string;

    #-------------
    #--- sign  ---
    #-------------
    my $cert = $new_x509->sign(Crypt::OpenSSL::CA::PrivateKey->parse($issuerKey, -password => $issuerPassword), $digestType);

    my $secret = md5_sum(localtime(time)+rand(10240));

    my $alg = 'Crypt::OpenSSL::AES';
    my $secret = md5_sum(localtime(time));
    my $cipher = Crypt::CBC->new({
        key    => $secret,
        cipher => $alg,
        keylength => '256'
    });

    my $issuerRSAPub = Crypt::OpenSSL::RSA->new_public_key($issuerX509->get_public_key->to_PEM);

    $cert = b64_encode($cert, '');
    my $enc_key = b64_encode($cipher->encrypt($key), '');
    my $enc_secret = b64_encode($issuerRSAPub->encrypt($secret), '');

    my $serial = hex $new_x509->get_serial;
    my $subject = decode_oneline($new_x509->get_subject_DN->to_string);
    my $id = $new_x509->get_serial.'::'.$new_x509->get_public_key->get_openssl_keyid;
    my $begindate = $self->fromZulu($new_x509->get_notBefore);
    my $expiredate = $self->fromZulu($new_x509->get_notAfter);
    my $dbserial = hex $new_x509->get_serial;

    my $db = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "insert into cert (id, issuer_id, serial, subject, begindate, expiredate, cert, secret, key)
                      values ('$id',
                              '$issuerId',
                              '$dbserial',
                              '$subject',
                              '$begindate',
                              '$expiredate',
                              '$cert',
                              '$enc_secret',
                              '$enc_key');";
    $rows = $db->do($query);
    $db->disconnect;
    return ($id, "Certificate create done");
}

sub listCert {
    my $self = shift;
    my %param = @_;

    my $id = $param{id} || '';
    my $issuerId = $param{issuerId} || '';

    my $selector = '';
    $selector .= " and cert.issuer_id = '$issuerId' " if length($issuerId);
    $selector .= " and cert.id = '$id' " if length($id);

    my $db = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select cert.id, 
                        cert.issuer_id, 
                        cert.serial, 
                        cert.subject, 
                        cacert.subject as issuer, 
                        cert.begindate, 
                        cert.expiredate, 
                        cert.revokedate, 
                        cert.revokereason 
                            from cert, cacert 
                            where cert.issuer_id = cacert.id $selector order by cert.id;";
    my $sth = $db->prepare($query);
    my $rows = $sth->execute;
    my @a;
    while (my $row = $sth->fetchrow_hashref) {
        push @a, $row;
    }
    $sth->finish;
    $db->disconnect;
    return \@a;
}

sub listCertCA {
    my $self = @_;
    my $db = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select distinct issuer_id from cert;";
    my $sth = $db->prepare($query);
    my $rows = $sth->execute;
    my @a;
    while (my $row = $sth->fetchrow_hashref) {
        push @a, $row->{issuer_id};
    }
    $sth->finish;
    $db->disconnect;
    return \@a;
}

sub getCert {
    my ($self, $id) = @_;
    return (undef, undef) unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select cert from cert where id = '$id' limit 1;";
    my $sth = $dbi->prepare($query);
    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;
    my $cert = $row->{cert} || undef;
    $sth->finish;
    $dbi->disconnect;
    return undef unless $cert;
    return b64_decode $cert;
}


sub getKey {
    my ($self, $id, $password, $outpass, $outcipher) = @_;

    return (undef, undef) unless $id;
    $outpass = $outpass || '';
    $outcipher = $outcipher || 'AES256';
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);

    my $query = "select cert.key as key, cert.secret as secret, cacert.key as cakey 
                from cert, cacert 
                where cert.issuer_id = cacert.id and cert.id = '$id' limit 1;";
    my $sth = $dbi->prepare($query);
    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;

    my $issuerKeyPem = b64_decode($row->{cakey}) || undef;

    my $enc_secret = $row->{secret};
    my $enc_key = $row->{key};

    $sth->finish;
    $dbi->disconnect;

    my $carsa;
    eval { 
        $issuerRSA = Crypt::OpenSSL::RSA->new_private_key($issuerKeyPem, $password); 
    };
    return undef if $@;

    my $dec_secret = $issuerRSA->decrypt(b64_decode($enc_secret));

    my $alg = 'Crypt::OpenSSL::AES';

    my $cipher = Crypt::CBC->new({
        key    => $dec_secret,
        cipher => $alg
    });
    my $key = $cipher->decrypt(b64_decode($enc_key)) || undef;

    eval {
        $key = Crypt::OpenSSL::RSA->new_private_key($key)->get_private_key_string($outpass, $outcipher); ;
    };
    return undef if $@;
    return $key;
}

sub getCertIssuerID {
    my ($self, $id) = @_;
    return (undef, undef) unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select issuer_id from cert where id = '$id' limit 1;";
    my $sth = $dbi->prepare($query);
    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;
    my $issuer_id = $row->{issuer_id} || undef;
    $sth->finish;
    $dbi->disconnect;
    return $issuer_id;
}

sub getCertSubject {
    my ($self, $id) = @_;
    return (undef, undef) unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select subject from cert where id = '$id' limit 1;";
    my $sth = $dbi->prepare($query);
    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;
    my $subject = $row->{subject} || undef;
    $sth->finish;
    $dbi->disconnect;
    return $subject;
}

sub deleteCert {
    my ($self, $id) = @_;
    return undef unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "delete from cert where id = '$id';";
    my $rows = $dbi->do($query);
    $dbi->disconnect;
    return $rows*1;
}

sub revokeCert {
    my ($self, $id) = @_;
    return undef unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $revokedate = $self->fromZulu($self->zuluTime);
    my $query = "update cert set revokedate = '$revokedate' where id = '$id';";
    my $rows = $dbi->do($query);
    $dbi->disconnect;
    return $rows*1;
}

sub unrevokeCert {
    my ($self, $id) = @_;
    return undef unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "update cert set revokedate = '' where id = '$id';";
    my $rows = $dbi->do($query);
    $dbi->disconnect;
    return $rows*1;
}

#---------------------------------------------
#--- CRL -------------------------------------
#---------------------------------------------

sub getNextCRLSerial {
    my ($self, $issuerId) = @_;

    my $db = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select serial+1 as nextserial from crl where issuer_id = '$issuerId' order by serial desc limit 1;";
    my $sth = $db->prepare($query);
    my $rows = $sth->execute;
    $row = $sth->fetchrow_hashref;
    my $serial = $row->{nextserial} || undef;
    $sth->finish;
    $db->disconnect;
    return $serial;
}

sub createCRL {
    my $self = shift;
    my %param = @_;

    my $issuerId = $param{issuerId};
    my $lifeTime = $param{lifeTime} || '3650';
    my $digestType = $param{digestType} || 'sha256';
    my $password = $param{password} || '';

    return undef unless length $issuerId;

    $pemCert = $self->getCACert($issuerId);
    $pemKey = $self->getCAKey($issuerId);

    my $crl = Crypt::OpenSSL::CA::X509_CRL->new("CRLv2");
    my $x509 = Crypt::OpenSSL::CA::X509->parse($pemCert);

    $crl->set_issuer_DN($x509->get_issuer_DN);

    $beginDate = $self->zuluTime;
    $expireDate = $self->zuluTime($lifeTime);

    $crl->set_lastUpdate($beginDate);
    $crl->set_nextUpdate($expireDate);

    my $serial = $self->getNextCRLSerial($issuerId) || 1;

    $crl->add_extension(crlNumber => sprintf('0x%x', $serial));
    $crl->add_extension(authorityKeyIdentifier =>
                              { keyid  => $x509->get_subject_keyid,
                                issuer => $x509->get_issuer_DN,
                                serial => $x509->get_serial });

    $listCert = $self->listCert(issuerId => $issuerId);

    foreach my $cert (@{$listCert}) {
        if ($cert->{issuer_id} eq $issuerId and $cert->{revokedate}) {
            $crl->add_entry( sprintf('0x%x', $cert->{serial}), $self->toZulu($cert->{revokedate}));
        }
    }

    my $key;
    eval {
        $key  = Crypt::OpenSSL::CA::PrivateKey->parse($pemKey, -password => $password);
    };
    return undef if $@;

    my $crlpem = $crl->sign($key, $digestType), '';

    my $id = $serial.'::'.md5_sum $crlpem;
    $crlpem = b64_encode $crlpem, '';

    $beginDate = $self->fromZulu($beginDate);
    $expireDate = $self->fromZulu($expireDate);

    my $db = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "insert into crl (id, issuer_id, serial, begindate, expiredate, crl)
                      values ('$id',
                              '$issuerId',
                              '$serial',
                              '$beginDate',
                              '$expireDate',
                              '$crlpem');";
    $rows = $db->do($query);
    $db->disconnect;

    return $id;
}

sub listCRL {
    my $self = shift;
    my %param = @_;

    my $id = $param{id} || '';
    my $issuerId = $param{issuerId} || '';

    my $selector = '';
    $selector .= " and crl.issuer_id = '$issuerId' " if length($issuerId);
    $selector .= " and crl.id = '$id' " if length($id);

    my $db = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select crl.id as id,
                        crl.issuer_id as issuer_id,
                        crl.serial as serial,
                        cacert.subject as issuer,
                        crl.begindate as begindate,
                        crl.expiredate as expiredate
                            from crl, cacert
                            where crl.issuer_id = cacert.id $selector order by crl.id;";

    my $sth = $db->prepare($query);
    my $rows = $sth->execute;
    my @a;
    while (my $row = $sth->fetchrow_hashref) {
        push @a, $row;
    }
    $sth->finish;
    $db->disconnect;
    return \@a;
}

sub deleteCRL {
    my ($self, $id) = @_;
    return undef unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "delete from crl where id = '$id';";
    my $rows = $dbi->do($query);
    $dbi->disconnect;
    return $rows*1;
}

sub getCRL {
    my ($self, $id) = @_;
    return (undef, undef) unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select crl from crl where id = '$id' limit 1;";
    my $sth = $dbi->prepare($query);
    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;
    my $crl = $row->{crl} || undef;
    $sth->finish;
    $dbi->disconnect;
    return undef unless $crl;
    return b64_decode $crl;
}

sub getCRLIssuerDN {
    my ($self, $id) = @_;
    return (undef, undef) unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select cacert.subject as issuer_dn from cacert, crl  where id = '$id' and cacert.id = crl.issuer_id limit 1;";
    my $sth = $dbi->prepare($query);
    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;
    my $issuerDN = $row->{issuer_dn} || undef;
    $sth->finish;
    $dbi->disconnect;
    return $issuerDN;
}

sub getCRLIssuerId {
    my ($self, $id) = @_;
    return (undef, undef) unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select issuer_id from crl  where id = '$id' limit 1;";
    my $sth = $dbi->prepare($query);
    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;
    my $issuer_id = $row->{issuer_id} || undef;
    $sth->finish;
    $dbi->disconnect;
    return $issuer_id;
}


sub getCRLDump {
    my ($self, $id) = @_;
    return (undef, undef) unless $id;
    my $dbi = DBI->connect($self->dsn, $self->username, $self->password);
    my $query = "select crl from crl where id = '$id' limit 1;";
    my $sth = $dbi->prepare($query);
    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;
    my $crlpem = $row->{crl} || undef;
    $sth->finish;
    $dbi->disconnect;
    return undef unless $crlpem;
    my $crl = Crypt::OpenSSL::CA::X509_CRL->parse_CRL(b64_decode $crlpem);
    my $crlDump = $crl->dump;
    return undef unless $crlDump;
    return $crlDump;
}

sub dumpCRL {
    my ($self, $crl) = @_;
    return undef unless $crl;
    my $crl = Crypt::OpenSSL::CA::X509_CRL->parse_CRL($crl);
    my $crlDump = $crl->dump;
    return undef unless $crlDump;
    return $crl->dump;
}

1;
#EOF
