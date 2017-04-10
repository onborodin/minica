


my $crl = Crypt::OpenSSL::CA::X509_CRL->new("CRLv2");

$crl->set_issuer_DN( ....  );

$crl->set_lastUpdate ($enddate);
$crl->set_nextUpdate ($startdate);
$crl->set_extension("authorityKeyIdentifier"
$crl->crlNumber(

foreach my cert (
    my $serial = $cert->
    my $revocationDate = $cert->
    $crl->add_entry(


my $digestName = 'SHA256';
my $crlpem = $crl->sign($privkey, $digestname);



