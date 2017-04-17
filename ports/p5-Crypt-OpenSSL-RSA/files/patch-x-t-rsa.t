--- ./t/rsa.t.orig	2011-08-25 01:57:35.000000000 +0300
+++ ./t/rsa.t	2017-03-24 23:40:30.761508000 +0200
@@ -4,7 +4,7 @@
 use Crypt::OpenSSL::Random;
 use Crypt::OpenSSL::RSA;
 
-BEGIN { plan tests => 43 + (UNIVERSAL::can("Crypt::OpenSSL::RSA", "use_sha512_hash") ? 4*5 : 0) }
+BEGIN { plan tests => 46 + (UNIVERSAL::can("Crypt::OpenSSL::RSA", "use_sha512_hash") ? 4*5 : 0) }
 
 sub _Test_Encrypt_And_Decrypt
 {
@@ -84,6 +84,15 @@
 
 ok($private_key_string and $public_key_string);
 
+my $enc_private_key_string_default = $rsa->get_private_key_string('12345');
+ok($enc_private_key_string_default);
+
+my $enc_private_key_string_des3 = $rsa->get_private_key_string('12345', 'des3-cbc');
+ok($enc_private_key_string_des3);
+
+my $enc_private_key_string_idea = $rsa->get_private_key_string('12345', 'IDEA');
+ok($enc_private_key_string_idea);
+
 my $plaintext = "The quick brown fox jumped over the lazy dog";
 my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($private_key_string);
 ok($plaintext eq $rsa_priv->decrypt($rsa_priv->encrypt($plaintext)));
