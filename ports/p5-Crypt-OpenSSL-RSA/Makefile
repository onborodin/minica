# Created by: nork@cityfujisawa.ne.jp
# $FreeBSD: head/security/p5-Crypt-OpenSSL-RSA/Makefile 436247 2017-03-15 14:45:30Z mat $

PORTNAME=	Crypt-OpenSSL-RSA
PORTVERSION=	0.28
PORTREVISION=	1
CATEGORIES=	security perl5
MASTER_SITES=	CPAN
PKGNAMEPREFIX=	p5-

MAINTAINER=	perl@FreeBSD.org
COMMENT=	Perl5 module to RSA encode and decode strings using OpenSSL

BUILD_DEPENDS=	p5-Crypt-OpenSSL-Bignum>=0:security/p5-Crypt-OpenSSL-Bignum \
		p5-Crypt-OpenSSL-Random>=0:security/p5-Crypt-OpenSSL-Random
RUN_DEPENDS:=	${BUILD_DEPENDS}

USES=		perl5 ssl
USE_PERL5=	configure
MAKE_ARGS=	PASTHRU_INC=-I${OPENSSLINC}

regression-test: build
	cd ${WRKSRC}/ && ${SETENV} ${MAKE_ENV} ${MAKE} ${MAKE_ARGS} test

.include <bsd.port.pre.mk>

.if ${SSL_DEFAULT:Mopenssl-devel}
BROKEN=		Does not build with openssl-devel
.endif

.include <bsd.port.post.mk>
