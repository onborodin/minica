#
# $Id$
#
PORTNAME=	minica
PORTVERSION=	0.02
CATEGORIES=	security perl5
MASTER_SITES=	http://minica.unix7.org/_media/

MAINTAINER=	borodin@unix7.org
COMMENT=	X.509 web certificate manager

RUN_DEPENDS+= p5-Mojolicious>=0:www/p5-Mojolicious
RUN_DEPENDS+= p5-Apache-Htpasswd>=0:security/p5-Apache-Htpasswd
RUN_DEPENDS+= p5-Config-Simple>=0:devel/p5-Config-Simple
RUN_DEPENDS+= p5-Crypt-OpenSSL-AES>=0:security/p5-Crypt-OpenSSL-AES
RUN_DEPENDS+= p5-Crypt-OpenSSL-Random>=0:security/p5-Crypt-OpenSSL-Random
RUN_DEPENDS+= p5-Crypt-OpenSSL-RSA>=0:security/p5-Crypt-OpenSSL-RSA
RUN_DEPENDS+= p5-Crypt-OpenSSL-CA>=0:security/p5-Crypt-OpenSSL-CA
RUN_DEPENDS+= p5-Crypt-OpenSSL-X509>=0:security/p5-Crypt-OpenSSL-X509
RUN_DEPENDS+= p5-Crypt-CBC>=0:security/p5-Crypt-CBC
RUN_DEPENDS+= p5-DBI>=0:databases/p5-DBI
RUN_DEPENDS+= p5-DBD-SQLite>=0:databases/p5-DBD-SQLite
RUN_DEPENDS+= p5-Encode>=0:converters/p5-Encode
RUN_DEPENDS+=	${BUILD_DEPENDS}


MINICA_LOGDIR=	/var/log/${PORTNAME}
MINICA_RUNDIR=	/var/run/${PORTNAME}
MINICA_DBDIR=	/var/db/${PORTNAME}

MINICA_OWNER=	minica
MINICA_GROUP=	minica
MINICA_OWNER_ID=	997
MINICA_GROUP_ID=	997

USES=		perl5 tar:xz
GNU_CONFIGURE=	yes
CONFIGURE_ARGS+= --with-logfile=${MINICA_LOGDIR}/${PORTNAME}.log
CONFIGURE_ARGS+= --with-pidfile=${MINICA_RUNDIR}/${PORTNAME}.pid
CONFIGURE_ARGS+= --with-dbdir=${MINICA_DBDIR}
CONFIGURE_ARGS+= --with-user=${MINICA_OWNER}
CONFIGURE_ARGS+= --with-group=${MINICA_GROUP}

SUB_FILES+= 	pkg-install

SUB_LIST+=	MINICA_LOGDIR=${MINICA_LOGDIR}
SUB_LIST+=	MINICA_RUNDIR=${MINICA_RUNDIR}
SUB_LIST+=	MINICA_DBDIR=${MINICA_DBDIR}

SUB_LIST+=	MINICA_OWNER=${MINICA_OWNER}
SUB_LIST+=	MINICA_GROUP=${MINICA_GROUP}
SUB_LIST+=	MINICA_OWNER_ID=${MINICA_OWNER_ID}
SUB_LIST+=	MINICA_GROUP_ID=${MINICA_GROUP_ID}

PORTEXAMPLES=	*

post-install:
	${MKDIR} ${STAGEDIR}${EXAMPLESDIR}
	${INSTALL_DATA} ${WRKSRC}/*.example ${STAGEDIR}${EXAMPLESDIR}

.include <bsd.port.mk>
#EOF
