AC_INIT(minica.in)
AM_INIT_AUTOMAKE(minica,0.02)
AC_PREFIX_DEFAULT(/usr/local)

PACKAGE=minica

AC_CHECK_PROG(HAVE_PERL, perl, true, false, /usr/local/bin /usr/bin)
if test "x$HAVE_PERL" = "xfalse"; then
	AC_MSG_ERROR([Requested program perl not found])
fi
AC_SUBST(PERL, perl)
AC_PATH_PROG([PERL],[perl])

AC_PROG_INSTALL

AC_CANONICAL_HOST
case $host_os in
    *freebsd* )
	AC_SUBST(ROOT_GROUP, "wheel")
	AM_CONDITIONAL(FREEBSD_OS, true)
	AM_CONDITIONAL(LINUX_OS, false)
	OSNAME=freebsd
	ROOT_GROUP=wheel
        ;;
    *linux* )
	AC_SUBST(ROOT_GROUP, "root")
	AM_CONDITIONAL(FREEBSD_OS, false)
	AM_CONDITIONAL(LINUX_OS, true)
	OSNAME=linux
	ROOT_GROUP=root
        ;;
esac


AC_ARG_WITH(app-conf,
	AS_HELP_STRING([--with-app-conf=PATH],[set configuration file for minica to PATH (default: "${ac_default_prefix}"/etc/${PACKAGE}/${PACKAGE}.conf)]),
	[ if test ! -z "$with_minica_conf" ; then
		case $with_app_conf in
			/*)
				APP_SYSCONF="$with_app_conf"
				;;
			*)
                                AC_MSG_ERROR(You must specify an absolute path to --with-app-conf=PATH)
				;;
		esac
	else
		APP_SYSCONF="$ac_default_prefix/etc/${PACKAGE}/${PACKAGE}.conf"
	fi ],
	[
	APP_SYSCONF="$ac_default_prefix/etc/${PACKAGE}/${PACKAGE}.conf" 
	APP_SYSCONFDIR="$ac_default_prefix/etc/${PACKAGE}"
	])

AC_DEFINE_UNQUOTED(APP_SYSCONF, "$APP_SYSCONF", [location of configuration file for ${PACKAGE}])
AC_SUBST(APP_SYSCONF, "$APP_SYSCONF")
AC_SUBST(APP_SYSCONFDIR, "$APP_SYSCONFDIR")

AC_ARG_WITH(logfile,
	AS_HELP_STRING([--with-logfile=PATH],[set file path for source logfile (default: /var/log/${PACKAGE}/${PACKAGE}.log)]),
	[ if test ! -z "$with_logfile" ; then
		case $with_logfile in
			/*)
				APP_LOGFILE="$with_logfile"
				APP_LOGDIR=`dirname $APP_LOGFILE`
				;;
			*)
                                AC_MSG_ERROR(You must specify an absolute path to --with-logfile=PATH)
				;;
		esac
	else
		APP_LOGFILE="/var/log/${PACKAGE}/{PACKAGE}.log"
		APP_LOGDIR="/var/log/${PACKAGE}"
	fi ],
	[ 
	APP_LOGFILE="/var/log/${PACKAGE}/${PACKAGE}.log" 
	APP_LOGDIR="/var/log/${PACKAGE}"
	])

AC_DEFINE_UNQUOTED(APP_LOGFILE, "$APP_LOGFILE", [location of ${PACKAGE} logfile])
AC_SUBST(APP_LOGFILE, "$APP_LOGFILE")
AC_SUBST(APP_LOGDIR, "$APP_LOGDIR")

AC_ARG_WITH(pidfile,
	AS_HELP_STRING([--with-pidfile=PATH],[set file path for source pidfile (default: /var/run/${PACKAGE}/${PACKAGE}.pid)]),
	[ if test ! -z "$with_pidfile" ; then
		case $with_pidfile in
			/*)
				APP_PIDFILE="$with_pidfile"
				APP_PIDDIR=`dirname $APP_PIDFILE`
				;;
			*)
                                AC_MSG_ERROR(You must specify an absolute path to --with-pidfile=PATH)
				;;
		esac
	else
		APP_PIDFILE="/var/run/${PACKAGE}/${PACKAGE}.pid"
		APP_PIDDIR="/var/run/${PACKAGE}"
	fi ],
	[
	APP_PIDFILE="/var/run/${PACKAGE}/${PACKAGE}.pid" 
	APP_PIDDIR="/var/run/${PACKAGE}"
	])

AC_DEFINE_UNQUOTED(APP_PIDFILE, "$APP_PIDFILE", [location of pid file])
AC_SUBST(APP_PIDFILE, "$APP_PIDFILE")
AC_SUBST(APP_PIDDIR, "$APP_PIDDIR")


AC_ARG_WITH(dbdir,
	AS_HELP_STRING([--with-dbdir=PATH],[set file path for data files (default: "/var/db/${PACKAGE}")]),
	[ if test ! -z "$with_dbdir" ; then
		case $with_dbdir in
			/*)
				APP_DBDIR="$with_dbdir"
				;;
			*)
                                AC_MSG_ERROR(You must specify an absolute path to --with-dbdir=PATH)
				;;
		esac
	else
		APP_DBDIR="/var/db/${PACKAGE}"
	fi ],
	[ APP_DBDIR="/var/db/${PACKAGE}" ])
AC_DEFINE_UNQUOTED(APP_DBDIR, "$APP_DBDIR", [location of application data])
AC_SUBST(APP_DBDIR, "$APP_DBDIR")


AC_ARG_WITH(user,
	AS_HELP_STRING([--with-user=minica],[set executing user name]),
	[ if test ! -z "$with_user" ; then
		case $with_user in
			"")
				AC_MSG_ERROR(You must specify user name)
				;;
			*)
				APP_USER="$with_user"
				;;
		esac
	else
		APP_USER="minica"
	fi ],
	[ APP_USER="minica" ])
AC_DEFINE_UNQUOTED(APP_USER, "$APP_USER", [effective user])
AC_SUBST(APP_USER, "$APP_USER")

AC_ARG_WITH(group,
	AS_HELP_STRING([--with-group=minica],[set executing group name]),
	[ if test ! -z "$with_group" ; then
		case $with_group in
			"")
				AC_MSG_ERROR(You must specify group name)
				;;
			*)
				APP_GROUP="$with_group"
				;;
		esac
	else
		APP_GROUP="minica"
	fi ],
	[ APP_GROUP="minica" ])
AC_DEFINE_UNQUOTED(APP_GROUP, "$APP_GROUP", [effective group id])
AC_SUBST(APP_GROUP, "$APP_GROUP")


AC_SUBST(APP_DATADIR, ${ac_default_prefix}/share/${PACKAGE})
AC_SUBST(APP_PWDFILE, ${APP_DBDIR}/${PACKAGE}.pw)



AC_DEFUN([AC_PERL_MODULES],[
ac_perl_modules="$1"
for ac_perl_module in $ac_perl_modules; do
AC_MSG_CHECKING(for perl module $ac_perl_module)
perl "-M$ac_perl_module" -e exit > /dev/null 2>&1
if test $? -ne 0; then
    AC_MSG_RESULT(no);
    AC_MSG_ERROR(You must install perl module $ac_perl_module)
  else
    AC_MSG_RESULT(ok);
fi
done])

AC_PERL_MODULES([
Apache::Htpasswd
Config::Simple
Mojo::Base
Mojo::Home
Mojo::Server
Mojo::Util
Mojo::Server
Crypt::OpenSSL::AES
Crypt::OpenSSL::Random
Crypt::OpenSSL::RSA
Crypt::OpenSSL::CA
Crypt::OpenSSL::X509
Crypt::CBC
DBI
DBD::SQLite
Encode
MIME::QuotedPrint
])

AC_CONFIG_FILES([minica.conf.example])

AC_OUTPUT([Makefile minica rc.d/minica lib/MiniCA.pm minica-cacert-import minica-cert-import])
dnl EOF


