#
# $Id$
#
AUTOMAKE_OPTIONS = foreign no-dependencies no-installinfo

sbin_SCRIPTS = microca microca-cacert-import microca-cert-import

databasedir = @APP_DBDIR@
nobase_dist_database_DATA = microca.db.sample microca.pw.sample  microca.sql.sample

confdir = @APP_SYSCONFDIR@
nobase_conf_DATA = microca.conf.sample


microca.db.sample: microca.db
	cp microca.db microca.db.sample

microca.pw.sample: microca.pw
	cp microca.pw microca.pw.sample

microca.sql.sample: microca.sql
	cp microca.sql microca.sql.sample

microca.conf.sample: microca.conf
	cp microca.conf microca.conf.sample

etcdir = /usr/local/etc

if FREEBSD_OS
nobase_etc_SCRIPTS = rc.d/microca
endif

EXTRA_DIST = \
	LICENSE \
	microca.pw \
	microca.db \
	microca.sql \
	microca.8


nobase_dist_pkgdata_DATA = \
	public/favicon.png \
	public/css/app.css \
	public/css/foundation.css \
	public/css/foundation.min.css \
	public/css/autoFill.dataTables.css \
	public/css/autoFill.dataTables.min.css \
	public/css/autoFill.foundation.css \
	public/css/autoFill.foundation.min.css \
	public/css/dataTables.foundation.css \
	public/css/dataTables.foundation.min.css \
	public/css/fixedHeader.dataTables.css \
	public/css/fixedHeader.dataTables.min.css \
	public/css/fixedHeader.foundation.css \
	public/css/fixedHeader.foundation.min.css \
	public/css/jquery.dataTables.css \
	public/css/jquery.dataTables.min.css \
	public/css/colReorder.dataTables.css \
	public/css/colReorder.dataTables.min.css \
	public/css/colReorder.foundation.css \
	public/css/colReorder.foundation.min.css \
	public/js/jquery.js \
	public/js/what-input.js \
	public/js/jquery.min.js \
	public/js/foundation.js \
	public/js/app.js \
	public/js/foundation.min.js \
	public/js/jquery.simplePagination.js \
	public/js/autoFill.foundation.js \
	public/js/autoFill.foundation.min.js \
	public/js/dataTables.autoFill.js \
	public/js/dataTables.autoFill.min.js \
	public/js/dataTables.foundation.js \
	public/js/dataTables.foundation.min.js \
	public/js/jquery.dataTables.js \
	public/js/jquery.dataTables.min.js \
	public/js/dataTables.fixedHeader.js \
	public/js/dataTables.fixedHeader.min.js \
	public/js/foundation.js.orig \
	public/js/what-input.min.js \
	public/js/dataTables.colReorder.js \
	public/js/dataTables.colReorder.min.js \
	public/favicon.ico \
	public/images/sort_both.png \
	public/images/sort_asc_disabled.png \
	public/images/sort_desc_disabled.png \
	public/images/sort_desc.png \
	public/images/sort_asc.png \
	\
	public/muppetshow.jpg \
	public/muppetshow2.jpg \
	\
	templates/login.html.ep \
	templates/layouts/login.html.ep \
	templates/layouts/default.html.ep \
	templates/start.html.ep \
	templates/debug.html.ep \
	\
	templates/not_found.html.ep \
	templates/exception.html.ep \
	\
	lib/MicroCA.pm \
	lib/MicroCA/Controller/Main.pm \
	lib/MicroCA/Model/Users.pm \
	lib/MicroCA/Model/CA.pm \
	lib/Mojolicious/Plugin/RenderFile.pm \
	\
	templates/cacert-list.html.ep \
	templates/cacert-create.html.ep \
	templates/cacert-show-form.html.ep \
	templates/cacert-show.html.ep \
	templates/cacert-delete-form.html.ep \
	templates/cacert-delete.html.ep \
	templates/cacert-revoke-form.html.ep \
	templates/cacert-revoke.html.ep \
	templates/cacert-unrevoke-form.html.ep \
	templates/cacert-unrevoke.html.ep \
	templates/cacert-download-form.html.ep \
	\
	templates/cert-list.html.ep \
	templates/cert-list-form.html.ep \
	templates/cert-create.html.ep \
	templates/cert-show-form.html.ep \
	templates/cert-show.html.ep \
	templates/cert-delete-form.html.ep \
	templates/cert-delete.html.ep \
	templates/cert-revoke-form.html.ep \
	templates/cert-revoke.html.ep \
	templates/cert-unrevoke-form.html.ep \
	templates/cert-unrevoke.html.ep \
	templates/cert-download-form.html.ep \
	\
	templates/crl-list-form.html.ep \
	templates/crl-list.html.ep \
	templates/crl-create.html.ep \
	templates/crl-delete-form.html.ep \
	templates/crl-delete.html.ep \
	templates/crl-download-form.html.ep \
	templates/crl-show-form.html.ep \
	templates/crl-show.html.ep \
	templates/crl-download-form.html.ep \
	\
	templates/user-chname-form.html.ep \
	templates/user-chname.html.ep \
	templates/user-chpwd-form.html.ep \
	templates/user-chpwd.html.ep \
	templates/user-create.html.ep \
	templates/user-delete-form.html.ep \
	templates/user-delete.html.ep \
	templates/user-list.html.ep \
	\
	public/jquery-ui/jquery-ui.css \
	public/jquery-ui/jquery-ui.js \
	public/jquery-ui/jquery-ui.min.css \
	public/jquery-ui/jquery-ui.min.js \
	public/jquery-ui/jquery-ui.structure.css \
	public/jquery-ui/jquery-ui.structure.min.css \
	public/jquery-ui/jquery-ui.theme.css \
	public/jquery-ui/jquery-ui.theme.min.css \
	\
	templates/doc.html.ep \
	public/docs/microca-lifecicle1.svg \
	public/docs/microca-lifecicle2.svg


install-data-hook:
if FREEBSD_OS
	chmod a+x $(DESTDIR)/${etcdir}/rc.d/microca
endif
	$(INSTALL) -d -m 750 -o $(APP_USER) -g $(APP_GROUP) $(DESTDIR)$(APP_DBDIR)
	$(INSTALL) -d -m 750 -o $(APP_USER) -g $(APP_GROUP) $(DESTDIR)$(APP_LOGDIR)
	$(INSTALL) -d -m 750 -o $(APP_USER) -g $(APP_GROUP) $(DESTDIR)$(APP_PIDDIR)
	for data in $(nobase_dist_database_DATA);do \
	  chown $(APP_USER):$(APP_GROUP) $(DESTDIR)$(APP_DBDIR)/$$data; \
	  chmod 0640 $(DESTDIR)$(APP_DBDIR)/$$data; \
	done


man_MANS = microca.8

microca.8: microca
	pod2man microca > microca.8

microca: microca.pl
	cp microca.pl microca
	chmod a+x microca

microca.db: microca.sql
	sqlite3 microca.db < microca.sql
	chmod go-rw microca

microca-cert-import: microca-cert-import.pl
	cp microca-cert-import.pl microca-cert-import
	chmod a+x microca-cert-import

microca-cacert-import: microca-cacert-import.pl
	cp microca-cacert-import.pl microca-cacert-import
	chmod a+x microca-cacert-import

clean:
	rm -f microca *~ */*~ */*/*~ */*/*/*~

#EOF
