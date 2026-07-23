# -*- makefile -*-
# Make.inc.in
#
# Version:	$Id: fefb022a268626190ccc781068efaa16f7072131 $
#

# Location of files.
prefix		= /usr/local
exec_prefix	= ${prefix}
sysconfdir	= ${prefix}/etc
localstatedir	= ${prefix}/var
libdir		= ${exec_prefix}/lib
bindir		= ${exec_prefix}/bin
sbindir		= ${exec_prefix}/sbin
docdir		= ${datadir}/doc/freeradius
mandir		= ${datarootdir}/man
datadir		= ${datarootdir}
dictdir		= ${datarootdir}/freeradius
logdir		= ${localstatedir}/log/radius
includedir	= ${prefix}/include

#
#  In some systems, we don't want to over-write ANY configuration.
#  So we do:
#
#	$./configure
#	$ make
#	$ make -Draddbdir=/tmp/garbage install
#
#  and all of the configuration files go into /tmp/garbage
#
ifeq "${raddbdir}" ""
raddbdir	= ${sysconfdir}/raddb
endif
modconfdir	= ${raddbdir}/mods-config
radacctdir	= ${logdir}/radacct
top_builddir	= /home/admin-vb/EdhocSecondaryAuth/freeradius-v3
top_build_prefix=/home/admin-vb/EdhocSecondaryAuth/freeradius-v3/
top_srcdir	= /home/admin-vb/EdhocSecondaryAuth/freeradius-v3
datarootdir	= ${prefix}/share

MAKE		= /usr/bin/gmake

# Makeflags set within the makefile appear to be additive and override
# flags set on the command line and the environmental variables
MAKEFLAGS	= 

CC		= gcc
RANLIB		= ranlib
INCLUDE		= -I. -Isrc \
		  -include src/freeradius-devel/autoconf.h \
		  -include src/freeradius-devel/build.h \
		  -include src/freeradius-devel/features.h \
		  -include src/freeradius-devel/radpaths.h
CFLAGS		= $(INCLUDE) -fno-strict-aliasing -Wno-date-time -g -O2 -Wall -std=c99 -D_GNU_SOURCE -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS -DOPENSSL_NO_KRB5 -DNDEBUG 
CPPFLAGS	=           
LIBPREFIX	= lib
EXEEXT		= 

ACLOCAL		= ${SHELL} '/home/admin-vb/EdhocSecondaryAuth/freeradius-v3/missing' aclocal
AUTOCONF	= ${SHELL} '/home/admin-vb/EdhocSecondaryAuth/freeradius-v3/missing' autoconf
AUTOHEADER	= ${SHELL} '/home/admin-vb/EdhocSecondaryAuth/freeradius-v3/missing' autoheader
INSTALL		= ${top_builddir}/install-sh -c
INSTALL_PROGRAM	= ${INSTALL}
INSTALL_DATA	= ${INSTALL} -m 644
INSTALL_SCRIPT	= ${INSTALL_PROGRAM}
INSTALLSTRIP	= 

#
#  Linker arguments for libraries searched for by the main
#  configure script.
#
TALLOC_LIBS     = -ltalloc
TALLOC_LDFLAGS  = 

OPENSSL_LIBS    = -lcrypto -lssl
OPENSSL_LDFLAGS = 
OPENSSL_CPPFLAGS =  

PCAP_LIBS	= -lpcap
PCAP_LDFLAGS    = 

COLLECTDC_LIBS	= 
COLLECTDC_LDFLAGS = 

SYSTEMD_LIBS = 
SYSTEMD_LDFLAGS = 

LCRYPT		= -lcrypt

#
#  OpenSSL libs (if used) must be linked everywhere in order for
#  the server to work properly on on all platforms.
#
LIBS		= $(OPENSSL_LIBS) $(TALLOC_LIBS) -latomic -lresolv -ldl -lpthread 
LDFLAGS		= $(OPENSSL_LDFLAGS) $(TALLOC_LDFLAGS)  

LOGDIR		= ${logdir}
RADDBDIR	= ${raddbdir}
RUNDIR		= ${localstatedir}/run/radiusd
SBINDIR		= ${sbindir}
RADIR		= ${radacctdir}
LIBRADIUS	= $(top_builddir)/src/lib/$(LIBPREFIX)freeradius-radius.la $(TALLOC_LIBS)

USE_SHARED_LIBS = yes
bm_shared_libs  = yes
USE_STATIC_LIBS = yes
bm_static_libs  = yes

STATIC_MODULES	= 
LIBREADLINE	= 

WITH_DHCP	= yes

#
#  Version to use for packaging and other Make related things
#
RADIUSD_VERSION_STRING = 3.2.6

#
#  This allows dlopen to do runtime checks for version mismatches
#  between what it was originally linked with, and the library it's
#  actually loading.
#
MODULES		=  rlm_always rlm_attr_filter rlm_cache rlm_chap rlm_counter rlm_detail rlm_dhcp rlm_digest rlm_dpsk rlm_dynamic_clients rlm_eap rlm_exec rlm_expiration rlm_expr rlm_files rlm_ippool rlm_json rlm_krb5 rlm_ldap rlm_linelog rlm_logintime rlm_mschap rlm_pam rlm_pap rlm_passwd rlm_perl rlm_preprocess rlm_python rlm_python3 rlm_radutmp rlm_realm rlm_rest rlm_replicate rlm_soh rlm_sql rlm_sqlcounter rlm_sqlippool rlm_sql_map rlm_test rlm_totp rlm_unix rlm_sometimes rlm_wimax rlm_unbound rlm_yubikey rlm_redis rlm_rediswho
HOSTINFO	= x86_64-pc-linux-gnu

#
#  If the system has OpenSSL, use it's version of MD4/MD5/SHA1, instead of
#  using ours.
#
#  We don't use OpenSSL SHA1 by default because src/modules/rlm_eap/libeap/fips186prf.c
#  needs access to the SHA internals.
#
ifeq "$(WITH_OPENSSL)" "yes"
CFLAGS		+=  -DWITH_OPENSSL_MD4 -DWITH_OPENSSL_MD5
CPPFLAGS	:= "$(OPENSSL_CPPFLAGS) $(CPPFLAGS)"
endif

OPENSSL_LIBS	= -lcrypto -lssl

ifneq ($(WITH_OPENSSL_MD5),)
LIBRADIUS_WITH_OPENSSL = 1
CFLAGS += -DWITH_OPENSSL_MD5
endif

ifneq ($(WITH_OPENSSL_SHA1),)
LIBRADIUS_WITH_OPENSSL = 1
CFLAGS += -DWITH_OPENSSL_SHA1
endif

ifneq ($(LIBRADIUS_WITH_OPENSSL),)
ifeq ($(OPENSSL_LIBS),)
$(error OPENSSL_LIBS must be define in order to use WITH_OPENSSL_*)
else
LIBRADIUS += $(OPENSSL_LIBS)
endif
endif

# Path to clang, setting this enables the 'scan.*' build targets
# which perform static analysis on various server components.
ANALYZE.c       := 

#
#  With shared libs, the test binaries are in a different place
#  AND the method we use to run those binaries changes.
#
ifeq "$(USE_SHARED_LIBS)" "yes"
	TESTBINDIR = ./$(BUILD_DIR)/bin/local
	TESTBIN    =  FR_LIBRARY_PATH=./build/lib/.libs $(JLIBTOOL) --quiet --mode=execute $(TESTBINDIR)
else
	TESTBINDIR = ./$(BUILD_DIR)/bin
	TESTBIN    = ./$(BUILD_DIR)/bin
endif


#
#  For creating documentation via doc/all.mk
#
ASCIIDOCTOR := 
PANDOC := 
PANDOC_ENGINE := 
DOXYGEN := 
GRAPHVIZ_DOT := 
ANTORA := 
