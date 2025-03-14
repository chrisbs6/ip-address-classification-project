#Autoconfigure for lander
#$Id: configure.ac 4349 2008-07-15 20:30:04Z yuri $
AC_INIT([print_datafile], [0.5], [yuri@isi.edu])
AC_CONFIG_AUX_DIR(.build-aux)
AM_INIT_AUTOMAKE([foreign])
#AC_CONFIG_HEADERS([config.h])
AM_CONFIG_HEADER([config.h])

#checks for programs
AC_PROG_CXX
AC_PROG_INSTALL

#check for libraries
link_magic=
link_zlib=
link_bzlib=
link_ssl=

AC_CHECK_LIB([magic],	[magic_file],		[link_magic=-lmagic])
AC_CHECK_LIB([z],	[gzdopen],		[link_zlib=-lz])
AC_CHECK_LIB([bz2],	[BZ2_bzdopen],		[link_bzlib=-lbz2])
AC_CHECK_LIB([crypto],	[BF_ecb_encrypt],	[link_ssl=-lcrypto])

#check for headers
test -n "$link_magic" && AC_CHECK_HEADERS([magic.h],,		[link_magic=])
test -n "$link_zlib"  && AC_CHECK_HEADERS([zlib.h],,		[link_zlib=])
test -n "$link_bzlib" && AC_CHECK_HEADERS([bzlib.h],,		[link_bzlib=])
test -n "$link_ssl"   && AC_CHECK_HEADERS([openssl/blowfish.h],,[link_ssl=])
test -n "$link_ssl"   && AC_CHECK_HEADERS([openssl/sha.h],,	[link_ssl=])

#if a header is defined, then lib is defined as well

test -z "$link_magic" && \
	AC_MSG_WARN([Libmagic is not found: print_datafile cannot autodetermine file types (fix: install the Fedora file-libs package)])
test -z "$link_zlib"  && \
	AC_MSG_WARN([zlib is not found: icmptrain/print_datafile cannot write gzip dumps (fix: install the Fedora zlib-devel package)])
test -z "$link_bzlib" && \
	AC_MSG_WARN([bzlib is not found: icmptrain/print_datafile cannot write bzip2 dumps  (fix: install the Fedora bzip2-devel package)])
test -z "$link_ssl"   && {
	AC_MSG_WARN([ssl is not found: print_datafile cannot use scrambling (fix: install the Fedora glibc-devel package)])
	HAVE_OPENSSL_BLOWFISH_H=
	HAVE_OPENSSL_SHA_H=
	AC_SUBST(HAVE_OPENSSL_BLOWFISH_H)
	AC_SUBST(HAVE_OPENSSL_SHA_H)
}

AC_SUBST(print_datafile_ldadd, "$link_magic $link_zlib $link_bzlib $link_ssl")

#enable large file support
AC_SYS_LARGEFILE

AC_CACHE_SAVE
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])

AC_OUTPUT

