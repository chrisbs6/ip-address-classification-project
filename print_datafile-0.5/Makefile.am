# $Id: Makefile 4485 2008-08-26 19:53:18Z yuri $

AM_CXXFLAGS = -Wall -Werror -Wno-system-headers -Woverloaded-virtual -Wsign-promo \
	      -Wformat-security -Wparentheses -Wsequence-point -Wshadow -pedantic
#AM_CXXFLAGS += -Weffc++


bin_PROGRAMS = print_datafile
print_datafile_SOURCES = icmptrain_datafile.cc  icmptrain_datafile.hh  print_datafile.cc  \
	scramble_crypt.c  scramble_crypt.h
print_datafile_LDADD = @print_datafile_ldadd@

$(srcdir)/stamp-h.in: configure.ac aclocal.m4
	cd '$(srcdir)' && autoheader
	echo timestamp > '$(srcdir)/stamp-h.in'

tarball: distclean
	cd ..; tar zcvfh print_datafile.tar.gz print_datafile
