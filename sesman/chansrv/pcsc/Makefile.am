#EXTRA_DIST = \
  #xrdp_surface.c

AM_CPPFLAGS = \
    $(LIBPCSCLITE_CFLAGS)
#   -DXRDP_PAMCONF_PATH=\"${pamconfdir}\" \
#   -DXRDP_CFG_PATH=\"${sysconfdir}/xrdp\" \
#   -I$(top_srcdir)/libipm \
#   -I$(top_srcdir)/common \
#  -DXRDP_SBIN_PATH=\"${sbindir}\" \
#  -DXRDP_SHARE_PATH=\"${datadir}/xrdp\" \
#  -DXRDP_PID_PATH=\"${localstatedir}/run\"

#AM_CFLAGS = $(OPENSSL_CFLAGS)

#AM_LDFLAGS =

#LIBXRDP_EXTRA_LIBS =

lib_LTLIBRARIES = \
  libpcsclite-xrdp.la

libpcsclite_xrdp_la_SOURCES = \
  xrdp_pcsc.c \
  xrdp_pcsc.h

libpcsclite_xrdp_la_LIBADD = \
 -lpthread

libpcsclite_xrdp_la_LDFLAGS = \
  -version-info 0:0:0
