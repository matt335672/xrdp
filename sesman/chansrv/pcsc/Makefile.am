#EXTRA_DIST = \
  #xrdp_surface.c

AM_CPPFLAGS = \
    $(LIBPCSCLITE_CFLAGS)
#   -DXRDP_PAMCONF_PATH=\"${pamconfdir}\" \
#   -DXRDP_CFG_PATH=\"${sysconfdir}/xrdp\" \
#   -I$(top_srcdir)/libipm \
#   -I$(top_srcdir)/common
#  -DXRDP_SBIN_PATH=\"${sbindir}\" \
#  -DXRDP_SHARE_PATH=\"${datadir}/xrdp\" \
#  -DXRDP_PID_PATH=\"${localstatedir}/run\"

#AM_CFLAGS = $(OPENSSL_CFLAGS)

#AM_LDFLAGS =

#LIBXRDP_EXTRA_LIBS =

pcscmodule_LTLIBRARIES = \
  libpcsclite.la

libpcsclite_la_SOURCES = \
  xrdp_pcsc.c

libpcsclite_la_LIBADD = \
 -lpthread

libpcsclite_la_LDFLAGS = \
  -version-info 1:0:0
