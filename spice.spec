Name:           spice
Version:        0.14.0
Release:        7%{?dist}
Summary:        Implements the SPICE protocol
Group:          User Interface/Desktops
License:        LGPLv2+
URL:            http://www.spice-space.org/
Source0:        http://www.spice-space.org/download/releases/%{name}-%{version}.tar.bz2
Patch1:         0001-inputs-channel-Check-message-size-handling-migration.patch
Patch2:         0002-red-channel-Remove-red_channel_init_outgoing_message.patch
Patch3:         0003-reds-Remove-leak-allocating-migration-state.patch
Patch4:         0004-tests-Check-leaks-registering-migration-interface.patch
Patch5:         0005-Notify-client-of-the-creation-of-new-channels-dynami.patch
Patch6:         0006-stream-device-Add-device-to-handle-streaming.patch
Patch7:         0007-stream-device-Start-parsing-new-protocol-from-guest.patch
Patch8:         0008-stream-channel-Write-a-base-channel-to-implement-the.patch
Patch9:         0009-stream-channel-Start-implementing-DisplayChannel-pro.patch
Patch10:        0010-stream-device-Create-channel-for-stream-device.patch
Patch11:        0011-stream-device-Handle-streaming-data-from-device-to-c.patch
Patch12:        0012-stream-channel-Allows-not-fixed-size.patch
Patch13:        0013-stream-channel-Allows-to-register-callback-to-get-ne.patch
Patch14:        0014-stream-channel-Support-client-connection-disconnecti.patch
Patch15:        0015-stream-channel-Do-not-show-an-empty-blank-screen-on-.patch
Patch16:        0016-char-device-Do-not-stop-and-clear-interface-on-reset.patch
Patch17:        0017-stream-device-Start-supporting-resetting-device-when.patch
Patch18:        0018-stream-device-Create-channel-when-needed.patch
Patch19:        0019-stream-device-Limit-sending-queue-from-guest-to-serv.patch
Patch20:        0020-stream-channel-Activate-streaming-report-from-client.patch
Patch21:        0021-reds-Disable-TLS-1.0.patch
Patch22:        0022-cursor-Delay-release-of-QXL-guest-cursor-resources.patch
Patch23:        0023-sound-Don-t-mute-recording-when-client-reconnects.patch
Patch24:        0024-tls-Parse-spice.cnf-OpenSSL-configuration-file.patch
Patch25:        0025-ssl-Allow-to-use-ECDH-ciphers-with-OpenSSL-1.0.patch
Patch26:        0026-Fix-flexible-array-buffer-overflow.patch
Patch27:        0027-dcc-Fix-QUIC-fallback-in-get_compression_for_bitmap.patch
Patch28:        0028-memslot-Fix-off-by-one-error-in-group-slot-boundary-.patch

# https://bugzilla.redhat.com/show_bug.cgi?id=613529
%if 0%{?rhel}
ExclusiveArch:  x86_64
%else
ExclusiveArch:  i686 x86_64 armv6l armv7l armv7hl
%endif

BuildRequires:  pkgconfig
BuildRequires:  glib2-devel >= 2.22
BuildRequires:  spice-protocol >= 0.12.10
BuildRequires:  celt051-devel
BuildRequires:  pixman-devel alsa-lib-devel openssl-devel libjpeg-turbo-devel
BuildRequires:  libcacard-devel cyrus-sasl-devel
BuildRequires:  lz4-devel
BuildRequires:  pyparsing python-six
BuildRequires:  opus-devel
BuildRequires:  git
BuildRequires:  autoconf automake libtool

%description
The Simple Protocol for Independent Computing Environments (SPICE) is
a remote display system built for virtual environments which allows
you to view a computing 'desktop' environment not only on the machine
where it is running, but from anywhere on the Internet and from a wide
variety of machine architectures.


%package server
Summary:        Implements the server side of the SPICE protocol
Group:          System Environment/Libraries
Obsoletes:      spice-client < %{version}-%{release}
# Ensure SSL_CONF_CTX_set_ssl_ctx (needed by Patch24) is present
# https://bugzilla.redhat.com/show_bug.cgi?id=1627693
Requires:       openssl-libs >= 1.0.2k-16

%description server
The Simple Protocol for Independent Computing Environments (SPICE) is
a remote display system built for virtual environments which allows
you to view a computing 'desktop' environment not only on the machine
where it is running, but from anywhere on the Internet and from a wide
variety of machine architectures.

This package contains the run-time libraries for any application that wishes
to be a SPICE server.


%package server-devel
Summary:        Header files, libraries and development documentation for spice-server
Group:          Development/Libraries
Requires:       %{name}-server%{?_isa} = %{version}-%{release}
Requires:       pkgconfig
Requires:       spice-protocol >= 0.12.3

%description server-devel
This package contains the header files, static libraries and development
documentation for spice-server. If you like to develop programs
using spice-server, you will need to install spice-server-devel.


%prep
%autosetup -S git_am


%build
autoreconf -fi
%configure --enable-smartcard --disable-client
make %{?_smp_mflags} WARN_CFLAGS='' V=1


%install
make DESTDIR=%{buildroot} install
rm -f %{buildroot}%{_libdir}/libspice-server.a
rm -f %{buildroot}%{_libdir}/libspice-server.la
mkdir -p %{buildroot}%{_libexecdir}


%post server -p /sbin/ldconfig
%postun server -p /sbin/ldconfig


%files server
%doc COPYING README NEWS docs/spice.cnf.sample
%{_libdir}/libspice-server.so.1*

%files server-devel
%{_includedir}/spice-server
%{_libdir}/libspice-server.so
%{_libdir}/pkgconfig/spice-server.pc


%changelog
* Tue Dec 18 2018 Christophe Fergeau <cfergeau@redhat.com> - 0.14.0-7
- Fix off-by-one error during guest-to-host memory address conversion
  Resolves: CVE-2019-3813
- Add patch for upstream commit 48179332d9da0. This should help with corrupted
  spice-html5 displays
  Resolves: rhbz#1573739
- Add missing minimum openssl version Requires for patch #24
  Resolves: rhbz#1627693

* Thu Aug 09 2018 Frediano Ziglio <fziglio@redhat.com> - 0.14.0-6
- Fix flexible array buffer overflow
  Resolves: rhbz#1596008

* Wed Jun 20 2018 Christophe Fergeau <cfergeau@redhat.com> - 0.14.0-5
- Don't mute Record channel on client reconnection
  Resolves: rhbz#1549132
- Allow to configure TLS protocol versions and ciphers which SPICE will use for
  TLS communications
  Resolves: rhbz#1562213
- Enable ECDH ciphers with OpenSSL 1.0
  Resolves: rhbz#1566597

* Fri Apr 27 2018 Christophe Fergeau <cfergeau@redhat.com> - 0.14.0-4
- Revert back to spice 0.12 behaviour where QXL guest resources for cursor
  commands are only released when the current cursor is replaced. This avoids
  a QEMU regression causing crashes during migration
  Resolves: rhbz#1567944

* Tue Apr 03 2018 Christophe Fergeau <cfergeau@redhat.com> - 0.14.0-3
- Disable TLSv1.0
  Resolves: rhbz#1521053

* Thu Oct 12 2017 Christophe Fergeau <cfergeau@redhat.com> - 0.14.0-2
- Add streaming patches for use with spice-streaming-agent
  Related: rhbz#1478356

* Wed Oct 11 2017 Christophe Fergeau <cfergeau@redhat.com> - 0.14.0-1
- Rebase to 0.14.0 release
  Resolves: rhbz#1472948

* Fri Sep 22 2017 Christophe Fergeau <cfergeau@redhat.com> 0.13.90-2
- Add lz4-devel BuildRequires
  Resolves: rhbz#1460191

* Wed Jul 26 2017 Christophe Fergeau <cfergeau@redhat.com> 0.13.90-1
- Rebase to latest upstream release
  Resolves: rhbz#1472948

* Fri Jul 14 2017 Jonathon Jongsma <jjongsma@redhat.com> - 0.12.8-4
- build with opus support
  Resolves: rhbz#1456832

* Fri Jun 30 2017 Christophe Fergeau <cfergeau@redhat.com> 0.12.8-3
- Prevent potential buffer/integer overflows with invalid MonitorsConfig messages
  sent from an authenticated client
  Resolves: CVE-2017-7506

* Tue Apr 25 2017 Christophe Fergeau <cfergeau@redhat.com> 0.12.8-2
- Drop clients immediatly if the magic they send is wrong
  Resolves: rhbz#1416692

* Mon Jan 16 2017 Christophe Fergeau <cfergeau@redhat.com> 0.12.8-1
- Rebase to spice-server 0.12.8
  Resolves: rhbz#1388947
  Resolves: rhbz#1377551
  Resolves: rhbz#1283202
* Fri Dec 09 2016 Frediano Ziglio <fziglio@redhat.com> - 0.12.4-20
- Fix buffer overflow in main_channel_alloc_msg_rcv_buf when reading large
  messages.
  Resolves: CVE-2016-9577
- Fix remote DoS via crafted message.
  Resolves: CVE-2016-9578
* Fri Sep 09 2016 Christophe Fergeau <cfergeau@redhat.com> 0.12.4-19
- Ensure SPICE_MIGRATE_COMPLETED is sent in all cases when it's needed.
  Resolves: rhbz#1352836
* Fri Jul 01 2016 Christophe Fergeau <cfergeau@redhat.com> - 0.12.4-18
- Fix crash when connecting to VM using smartcard passthrough
  Resolves: rhbz#1340899
- Fix hang after unredirecting a USB device
  Resolves: rhbz#1338752
- Backport spice_qxl_set_max_monitors()
  Resolves: rhbz#1283202
* Wed Apr 27 2016 Christophe Fergeau <cfergeau@redhat.com> - 0.12.4-17
- Fix crash when the client sends a wrong header (for example when using spice-html5)
  Resolves: rhbz#1281442
- Fix crash when guest provides wrong address
  Resolves: rhbz#1264356
- Fix thread-safety issue causing a crash when playing a Youtube video spanning
  multiple monitors
  Resolves: rhbz#1253375
- Add patches reducing QEMU wake-ups
  Related: rhbz#912763, rhbz#1186146
- Fix use-after-free after resetting a VM
  Resolves: rhbz#1281455
- Send KeepAlive probes every 10 minutes
  Resolves: rhbz#1298590
- Add client to guest volume synchronization
  Resolves: rhbz#1264107

* Mon Apr 25 2016 Christophe Fergeau <cfergeau@redhat.com> - 0.12.4-16
- Use autosetup
  Related: CVE-2016-0749
- Fix heap-based memory corruption within smartcard handling
  Resolves: CVE-2016-0749
- Fix host memory access from guest with invalid primary surface parameters
  Resolves: CVE-2016-2150

* Wed Sep 23 2015 Frediano Ziglio <fziglio@redhat.com> 0.12.4-15
- CVE-2015-5260 CVE-2015-5261 fixed various security flaws
  Resolves: rhbz#1267134

* Thu Sep 10 2015 Frediano Ziglio <fziglio@redhat.com> 0.12.4-14
- Validate surface_id
  Resolves: rhbz#1260971

* Tue Jul 21 2015 Frediano Ziglio <fziglio@redhat.com> 0.12.4-13
- Clean stale statistics file before creating a new one
  Resolves: rhbz#1177326

* Fri Jul 10 2015 Fabiano Fidêncio <fidencio@redhat.com> 0.12.4-12
- Fix a backport issue on Patch0040.
  Related: rhbz#1071176
  Resolves: rhbz#1241860

* Thu Jul 09 2015 Fabiano Fidêncio <fidencio@redhat.com> 0.12.4-11
- Don't assert on invalid client message
  Resolves: rhbz#1227410
- Don't truncate large 'now' values in _spice_timer_set
  Resolves: rhbz#1227408
- Avoid race conditions reading monitor configs from guest
  Resolves: rhbz#1239128
- Lock the pixmap image cache for the entire fill_bits call
  Resolves: rhbz#1235443

* Wed Jul 08 2015 Fabiano Fidêncio <fidencio@redhat.com> 0.12.4-10
- Fix qemu segmentation fault (core dumped) when boot KVM guest with
  spice in FIPS enabled mode.
  Resolves: rhbz#1071176

* Mon Jan 05 2015 Marc-Andre Lureau <marcandre.lureau@redhat.com> 0.12.4-9
- Allow recent TLS/SSL methods, block SSLv2/SSLv3. Resolves: rhbz#1175540

* Tue Oct 21 2014 Christophe Fergeau <cfergeau@redhat.com> 0.12.4-8
- Fix defects reported by Coverity
  Resolves: rhbz#885717
- Validate surface bounding box sent from QXL driver
  Resolves: rhbz#1052856
- Fix assertion sometimes happening during migration while a client is
  connected
  Resolves: rhbz#1035184
- Fix crash when restarting VM with old client
  Resolves: rhbz#1145919

* Thu Sep 18 2014 Christophe Fergeau <cfergeau@redhat.com> 0.12.4-7
- Fix assert in mjpeg_encoder_adjust_params_to_bit_rate()
  Resolves: rhbz#1086823
- Fix "Spice-ERROR **: reds.c:1464:reds_send_link_ack: assertion
  `link->link_mess->channel_type == SPICE_CHANNEL_MAIN' failed" assertion
  Resolves: rhbz#1058625
- Lower a monitor-config warning to debug level
  Resolves: rhbz#1119220
- mjpeg: Don't warn on unsupported image formats
  Resolves: rhbz#1070028

* Thu Aug 07 2014 Marc-Andre Lureau <marcandre.lureau@redhat.com> 0.12.4-6
- Fix invalid surface clearing
  Resolves: rhbz#1029646

* Wed Jan 29 2014 Christophe Fergeau <cfergeau@redhat.com> 0.12.4-5
- Fix qemu crash during migration with reboot
  Resolves: rhbz#1016795
- Monitor whether the client is alive
  Resolves: rhbz#1016790

* Tue Oct 15 2013 Christophe Fergeau <cfergeau@redhat.com> 0.12.4-3
- Fix spice-server crash when client sends a password which is too long
  Resolves: CVE-2013-4282

* Fri Sep 13 2013 Christophe Fergeau <cfergeau@redhat.com> 0.12.4-2
- Add upstream patch fixing rhbz#995041

* Fri Aug  2 2013 Hans de Goede <hdegoede@redhat.com> - 0.12.4-1
- Add patches from upstream git to fix sound-channel-free crash (rhbz#986407)
- Add Obsoletes for dropped spice-client sub-package

* Mon Jul 22 2013 Yonit Halperin <yhalperi@redhat.com> 0.12.4-1
- New upstream release 0.12.4
- Require libjpeg-turbo-devel instead of libjpeg-devel
- Remove "BuildRequires: spice-protocol" from spice-server
- Add "Requires: spice-protocol" to spice-server-devel.

* Thu May 23 2013 Christophe Fergeau <cfergeau@redhat.com> 0.12.3-2
- Stop building spicec, it's obsolete and superseded by remote-viewer
  (part of virt-viewer)

* Tue May 21 2013 Christophe Fergeau <cfergeau@redhat.com> 0.12.3-1
- New upstream release 0.12.3
- Drop all patches (they were all upstreamed)

* Mon Apr 15 2013 Hans de Goede <hdegoede@redhat.com> - 0.12.2-4
- Add fix from upstream for a crash when the guest uses RGBA (rhbz#952242)

* Thu Mar 07 2013 Adam Jackson <ajax@redhat.com> 0.12.2-4
- Rebuild for new libsasl2 soname in F19

* Mon Jan 21 2013 Hans de Goede <hdegoede@redhat.com> - 0.12.2-3
- Add a number of misc. bug-fixes from upstream

* Fri Dec 21 2012 Adam Tkac <atkac redhat com> - 0.12.2-2
- rebuild against new libjpeg

* Thu Dec 20 2012 Hans de Goede <hdegoede@redhat.com> - 0.12.2-1
- New upstream release 0.12.2

* Fri Sep 28 2012 Hans de Goede <hdegoede@redhat.com> - 0.12.0-1
- New upstream release 0.12.0
- Some minor spec file cleanups
- Enable building on arm

* Thu Sep 6 2012 Soren Sandmann <ssp@redhat.com> - 0.11.3-1
- BuildRequire pyparsing

* Thu Sep 6 2012 Soren Sandmann <ssp@redhat.com> - 0.11.3-1
- Add capability patches
- Add capability patches to the included copy of spice-protocol

    Please see the comment above Patch6 and Patch7
    regarding this situation.

* Thu Sep 6 2012 Soren Sandmann <ssp@redhat.com> - 0.11.3-1
- Update to 0.11.3 and drop upstreamed patches
- BuildRequire spice-protocol 0.12.1

* Sat Jul 21 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.10.1-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Mon May 14 2012 Alon Levy <alevy@redhat.com>
- Fix mjpeg memory leak and bad behavior.
- Add usbredir to list of channels for security purposes. (#819484)

* Sun May 13 2012 Alon Levy <alevy@redhat.com>
- Add double free fix. (#808936)

* Tue Apr 24 2012 Alon Levy <alevy@redhat.com>
- Add 32 bit fixes from git master. (#815717)

* Tue Feb 28 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.10.1-2
- Rebuilt for c++ ABI breakage

* Mon Jan 23 2012 Hans de Goede <hdegoede@redhat.com> - 0.10.1-1
- New upstream release 0.10.1

* Sat Jan 14 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.10.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Thu Nov 10 2011 Alon Levy <alevy@redhat.com> - 0.10.0-1
- New upstream release 0.10.0
- support spice-server.i686

* Wed Sep 28 2011 Marc-André Lureau <marcandre.lureau@redhat.com> - 0.9.1-2
- Provides spice-xpi-client alternative in spice-client

* Thu Aug 25 2011 Hans de Goede <hdegoede@redhat.com> - 0.9.1-1
- New upstream release 0.9.1

* Mon Jul 25 2011 Marc-André Lureau <marcandre.lureau@redhat.com> - 0.9.0-1
- New upstream release 0.9.0

* Wed Apr 20 2011 Hans de Goede <hdegoede@redhat.com> - 0.8.1-1
- New upstream release 0.8.1

* Fri Mar 11 2011 Hans de Goede <hdegoede@redhat.com> - 0.8.0-2
- Fix being unable to send ctrl+alt+key when release mouse is bound to
  ctrl+alt (which can happen when used from RHEV-M)

* Tue Mar  1 2011 Hans de Goede <hdegoede@redhat.com> - 0.8.0-1
- New upstream release 0.8.0

* Fri Feb 11 2011 Hans de Goede <hdegoede@redhat.com> - 0.7.3-1
- New upstream release 0.7.3

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.7.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Wed Jan 19 2011 Hans de Goede <hdegoede@redhat.com> - 0.7.2-1
- New upstream release 0.7.2

* Fri Dec 17 2010 Hans de Goede <hdegoede@redhat.com> - 0.7.1-1
- New upstream release 0.7.1
- Drop all patches (all upstreamed)
- Enable smartcard (CAC) support

* Wed Nov 17 2010 Hans de Goede <hdegoede@redhat.com> - 0.6.3-4
- Fix the info layer not showing when used through the XPI
- Do not let the connection gui flash by when a hostname has been specified
  on the cmdline
- Fix spice client locking up when dealing with XIM input (#654265)
- Fix modifier keys getting stuck (#655048)
- Fix spice client crashing when dealing with XIM ibus input (#655836)
- Fix spice client only showing a white screen in full screen mode

* Sat Nov  6 2010 Hans de Goede <hdegoede@redhat.com> - 0.6.3-3
- Log to ~/.spicec/cegui.log rather then to CEGUI.log in the cwd, this
  fixes spicec from aborting when run in a non writable dir (#650253)

* Fri Nov  5 2010 Hans de Goede <hdegoede@redhat.com> - 0.6.3-2
- Various bugfixes from upstream git:
  - Make spicec work together with the Firefox XPI for RHEV-M
  - Make sure the spicec window gets properly raised when first shown

* Mon Oct 18 2010 Hans de Goede <hdegoede@redhat.com> - 0.6.3-1
- Update to 0.6.3
- Enable GUI

* Thu Sep 30 2010 Gerd Hoffmann <kraxel@redhat.com> - 0.6.1-1
- Update to 0.6.1.

* Tue Aug 31 2010 Alexander Larsson <alexl@redhat.com> - 0.6.0-1
- Update to 0.6.0 (stable release)

* Tue Jul 20 2010 Alexander Larsson <alexl@redhat.com> - 0.5.3-1
- Update to 0.5.3

* Tue Jul 13 2010 Gerd Hoffmann <kraxel@redhat.com> - 0.5.2-4
- Quote %% in changelog to avoid macro expansion.

* Mon Jul 12 2010 Gerd Hoffmann <kraxel@redhat.com> - 0.5.2-3
- %%configure handles CFLAGS automatically, no need to fiddle
  with %%{optflags} manually.

* Mon Jul 12 2010 Gerd Hoffmann <kraxel@redhat.com> - 0.5.2-2
- Fix license: LGPL.
- Cleanup specfile, drop bits not needed any more with
  recent rpm versions (F13+).
- Use optflags as-is.
-

* Fri Jul 9 2010 Gerd Hoffmann <kraxel@redhat.com> - 0.5.2-1
- initial package.

