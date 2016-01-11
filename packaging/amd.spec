%bcond_with x
%bcond_with wayland

Name:       amd
Summary:    Application Management Daemon
Version:    0.0.100
Release:    1
Group:      Application Framework/Service
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source100:  ac.conf
Source101:  ac.service
Source102:  ac.socket
Source1001: %{name}.manifest

Requires(post):   /sbin/ldconfig
Requires(post):   /usr/bin/systemctl
Requires(postun): /sbin/ldconfig
Requires(postun): /usr/bin/systemctl
Requires(preun):  /usr/bin/systemctl
Requires:   tizen-platform-config

BuildRequires:  cmake
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(security-manager)
BuildRequires:  pkgconfig(rua)
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(pkgmgr)
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(cynara-client)
BuildRequires:  pkgconfig(cynara-creds-socket)
BuildRequires:  pkgconfig(cynara-session)
BuildRequires:  pkgconfig(cert-svc-vcore)
BuildRequires:  pkgconfig(libsmack)
%if %{with wayland}
BuildRequires:  pkgconfig(ecore-wayland)
BuildRequires:  pkgconfig(wayland-client)
BuildRequires:  pkgconfig(tizen-extension-client)
%endif

%description
Application management daemon

%prep
%setup -q
sed -i 's|TZ_SYS_DB|%{TZ_SYS_DB}|g' %{SOURCE1001}
cp %{SOURCE1001} .

%build
%if 0%{?simulator}
CFLAGS="%{optflags} -D__emul__"; export CFLAGS
%endif

MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%cmake . -DFULLVER=%{version} -DMAJORVER=${MAJORVER} \
%if %{with wayland}
-Dwith_wayland=TRUE\
%endif
%if %{with x}
-Dwith_x11=TRUE\
%endif

%__make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_tmpfilesdir}
mkdir -p %{buildroot}%{_unitdir_user}/default.target.wants
mkdir -p %{buildroot}%{_unitdir_user}/sockets.target.wants
install -m 0644 %SOURCE100 %{buildroot}%{_tmpfilesdir}/ac.conf
install -m 0644 %SOURCE101 %{buildroot}%{_unitdir_user}/ac.service
install -m 0644 %SOURCE102 %{buildroot}%{_unitdir_user}/ac.socket
ln -sf ../ac.service %{buildroot}%{_unitdir_user}/default.target.wants/ac.service
ln -sf ../ac.socket %{buildroot}%{_unitdir_user}/sockets.target.wants/ac.socket

%preun
if [ $1 == 0 ]; then
    systemctl stop ac.service
    systemctl disable ac
fi

%post
/sbin/ldconfig

systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart ac.service
fi

%postun
/sbin/ldconfig
systemctl daemon-reload

%files
%license LICENSE
%manifest %{name}.manifest
%{_tmpfilesdir}/ac.conf
%{_unitdir_user}/ac.service
%{_unitdir_user}/default.target.wants/ac.service
%{_unitdir_user}/ac.socket
%{_unitdir_user}/sockets.target.wants/ac.socket
%{_bindir}/amd

