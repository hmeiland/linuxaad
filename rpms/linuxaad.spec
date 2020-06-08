Name:       linuxaad
Version:    0.3
Release:    1
Summary:    Libraries for pam and nss to use Azure Active Directory
License:    MSFT Open Source

URL:        https://github.com/hmeiland/linuxaad
Source0:    v0.2.1.tar.gz

BuildRequires: gcc
BuildRequires: pam-devel
BuildRequires: libcurl-devel
BuildRequires: jansson-devel
BuildRequires: checkpolicy
BuildRequires: policycoreutils-python

Requires: policycoreutils


%description
Libraries for pam and nss to use Azure Active Directory for directory and authentication services.

%prep
%setup

%build
cd pam_aad
  make
  checkmodule -M -m -o pam_aad.mod pam_aad.te
  semodule_package -o pam_aad.pp -m pam_aad.mod
  cd ..
cd libnss_aad; make; cd ..

%install
mkdir -p ${RPM_BUILD_ROOT}/usr/lib64
install libnss_aad/.libs/libnss_aad.so.2.0 ${RPM_BUILD_ROOT}/usr/lib64/libnss_aad.so.2.0
mkdir -p ${RPM_BUILD_ROOT}/usr/lib64/security
install pam_aad/.libs/pam_aad.so ${RPM_BUILD_ROOT}/usr/lib64/security/pam_aad.so
mkdir -p ${RPM_BUILD_ROOT}/etc/azuread
install libnss_aad/parameters.json.example ${RPM_BUILD_ROOT}/etc/azuread/parameters.json.example
mkdir -p ${RPM_BUILD_ROOT}/usr/share/selinux/packages
install pam_aad/pam_aad.pp ${RPM_BUILD_ROOT}/usr/share/selinux/packages/pam_aad.pp
install pam_aad/pam_aad.te ${RPM_BUILD_ROOT}/usr/share/selinux/packages/pam_aad.te
mkdir -p ${RPM_BUILD_ROOT}/usr/sbin
install rpms/enable_libnss_pam_aad.sh ${RPM_BUILD_ROOT}/usr/sbin/enable_libnss_pam_aad.sh
chmod 700 ${RPM_BUILD_ROOT}/usr/sbin/enable_libnss_pam_aad.sh

%files
/usr/lib64/libnss_aad.so.2.0
/usr/lib64/security/pam_aad.so
/etc/azuread/parameters.json.example
/usr/share/selinux/packages/pam_aad.pp
/usr/share/selinux/packages/pam_aad.te
/usr/sbin/enable_libnss_pam_aad.sh

%post
ln -s /usr/lib64/libnss_aad.so.2.0 /usr/lib64/libnss_aad.so.2
ln -s /usr/lib64/libnss_aad.so.2.0 /usr/lib64/libnss_aad.so
semodule -i /usr/share/selinux/packages/pam_aad.pp

%changelog
