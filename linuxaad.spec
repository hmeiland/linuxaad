Name:       linuxaad
Version:    0.1
Release:    2
Summary:    Libraries for pam and nss to use Azure Active Directory
License:    MSFT Open Source

URL:        https://github.com/hmeiland/linuxaad
Source0:    v0.1.tar.gz

BuildRequires: gcc
BuildRequires: pam-devel
BuildRequires: libcurl-devel
BuildRequires: jansson-devel


%description
Libraries for pam and nss to use Azure Active Directory for directory and authentication services.

%prep
%setup

%build
cd pam_aad; make; cd ..
cd libnss_aad; make; cd ..

%install
mkdir -p ${RPM_BUILD_ROOT}/usr/lib64
install libnss_aad/.libs/libnss_aad.so.2.0 ${RPM_BUILD_ROOT}/usr/lib64/libnss_aad.so.2.0
mkdir -p ${RPM_BUILD_ROOT}/usr/lib64/security
install pam_aad/.libs/pam_aad.so ${RPM_BUILD_ROOT}/usr/lib64/security/pam_aad.so
mkdir -p ${RPM_BUILD_ROOT}/etc/azuread
install libnss_aad/parameters.json.example ${RPM_BUILD_ROOT}/etc/azuread/parameters.json.example

%files
/usr/lib64/libnss_aad.so.2.0
/usr/lib64/security/pam_aad.so
/etc/azuread/parameters.json.example

%post
sed -i '/^passwd: / s/$/ aad/' /etc/nsswitch.conf
sed -i '/^shadow: / s/$/ aad/' /etc/nsswitch.conf
sed -i '/^group: / s/$/ aad/' /etc/nsswitch.conf
sed -i '/#%PAM-1.0/ s/$/\nauth sufficient pam_aad.so/' /etc/pam.d/sshd
sed -i 's/^PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^ChallengeResponseAuthentication .*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
ln -s /usr/lib64/libnss_aad.so.2.0 /usr/lib64/libnss_aad.so.2
ln -s /usr/lib64/libnss_aad.so.2.0 /usr/lib64/libnss_aad.so

%changelog
