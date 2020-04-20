#!/bin/bash


yum install -y rpm-build gcc libcurl-devel jansson-devel pam-devel
mkdir -p ~/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
wget https://github.com/hmeiland/linuxaad/archive/v0.2.1.tar.gz
cp v0.2.1.tar.gz ~/rpmbuild/SOURCES/

git clone https://github.com/hmeiland/linuxaad.git
rpmbuild -ba linuxaad/rpms/linuxaad.spec

 
