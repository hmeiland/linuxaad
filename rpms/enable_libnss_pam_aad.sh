#!/bin/bash

sed -i '/^passwd: / s/$/ aad/' /etc/nsswitch.conf
sed -i '/^shadow: / s/$/ aad/' /etc/nsswitch.conf
sed -i '/^group: / s/$/ aad/' /etc/nsswitch.conf
sed -i '/#%PAM-1.0/ s/$/\nauth sufficient pam_aad.so/' /etc/pam.d/sshd
sed -i 's/^PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^ChallengeResponseAuthentication .*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
ln -s /usr/lib64/libnss_aad.so.2.0 /usr/lib64/libnss_aad.so.2
ln -s /usr/lib64/libnss_aad.so.2.0 /usr/lib64/libnss_aad.so
systemctl restart sshd
