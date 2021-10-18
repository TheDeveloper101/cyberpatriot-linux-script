#!/bin/bash

function main {
    #variable assignment
    now="$(date +'%d/%m/%Y %r')"
    #intro
    echo "running main ($now)"
    echo "run as 'sudo sh linux.sh 2>&1 | tee output.log' to output the console output to a log file."
    #manual config edits
    nano /etc/apt/sources.list #check for malicious sources
    nano /etc/resolv.conf #make sure if safe, use 8.8.8.8 for name server
    nano /etc/hosts #make sure is not redirecting
    nano /etc/rc.local #should be empty except for 'exit 0'
    nano /etc/sysctl.conf #change net.ipv4.tcp_syncookies entry from 0 to 1
    nano /etc/lightdm/lightdm.conf #allow_guest=false, remove autologin
    nano /etc/ssh/sshd_config #Look for PermitRootLogin and set to no
    nano /etc/login.defs
    nano /etc/sysctl.conf
    #disable root account
    passwd -l root
    #secure /etc/shadow
    chmod 640 /etc/shadow
    #search for bad programs and uninstall
    dpkg -l | grep 'john' 2> /dev/null
    apt-get --purge remove john 2> /dev/null
    dpkg -l | grep 'Hydra' 2> /dev/null
    apt-get --purge remove hydra 2> /dev/null
    dpkg -l | grep 'Nginx' 2> /dev/null
    apt-get --purge remove samba 2> /dev/null
    dpkg -l | grep 'Bind9' 2> /dev/null
    apt-get --purge remove bind9 2> /dev/null
    dpkg -l | grep 'tftpd' 2> /dev/null
    apt-get --purge remove tftpd 2> /dev/null
    dpkg -l | grep 'ftp' 2> /dev/null
    apt-get --purge remove ftp 2> /dev/null
    dpkg -l | grep 'x11vnc'2> /dev/null
    apt-get --purge remove x11vnc 2> /dev/null
    dpkg -l | grep 'tightvncserver' 2> /dev/null
    apt-get --purge remove tightvncserver 2> /dev/null
    dpkg -l | grep 'snmp' 2> /dev/null
    apt-get --purge remove snmp 2> /dev/null
    dpkg -l | grep 'sendmail' 2> /dev/null
    apt-get --purge remove nginx 2> /dev/null
    dpkg -l | grep 'Samba' 2> /dev/null
    apt-get --purge remove samba 2> /dev/null
    dpkg -l | grep 'Bind9' 2> /dev/null
    apt-get --purge remove bind9 2> /dev/null
    dpkg -l | grep 'tftpd' 2> /dev/null
    apt-get --purge remove tftpd 2> /dev/null
    dpkg -l | grep 'ftp' 2> /dev/null
    apt-get --purge remove ftp 2> /dev/null
    dpkg -l | grep 'x11vnc'2> /dev/null
    apt-get --purge remove x11vnc 2> /dev/null
    dpkg -l | grep 'tightvncserver' 2> /dev/null
    apt-get --purge remove tightvncserver 2> /dev/null
    dpkg -l | grep 'snmp' 2> /dev/null
    apt-get --purge remove snmp 2> /dev/null
    dpkg -l | grep 'sendmail' 2> /dev/null
    apt-get --purge remove sendmail 2> /dev/null
    dpkg -l | grep 'postfix' 2> /dev/null
    apt-get --purge remove postfix 2> /dev/null
    dpkg -l | grep 'xinetd' 2> /dev/null
    apt-get --purge xinetd 2> /dev/null
    #installs
    apt-get -V -y install firefox hardinfo chkrootkit iptables portsentry lynis ufw gufw sysv-rc-conf nessus clamav
    apt-get -V -y install --reinstall coreutils
    apt-get update
    apt-get upgrade
    apt-get dist-upgrade
    #network security
    iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP         #Block Telnet
    iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
    iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
    iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP  #Block X-Windows
    iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP       #Block X-Windows font server
    iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
    iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
    iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
    iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
    iptables -A INPUT -p all -s localhost  -i eth0 -j DROP            #Deny outside packets from internet which claim to be from your loopback interface.
    ufw enable
    ufw deny 23
    ufw deny 2049
    ufw deny 515
    ufw deny 111
    lsof  -i -n -P
    netstat -tulpn
    #media file deletion
    find / -name '*.mp3' -type f -delete
    find / -name '*.mov' -type f -delete
    find / -name '*.mp4' -type f -delete
    find / -name '*.avi' -type f -delete
    find / -name '*.mpg' -type f -delete
    find / -name '*.mpeg' -type f -delete
    find / -name '*.flac' -type f -delete
    find / -name '*.m4a' -type f -delete
    find / -name '*.flv' -type f -delete
    find / -name '*.ogg' -type f -delete
    find /home -name '*.gif' -type f -delete
    find /home -name '*.png' -type f -delete
    find /home -name '*.jpg' -type f -delete
    find /home -name '*.jpeg' -type f -delete
    #information gathering
    hardinfo -r -f html
    chkrootkit 
    lynis -c 
    freshclam
    clamscan -r /
    echo "remember to do user management, gui related configurations, set automatic updates/security updates, etc."
    echo "thank you for using linux.sh ($now)"
    now="$(date +'%d/%m/%Y %r')" #update date/time
}

if [ "$(id -u)" != "0" ]; then
    echo "linux.sh is not being run as root"
    echo "run as 'sudo sh linux.sh 2>&1 | tee output.log' to output the console output to a log file."
    exit
else
    main
fi

