#!/bin/bash

function main {
    #variable assignment
    now="$(date +'%d/%m/%Y %r')"
    #intro
    echo "running main ($now)"
    #manual config edits
    nano /etc/apt/sources.list #check for malicious sources
    nano /etc/resolv.conf #make sure if safe, use 8.8.8.8 for name server
    nano /etc/hosts #make sure is not redirecting
    nano /etc/rc.local #should be empty except for 'exit 0'
    echo  "Setting lockout policy..." 
	sed -i 's/auth\trequisite\t\t\tpam_deny.so\+/auth\trequired\t\t\tpam_deny.so/' /etc/pam.d/common-auth
	sed -i 'auth\trequired\t\t\tpam_tally2.so deny=5 unlock_time=1800 onerr=fail' /etc/pam.d/common-auth
	sed -i 's/sha512\+/sha512 remember=13/' /etc/pam.d/common-password
    echo "Lockout poicy set."
    echo "configuring IP security settings"
    ##Disables IPv6
	sed -i 'net.ipv6.conf.all.disable_ipv6 = 1' /etc/sysctl.conf 
	sed -i 'net.ipv6.conf.default.disable_ipv6 = 1' /etc/sysctl.conf
	sed -i 'net.ipv6.conf.lo.disable_ipv6 = 1' /etc/sysctl.conf 

	##Disables IP Spoofing
	sed -i 'net.ipv4.conf.all.rp_filter=1' /etc/sysctl.conf

	##Disables IP source routing
	sed -i 'net.ipv4.conf.all.accept_source_route=0' /etc/sysctl.conf

	##SYN Flood Protection
	sed -i 'net.ipv4.tcp_max_syn_backlog = 2048' /etc/sysctl.conf
	sed -i 'net.ipv4.tcp_synack_retries = 2' /etc/sysctl.conf
	sed -i 'net.ipv4.tcp_syn_retries = 5' /etc/sysctl.conf
	sed -i 'net.ipv4.tcp_syncookies=1' /etc/sysctl.conf

	##IP redirecting is disallowed
	sed -i 'net.ipv4.ip_foward=0' /etc/sysctl.conf
	sed -i 'net.ipv4.conf.all.send_redirects=0' /etc/sysctl.conf
	sed -i 'net.ipv4.conf.default.send_redirects=0' /etc/sysctl.conf
    echo "configuring login - creating file for ubuntu 12"
    sed -i '[SeatDefault]' /etc/lightdm/lightdm.conf
    sed -i 'allow-guest=false' /etc/lightdm/lightdm.conf
    sed -i 'greeter-hide-users=true' /etc/lightdm/lightdm.conf
    sed -i 'greeter-show-manual-login=true' /etc/lightdm/lightdm.conf 
    echo "configuring login for ubuntu 14"
    sed -i '[SeatDefault]' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
    sed -i 'allow-guest=false' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
    sed -i 'greeter-hide-users=true' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
    sed -i 'greeter-show-manual-login=true' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
    echo "checking if ssh exists"
    dpkg -l | grep openssh-server
    if [$? -eq 0];
    then
    echo "configuring ssh"
    touch /etc/ssh/sshd_config
    sed -i 's/LoginGraceTime .*/LoginGraceTime 60/g' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
    sed -i 's/Protocol .*/Protocol 2/g' /etc/ssh/sshd_config
    sed -i 's/#PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
    sed -i 's/X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config
    
    fi
    
    #set login policy
    echo "setting login policy"
    sed -i.bak -e 's/PASS_MAX_DAYS\t[[:digit:]]\+/PASS_MAX_DAYS\t90/' /etc/login.defs
	sed -i -e 's/PASS_MIN_DAYS\t[[:digit:]]\+/PASS_MIN_DAYS\t10/' /etc/login.defs
	sed -i -e 's/PASS_WARN_AGE\t[[:digit:]]\+/PASS_WARN_AGE\t7/' /etc/login.defs
	sed -i -e 's/difok=3\+/difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
    #disable root account
    passwd -l root
    #secure /etc/shadow
    chmod 640 /etc/shadow
    sed -i '/exec shutdown -r not "Control-Alt-Delete pressed"/#exec shutdown -r not "Control-Alt-Delete pressed"/' /etc/init/control-alt-delete.conf
    echo "purging bad programs"
    dpkg -l | grep john 2> /dev/null
    apt-get --purge remove john 2> /dev/null
    dpkg -l | grep hydra 2> /dev/null
    apt-get --purge remove hydra 2> /dev/null
    dpkg -l | grep nginx 2> /dev/null
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
    echo "updating firefox"
    killall firefox
		wait
	apt-get --purge --reinstall install firefox -y
    apt-get -V -y install hardinfo chkrootkit iptables portsentry lynis ufw gufw sysv-rc-conf nessus clamav
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

