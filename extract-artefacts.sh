#!/bin/bash
#Linux extract artefact for forensic
# (c) 2019 - 2020, Lionel PRAT <lionel.prat9 (at) gmail.com>
#run script to log output bash -x extract-artefacts.sh 2> extract.log
####List to extract####
#######################
# Memory RAM & Swap: KO
#  - Analyse: volatility
# Uptime : OK
#  - Analyse: identify information in RAM (running)
# Process: OK
#  - Analyse: date of creation, suspect path, from package, suspect right
# Packages: OK 
#  - Analyse: integrity file suspect, CVE on package
# ssh client info: OK
#  - Analyse: date of last modified/creation (backdoor), verify key known
# etc (sudoers, su, services, passwd, users, docker, hosts...): OK
#  - Analyse service: from package, date of creation/modification, suspect right, suspect path
#  - Analyse sudoers: from package, date of creation/modification, suspect right, suspect path, date last modification sudoers file, date last modification group,
#  - Analyse su:  date last modification sudoers file, date last modification group, suspect right
#  - Analyse hosts: date last modification hosts file,
# Docker: OK (DOCKER_DIR/graph/<layer_id>/json + DOCKER_DIR/containers/<container_id>/<container_id>-json.log + DOCKER_DIR/containers/<container_id>/config.json)
# log: OK (/var/log & /run/log/)
# Services: OK
# Network: OK
# Env & clipboard: OK
# Trap: OK
# File System: OK
# Home: OK
#
# Mounted memory: OK
# File rights: OK
# Kernel module: OK
# Crontab: OK
# browser (cache + cookie) OK

#extract from virtual gui (ref: https://stackoverflow.com/questions/22327728/mounting-vmdk-disk-image)
#prerequis: 
# apt install libguestfs-tools
# or
# apt install qemu-utils
#vmdk: 
# guestmount --ro -a xyz.vmdk -m /dev/sda3 /mnt/vmdk
# or 
# modprobe nbd;qemu-nbd -r -c /dev/nbd1 ./linux_box/VM/image.vmdk;mount /dev/nbd1p1 /mnt
#vdi:
# guestmount --ro -a fedora-test.vdi -m /dev/vg_fedoravbox/lv_root /mnt/root
# or
# modprobe nbd;qemu-nbd -c /dev/nbd1 ./linux_box/VM/image.vdi;mount /dev/nbd1p1 /mnt
#ova: 
# tar -xvf image.ova (create vmdk image)

#Attributs d'un fichier:
# - file config ('etc path')
# - service
# - executable file ('x')
# - device file ('b---------')
# - process executé
# - lib dans process
# - package
# - type (mime)
# - extension
# - droits d'accès
# - origine d'execution (service, crontab, manuel, ...)
# - owner & group
# - taille
# - entropy
#

#Plaso default format: log2timeline.py --parsers list
#     linux : apt_history, bash_history, bencode, czip/oxml, dockerjson, dpkg,
#             filestat, gdrive_synclog, olecf, pls_recall, popularity_contest,
#             selinux, sqlite/google_drive, sqlite/skype, sqlite/zeitgeist,
#             syslog, systemd_journal, utmp, vsftpd, webhist, xchatlog,
#             xchatscrollback, zsh_extended_history
#(https://github.com/log2timeline/plaso/tree/master/plaso/parsers & https://github.com/log2timeline/plaso/tree/master/plaso/formatters)
# - apache access
# - apt history (/var/log/apt/history.log)
# - dpkg log (/var/log/dpkg.log)
# - bash history (work if you have set HISTTIMEFORMAT)
# - Syslog (cron, ssh access)
# - systemd log
# - popularity-contest (debian)
# - utmp (/var/log/wtmp)
# - docker configuration and log file (work if you file have in path /containers/id/...)

#Plaso tagging linux: https://github.com/log2timeline/plaso/blob/master/data/tag_linux.txt
# tag file list: '.hushlogin', '.rhost', '.*history*', 'passwd', 'group', 'login.defs', 'services configuration [smtp, dns, syslog, supervision, smb.conf, ssh]', '/etc/pam.d/system-auth & /etc/pam.d/*', '/etc/profile', '/etc/shells', 'ftpusers' , '/etc/security/access.conf', '/etc/hosts.equiv', '/etc/bashrc', '/etc/exports', '/etc/xinetd.d/*', '/etc/issue', '/etc/motd', '/etc/security/time.conf', '/etc/security/opasswd', '/etc/security/access.conf', '/etc/securetty', '/etc/default/*', '/etc/grub.conf', '/etc/at.*', '/etc/sudoers*', '/etc/hosts.*', 'X*.hosts'

#USB trace analyze: usbrip events history -et -c conn vid pid disconn serial -d '1995-09-15' '2018-07-01' --pid 1337 -f /var/log/syslog.1 /var/log/syslog.2.gz
#https://github.com/snovvcrash/usbrip
#USE SIGMA knowledge: https://github.com/Neo23x0/sigma/tree/master/rules/linux

#ATTACH_TOOLS

#CONST CONF
MEMORY=1
MEM_PROC=1
GET_WEBSITE=0
YARA_EXTRACT_FILE=1
YARA_MAXSIZE="10MB"
YARA_PATHSCAN="/"
YARA_RULES_FS="/tmp/toolsEAL/tools/filescan.yar"
YARA_RULES_MEM="/tmp/toolsEAL/tools/procscan.yar"
#extract static linked file - max size file
EXTRACT_MAXSIZE=5

if [ -f "/tmp/toolsEAL/tools/EAL.config" ]; then
. /tmp/toolsEAL/tools/EAL.config
fi
#Function to find date creation from http://moiseevigor.github.io/software/2015/01/30/get-file-creation-time-on-linux-with-ext4/
xstat() {
  for target in "${@}"; do
    inode=$(ls -di "${target}" | cut -d ' ' -f 1)
    fs=$(df "${target}"  | tail -1 | awk '{print $1}')
    crtime=$(debugfs -R 'stat <'"${inode}"'>' "${fs}" 2>/dev/null | 
    grep -oP 'crtime.*--\s*\K.*')
    printf "%s\t%s\n" "${crtime}" "${target}"
  done
}

#Function from https://serverfault.com/questions/173999/dump-a-linux-processs-memory-to-file
procdump() 
( 
    mkdir /tmp/artefacts/procs_mem_dump/
    for i in $(ls /proc/);do 
      if [[ $i =~ [0-9]+ ]]; then
        mkdir /tmp/artefacts/procs_mem_dump/$i
        cp /proc/$i/maps /tmp/artefacts/procs_mem_dump/$i/
        cat /proc/$i/maps | grep "rw-p" | awk '{print $1}' | ( IFS="-"
        while read a b; do
          dd if=/proc/$i/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
             skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) | gzip > /tmp/artefacts/procs_mem_dump/$i/$i_mem_$a.bin.gz
        done )
      fi
    done
)

#use local web serveur to share https://security-tracker.debian.org/tracker/debsecan/release/1/GENERIC (else use base64 and command: debsecan --source=file://localhost/tmp/debsecan/
if [ -f "/tmp/toolsEAL/tools/GENERIC" ]
then
  URL_GENERIC="file://localhost/tmp/toolsEAL/tools/GENERIC"
else
  if [[ -z "${URL_GENERIC}" ]]; then
    URL_GENERIC="https://security-tracker.debian.org/tracker/debsecan/release/1/GENERIC"
  else
    URL_GENERIC="${URL_GENERIC}"
  fi
fi
#Identify OS
#1==linux && 2==Aix
OS=0
if uname -a|grep -i 'linux' ;then OS=1;echo Forensic on Linux OS;fi
if uname -a|grep -i 'aix' ;then OS=2;echo Forensic on AIX OS;fi
if [ $OS == 0 ]; then echo OS not detected!;exit; fi

#create artefact directory
rm -rf /tmp/artefacts
mkdir /tmp/artefacts/ 
if [ $OS == 2 ]; then lsconf | grep Memory ;fi
if [ $OS == 1 ]; then free ;fi
##Extract Memory RAM & swap
#option to bypass extract RAM => snapshot by host (xen, vmware, kvm, ...)
#if [ $OS == 1 ]; then ;fi
#if [ $OS == 2 ]; then ;fi
#use: https://github.com/kd8bny/LiMEaide for linux

#extract memory or memory process
if [ $OS == 1 ] && [ $MEMORY == 1 ] && [ -f "/tmp/toolsEAL/tools/avml-minimal" ]
then
  #use avml
  chmod +x /tmp/toolsEAL/tools/avml-minimal
  /tmp/toolsEAL/tools/avml-minimal --compress /tmp/artefacts/mem.raw.compressed
  if [ $? -eq 0 ]
  then
    MEM_PROC=0
    YARA_RULES_MEM="noexists.yar"
  fi
fi
if [ $MEM_PROC == 1 ]
then
  #https://serverfault.com/questions/173999/dump-a-linux-processs-memory-to-file
  procdump
  YARA_PROC=0
fi

#modified original ent code for print same of script ent.pl
#cross compiled (used:https://github.com/dockcross/dockcross) in static
#ref: http://www.fourmilab.ch/random/
#if [ $OS == 1 ]; then if which base64;then cat /tmp/ent32_b64|base64 -d>/tmp/ent32;chmod +x /tmp/ent32;else if which openssl;then openssl base64 -d < /tmp/ent32_b64 /tmp/ent32;chmod +x /tmp/ent32;fi;fi;fi
#change ignore par \( -fstype nfs -prune \) -o
#ent & md5sum is very slow -- remove 
#if [ $OS == 1 ];then find / -path /tmp/artefacts -prune -o \( -fstype nfs -prune \) -o -exec ls -dils --time-style=long-iso {} + -type f -exec /tmp/ent32 -t {} + -type f -exec file {} + -type f -exec md5sum {} + > /tmp/artefacts/all_files ;fi
TESTSTAT=$(stat -c 'STAT:%i|%b|%A|%h|%U|%G|%s|%t|%T|%w|%x|%y|%z|%n|%N' /)
if [ $OS == 1 ];then 
  if [ -x "$(which stat)" ] && [[ $TESTSTAT == "STAT:"* ]] ; then
    find / -path /tmp/artefacts -prune -o \( -fstype nfs -prune \) -o -exec stat -c 'STAT:%i|%b|%A|%h|%U|%G|%s|%t|%T|%w|%x|%y|%z|%n|%N' {} + -type f -exec file {} + > /tmp/artefacts/all_files 
  else
    find / -path /tmp/artefacts -prune -o \( -fstype nfs -prune \) -o -exec ls -dils --time-style=long-iso {} + -type f -exec file {} + > /tmp/artefacts/all_files 
  fi
fi
#stat -c '%i,%b,%A,%h,%U,%G,%s,%t,%T,%w,%x,%y%z,%n,%N'
# ls -dils --time=ctime & ls -dils --time=atime & ls -dils => pb identify time value according by ctime,atime,mtime
#linux
#find / -path /mnt -prune -o -type f -exec stat --printf="%n: %w|%x|%y|%z\n" {} \; > find_all_stat
#aix
#find / -path /mnt -prune -o -type f -exec istat {} \; > /tmp/artefacts/all_files_type
#besoin pour processus
#not found possibility to cross compile for aix
#if [ $OS == 2 ];then find / -path /tmp/artefacts -prune -o \( -fstype nfs -prune \) -o -ls -type f -exec perl /tmp/ent.pl {} \; -type f -exec file {} \; -type f -exec md5sum {} \; -type f -exec cksum {} \; > /tmp/artefacts/all_files;fi
#ent is very slow -- remove 
#if [ $OS == 2 ];then find / -path /tmp/artefacts -prune -o \( -fstype nfs -prune \) -o -ls -exec perl -e '@d=localtime ((stat(shift))[9]); printf "Date: %02d-%02d-%04d %02d:%02d:%02d\n", $d[3],$d[4]+1,$d[5]+1900,$d[2],$d[1],$d[0]' {} \; -type f -exec perl /tmp/ent.pl {} \; -type f -exec file {} \; -type f -exec md5sum {} \; -type f -exec cksum {} \; > /tmp/artefacts/all_files;fi
if [ $OS == 2 ];then find / -path /tmp/artefacts -prune -o \( -fstype nfs -prune \) -o -type f -exec file {} + > /tmp/artefacts/all_files_file;fi
if [ $OS == 2 ];then find / -path /tmp/artefacts -prune -o \( -fstype nfs -prune \) -o -ls > /tmp/artefacts/all_files;fi
#rm /tmp/ent.pl
#if [ $OS == 1 ];then rm /tmp/ent32 ;fi
#rm /tmp/ent32_b64

##tomcat extract pass
if grep 'tomcat-users.xml\:' /tmp/artefacts/all_files >/dev/null;then grep 'tomcat-users.xml\:' /tmp/artefacts/all_files | awk '{print $1}'|sed 's/://g' | tar -zcvpf /tmp/artefacts/tomcat-passwd.tar.gz --files-from -;fi

##General info
echo -e "#####Artefact for forensic#####\nhost:" > /tmp/artefacts/general
hostname >> /tmp/artefacts/general
##Uptime
echo -e "\nUptime:\n-------" >> /tmp/artefacts/general
uptime >> /tmp/artefacts/general
##Uname
echo -e "\nUname:\n-------" >> /tmp/artefacts/general
uname -a >> /tmp/artefacts/general
##Userlist
echo -e "-------\nusers:\n-------" >> /tmp/artefacts/general
cat /etc/passwd >> /tmp/artefacts/general
echo -e "-------\nDate of /etc/passwd:\n-------" >> /tmp/artefacts/general
istat /etc/passwd|grep -i last >> /tmp/artefacts/general
##
echo -e "-------\nHosts:\n-------" >> /tmp/artefacts/general
cat /etc/hosts >> /tmp/artefacts/general
#ssh key
#echo -e "-------\nssh-add -l:\n-------" >> /tmp/artefacts/general
#for user in $(cat /etc/passwd | cut -f1 -d: );  do echo -e "\nssh-add for user: $user"; sudo -u $user ssh-add -l; done

##HOME
#extract .*history* (identify command à risque ou passwd oublié...)
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/home_history.tar $homeuser/.*history*;done
gzip /tmp/artefacts/home_history.tar
#extract .ssh/known_hosts and authorized_keys files 
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/home_known_hosts.tar $homeuser/.ssh/known_hosts files;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/home_known_hosts.tar $homeuser/.ssh/authorized_keys files;done
gzip /tmp/artefacts/home_known_hosts.tar
echo -e "#####Artefact Home Hidden File#####\n" > /tmp/artefacts/home_hidden
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do ls -laR $homeuser/.[^.]* >> /tmp/artefacts/home_hidden;done
echo -e "#####Artefact Home ssh keys#####\n" > /tmp/artefacts/ssh_keys
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do ls -laR $homeuser/.ssh/ >> /tmp/artefacts/ssh_keys;done
#browser & cache
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/cache_home.tar $homeuser/.cache;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/cache_home.tar $homeuser/.mozilla;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/cache_home.tar $homeuser/.java/deployment/cache/;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/cache_home.tar $homeuser/.dropbox/*.db*;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/cache_home.tar $homeuser/.npm/;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/cache_home.tar $homeuser/.recently-used*;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/cache_home.tar $homeuser/.wget-hsts;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/cache_home.tar $homeuser/.local/share/zeitgeist/activity.sqlite;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/cache_home.tar $homeuser/.local/share/zeitgeist/activity.sqlite-wal;done
gzip /tmp/artefacts/cache_home.tar
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.bashrc;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.bash_profile;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.bash_logout;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.profile;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.cshrc;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.ksh;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.tcsh;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.zlogin;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.zlogout;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.zprofile;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.logout;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.login;done
for homeuser in $(awk -F ':' '{print $(NF-1)}' /etc/passwd);do tar vuf /tmp/artefacts/bash_home.tar $homeuser/.k5login;done

gzip /tmp/artefacts/bash_home.tar

##Extract /etc: sudoers (voir si timestamp_timeout => https://attack.mitre.org/techniques/T1206/), su, conf services, docker, passwd (new account? date d'edition... log?) ...
##Docker
echo -e "#####Artefact docker#####\n" > /tmp/artefacts/dockers
if which docker; then docker images >> /tmp/artefacts/dockers; docker ps -a >> /tmp/artefacts/dockers; for id in $(docker ps -a|awk '{print $1}'|sed '1d');do echo -e "\nDocker ID" $id >> /tmp/artefacts/dockers ; docker inspect $id >> /tmp/artefacts/dockers ;done ;fi
if [ $OS == 1 ]; then find /var/lib/docker/containers -name '*.json' -o -name '*.log' | tar -zcvpf /tmp/artefacts/docker.tar.gz --files-from -;fi
##Extract /etc
if [ $OS == 1 ]; then tar zcpvf /tmp/artefacts/etc.tgz /etc/ ;fi
if [ $OS == 2 ]; then tar cpvf  - /etc/| gzip -c >/tmp/artefacts/etc.tgz;fi
##Extract log /var/log/ & /run/log
if [ $OS == 1 ]; then tar zcpvf /tmp/artefacts/varlog.tgz /var/log/;fi
if [ $OS == 2 ]; then tar cpvf  - /var/log/| gzip -c >/tmp/artefacts/varlog.tgz;fi
if [ $OS == 1 ]; then tar zcpvf /tmp/artefacts/runlog.tgz /run/log/;fi
if [ $OS == 1 ]; then find / -path /run/log -prune -o -path /var/log -prune -o \( -fstype nfs -prune \) -o -name '*.log' -o -name '*.log.*' -o -name 'catalina.out' -o -name |grep -v '^/var/log'|grep -v '^/run/log'|tar -zcpvf /tmp/artefacts/otherlog.tar.gz --files-from -;fi
#su stat user (count, last, first) => plaso
#sudo stat user (count, last, first) => plaso

##network
echo -e "#####Artefact Network#####\n" > /tmp/artefacts/network
echo -e "-------\nnetstat -Aan:\n-------" >> /tmp/artefacts/network
if [ $OS == 1 ]; then netstat -lantp >> /tmp/artefacts/network; fi
if [ $OS == 2 ]; then netstat -Aan >> /tmp/artefacts/network; fi
echo -e "-------\nlsof -i:\n-------" >> /tmp/artefacts/network
lsof -i >> /tmp/artefacts/network
echo -e "-------\nRoute:\n-------" >> /tmp/artefacts/network
if [ $OS == 1 ]; then route -n >> /tmp/artefacts/network ;fi
if [ $OS == 2 ]; then netstat -nr >> /tmp/artefacts/network ;fi
#rpc info
if which rpcinfo;then rpcinfo > /tmp/artefacts/rpcinfo;fi

##PROCESSUS
if [ $OS == 2 ];then ps -aefl > /tmp/artefacts/process_ps;fi
if [ $OS == 1 ];then ps auxf > /tmp/artefacts/process_ps;fi
#sur chaque processus https://attack.mitre.org/techniques/T1055/
if [ $OS == 1 ];then ls -l /proc/*/exe> /tmp/artefacts/process_exe;fi
#if [ $OS == 1 ];then if which dpkg; then for path in $(ls -l /proc/*/exe|awk -F '->' '{print $2}'|sort -u);do echo check $path;dpkg -S $path;done;fi;fi > /tmp/artefacts/process_exe_package_dpkg
#if [ $OS == 1 ];then if which rpm; then for path in $(ls -l /proc/*/exe|awk -F '->' '{print $2}'|sort -u);do echo check $path;dpkg -qf $path;done;fi;fi > /tmp/artefacts/process_exe_package_rpm
if [ $OS == 2 ];then for pid in $(ps -aefl|awk '{print $4}');do procldd $pid;done > /tmp/artefacts/process_ldd;fi
if [ $OS == 1 ];then if which pldd;then for pid in $(ps -aefl|awk '{print $4}');do pldd $pid;done > /tmp/artefacts/process_ldd;fi;fi
#if [ $OS == 1 ];then if which dpkg; then for path in $(cat /tmp/artefacts/process_ldd);do echo check $path;dpkg -S $path ;done;fi;fi  > /tmp/artefacts/process_ldd_package_dpkg
#if [ $OS == 1 ];then if which rpm; then for path in $(cat /tmp/artefacts/process_ldd);do echo check $path;rpm -qf $path ;done;fi;fi  > /tmp/artefacts/process_ldd_package_rpm
ls -la /proc/*/fd > /tmp/artefacts/process_fd
#a comparer avec le fichier find_all_cksum
if [ $OS == 2 ];then cksum /proc/*/object/a.out > /tmp/artefacts/process_cksum;fi
if [ $OS == 2 ];then ls -l /proc/*/object/a.out > /tmp/artefacts/process_aout;fi
#handles
lsof > /tmp/artefacts/process_lsof
#####AIX
#ref: https://stackoverflow.com/questions/606041/how-do-i-get-the-path-of-a-process-in-unix-linux
#function aix get full path pid
getPathByPid()
{
    if [[ -e /proc/$1/object/a.out ]]; then
        inode=`ls -i /proc/$1/object/a.out 2>/dev/null | awk '{print $1}'`
        if [[ $? -eq 0 ]]; then
            strnode=${inode}"$"
            strNum=`ls -li /proc/$1/object/ 2>/dev/null | grep $strnode | awk '{print $NF}' | grep "[0-9]\{1,\}\.[0-9]\{1,\}\."`
            if [[ $? -eq 0 ]]; then
                # jfs2.10.6.5869
                n1=`echo $strNum|awk -F"." '{print $2}'`
                n2=`echo $strNum|awk -F"." '{print $3}'`
                # brw-rw----    1 root     system       10,  6 Aug 23 2013  hd9var
                strexp="^b.*"$n1,"[[:space:]]\{1,\}"$n2"[[:space:]]\{1,\}.*$"   # "^b.*10, \{1,\}5 \{1,\}.*$"
                strdf=`ls -l /dev/ | grep $strexp | awk '{print $NF}'`
                if [[ $? -eq 0 ]]; then
                    strMpath=`df | grep $strdf | awk '{print $NF}'`
                    if [[ $? -eq 0 ]]; then
                        fullpath=`find $strMpath -inum $inode 2>/dev/null`
                        if [[ $? -eq 0 ]]; then
                            echo $1": "$fullpath >> /tmp/artefacts/process_faout
                            return 0
                        fi
                    fi
                fi
            fi
        fi
    fi
    return 1
}
if [ $OS == 2 ];then for p in /proc/[0-9]*;do getPathByPid $(echo $p|awk -F '/' '{print $NF}') ;done ;fi
#####

##modules
#linux
if [ $OS == 1 ]; then awk '{ print $1 }' /proc/modules | xargs modinfo | grep filename | awk '{ print $2 }' | sort > /tmp/artefacts/kernel_modules;fi
#if [ $OS == 1 ];then if which dpkg; then for path in $(cat /tmp/artefacts/kernel_modules);do echo check $path;dpkg -S $path ;done;fi;fi  > /tmp/artefacts/kernel_modules_package_dpkg
#if [ $OS == 1 ];then if which rpm; then for path in $(cat /tmp/artefacts/kernel_modules);do echo check $path;rpm -qf $path ;done;fi;fi  > /tmp/artefacts/kernel_modules_package_rpm
#aix
if [ $OS == 2 ]; then genkex > /tmp/artefacts/kernel_modules;fi
#verifier si rwx non possible pour simpe user
#linux
if [ $OS == 1 ]; then for path in $(cat /tmp/artefacts/kernel_modules);do ls -l $path >> /tmp/artefacts/kernel_modules_rw;done ;fi
#aix
if [ $OS == 2 ]; then for path in $(genkex|awk '{print $NF}');do ls -l $path >> /tmp/artefacts/kernel_modules_rw;done ;fi
#sysctl
if which sysctl;then sysctl -a > /tmp/artefacts/sysctl;fi
#ssdt
if [ -x "$(which stat)" ] && [[ $TESTSTAT == "STAT:"* ]] ; then
  find /sys/firmware/acpi/tables/ -iname 'SSDT*' -exec stat -c 'STAT:%i|%b|%A|%h|%U|%G|%s|%t|%T|%w|%x|%y|%z|%n|%N' {} \; > /tmp/artefacts/ssdt
else
  find /sys/firmware/acpi/tables/ -iname 'SSDT*' -exec ls -dits --full-time --time=ctime {} \; > /tmp/artefacts/ssdt
  find /sys/firmware/acpi/tables/ -iname 'SSDT*' -exec ls -dits --full-time --time=atime {} \; >> /tmp/artefacts/ssdt
  find /sys/firmware/acpi/tables/ -iname 'SSDT*' -exec ls -dits --full-time {} \; >> /tmp/artefacts/ssdt
fi
#/proc conf
mkdir /tmp/artefacts/conf_sys/
if [ -f  /proc/sys/kernel/randomize_va_space ]; then cp /proc/sys/kernel/randomize_va_space /tmp/artefacts/conf_sys/;fi
if [ -f  /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts ]; then cp /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts /tmp/artefacts/conf_sys/;fi
if [ -f  /proc/sys/kernel/bootloader_type ]; then cp /proc/sys/kernel/bootloader_type /tmp/artefacts/conf_sys/;fi
if [ -f  /proc/sys/kernel/bootloader_version ]; then cp /proc/sys/kernel/bootloader_version /tmp/artefacts/conf_sys/;fi
if [ -f  /proc/sys/kernel/kexec_load_disabled ]; then cp /proc/sys/kernel/kexec_load_disabled /tmp/artefacts/conf_sys/;fi
if [ -f  /proc/sys/kernel/modules_disabled ]; then cp /proc/sys/kernel/modules_disabled /tmp/artefacts/conf_sys/;fi
if [ -f  /proc/sys/kernel/tainted ]; then cp /proc/sys/kernel/tainted /tmp/artefacts/conf_sys/;fi
find /proc/sys/net/ipv4/ -name 'ip_forward' -o -name 'mc_forwarding' -o -name 'rp_filter' -o -name 'log_martians' -o -name 'accept_redirects' -o -name 'secure_redirects' -o -name 'send_redirects'|tar -zcpvf /tmp/artefacts/conf_sys/net_ipv4.tar.gz --files-from -
find /proc/sys/net/ -name 'forwarding' -o -name 'accept_source_route'|tar -zcpvf /tmp/artefacts/conf_sys/net_ip.tar.gz --files-from -
if [ -f  /proc/net/arp ]; then cp /proc/net/arp /tmp/artefacts/conf_sys/;fi
if [ -f  /proc/mounts ]; then cp /proc/mounts /tmp/artefacts/conf_sys/;fi
if [ -f  /proc/sys/kernel/dmesg_restrict ]; then cp /proc/sys/kernel/dmesg_restrict /tmp/artefacts/conf_sys/;fi
if [ -f  /proc/sys/kernel/kptr_restrict ]; then cp /proc/sys/kernel/kptr_restrict /tmp/artefacts/conf_sys/;fi
if [ -f  /proc/sys/fs/suid_dumpable ]; then cp /proc/sys/fs/suid_dumpable /tmp/artefacts/conf_sys/;fi
if [ -f  /proc/sys/net/ipv4/tcp_syncookies ]; then cp /proc/sys/net/ipv4/tcp_syncookies /tmp/artefacts/conf_sys/;fi
if [ -f  /sys/kernel/security/lsm ]; then cat /sys/kernel/security/lsm > /tmp/artefacts/security-lsm;fi
##apparmor
if which aa-status;then
  aa-status > /tmp/artefacts/aa-status
fi
##selinux
if which sestatus;then
  sestatus > /tmp/artefacts/sestatus
fi
##tomoyo
if which tomoyo-savepolicy;then
  tomoyo-savepolicy -d > /tmp/artefacts/tomoyo-policy
fi
##Sgid & suid & unknown group or user & system writable
#ignore find
#IGNORE_FIND=""
#TODO: AIX pb to identify all mount remote
#if [ $OS == 2 ];then IGNORE_FIND=$(mount|grep -i 'autofs'|awk '{print "-path "$2" -prune -o"}'|tr '\n' ' ') ;fi
#if [ $OS == 1 ];then IGNORE_FIND=$(mount|grep -i systemd|awk '{print "-path "$3" -prune -o"}'|tr '\n' ' ');fi
#ENTROPY_TEST="perl /tmp/ent.pl"
#if which ent; then ENTROPY_TEST=$(which ent);fi
#sgid
# 1697067    356 -rwxr-sr-x   1 root  
#find / -path /tmp/artefacts -prune -o $IGNORE_FIND -type f -perm -02000 -ls 2>/dev/nul > /tmp/artefacts/files_sgid
#Suid
#1446508     64 -rwsr-xr-x   1 root     root 
#find / -path /tmp/artefacts -prune -o $IGNORE_FIND -type f -perm -04000 -ls 2>/dev/null > /tmp/artefacts/files_suid
#Unknown
#4958651     60 -rwsr-x---   1 root     81 
#4692077      4 drwxr-xr-x   4 192      192
#find / -path /tmp/artefacts -prune -o $IGNORE_FIND \( -nouser -o -nogroup \) -ls 2>/dev/null > /tmp/artefacts/files_owner_unknown
#system writable
#ignore "lrwxrwxrwx" => link
#16      0 -rw-r--rw-   1 root     root #W for all user
#find / -path /tmp/artefacts -prune -o $IGNORE_FIND -perm -2 ! -type l -ls 2>/dev/null|grep -vE "[0-9] (/proc/|/dev/|cgroup)" > /tmp/artefacts/files_writable
#recherche fichier avec espace à la fin - https://attack.mitre.org/techniques/T1151/
#find / -path /tmp/artefacts -prune -o $IGNORE_FIND -type f -name '* ' -ls {} > /tmp/artefacts/files_finish_with_space
#1442249      0 -rw-r--r--   1 root     root            0 déc.  9 14:50 ./test\ 
#identifier les fichiers qui contienne des secrets (clé rsa, shadow , ...) avec un accès en lecture pour tout le monde ou le groupe

##Files (trouver une idée pour identifier de potentiel webshell...)
# !dont find distance shared file (nfs)
#find / -path /tmp/artefacts -prune -o $IGNORE_FIND -ls > /tmp/artefacts/all_files
#find / -path /tmp/artefacts -prune -o $IGNORE_FIND -type f -exec md5sum {} \; > /tmp/artefacts/all_files_md5
#find / -path /tmp/artefacts -prune -o $IGNORE_FIND -type f -exec file {} \; > /tmp/artefacts/all_files_type

#entropy script
#reference: https://stackoverflow.com/questions/51624871/calculating-the-entropy-of-a-32mb-file-in-perl-what-is-the-quickest-method
cat << EOF > /tmp/ent.pl
sub file_entropy {
    my (\$file_name) = @_;

    # Get number of bytes in file
    my \$len = -s \$file_name;
    my (\$entropy, %t) = 0;

    open (my \$file, '<:raw', \$file_name) || die "Cant open \$file_name\n";

    # Read in file 1024 bytes at a time to create frequancy table
    while( read( \$file, my \$buffer, 1024) ) {
        \$t{\$_}++ 
            foreach split '', \$buffer;

        \$buffer = '';
    }

    foreach (values %t) {
        my \$p = \$_/\$len;
        \$entropy -= \$p * log \$p ;
    }       

    return \$entropy / log 2;
}
my \$ent=file_entropy(\$ARGV[0]);
print  "'\$ARGV[0]':'\$ent'\n";
EOF

##package (ref: http://gedsismik.free.fr/darkdoc/article.php?id=64)
#list
if which dpkg; then 
  dpkg -l > /tmp/artefacts/packages-list-deb
  apt-config dump > /tmp/artefacts/apt-config
fi
if which rpm; then 
  rpm -qa > /tmp/artefacts/packages-list-rmp
fi
if [ $OS == 2 ];then if which lslpp; then lslpp -L all ;fi > /tmp/artefacts/packages-list-aix;fi
#integrity
if which dpkg; then dpkg -l |grep -E '^ii'|awk '{print $2}'| while read line ; do dpkg -V $line >> /tmp/artefacts/packages-integrity-deb ; done ;fi
if which rpm; then rpm -qa | while read line ; do rpm -V $line >> /tmp/artefacts/packages-integrity-rpm  ; done ;fi
if [ $OS == 2 ];then if which lslpp; then lslpp -L all|grep -E '^  [0-9A-Za-z]'|awk '{print $1}'|while read line ; do echo "Package Name: $line" >> /tmp/artefacts/packages-integrity-aix;lslpp -v $line  >> /tmp/artefacts/packages-integrity-aix; done ; fi ;fi
#list all files
if which dpkg; then dpkg -l |grep -E '^ii'|awk '{print $2}'| while read line ; do echo "Package Name: $line" >> /tmp/artefacts/packages_deb-list_files; dpkg -L $line >> /tmp/artefacts/packages_deb-list_files; done ;fi
if which rpm; then rpm -qa | while read line ; do echo "Package Name: $line" >> /tmp/artefacts/packages_rpm-list_files; rpm -ql $line >> /tmp/artefacts/packages_rpm-list_files ; done ;fi
if [ $OS == 2 ];then if which lslpp; then lslpp -L all|grep -E '^  [0-9A-Za-z]'|awk '{print $1}'|while read line ; do echo "Package Name: $line" >> /tmp/artefacts/packages_aix-list_files;lslpp -f $line  >> /tmp/artefacts/packages_aix-list_files; done ; fi ;fi
#identify file from package:
#Rpm: rpm -qf path
#dpkg: dpkg -S path
#aix: lslpp -w
#extract proc network whithout package
if [ $OS == 1 ]
then
  for path in $(for pid in $(lsof -niTCP -niUDP | awk '{print $2}'|sort -u|grep -v 'PID');do ls -l /proc/$pid/exe|awk -F ' -> ' '{print $2}';done);do
    KEEPP=1
    if [ -f "/tmp/artefacts/packages_deb-list_files" ] && grep -F "${path}" /tmp/artefacts/packages_deb-list_files > /dev/null
    then
      KEEPP=0
    fi
    if [ -f "/tmp/artefacts/packages_rpm-list_files" ] && grep -F "${path}" /tmp/artefacts/packages_rpm-list_files > /dev/null
    then
      KEEPP=0
    fi
    if [ -f "/tmp/artefacts/packages-integrity-deb" ] && grep -F "${path}" /tmp/artefacts/packages-integrity-deb > /dev/null
    then
      KEEPP=1
    fi
    if [ -f "/tmp/artefacts/packages-integrity-rpm" ] && grep -F "${path}" /tmp/artefacts/packages-integrity-rpm > /dev/null
    then
      KEEPP=1
    fi
    if [ $KEEPP == 1 ]
    then
      size=$(du -m "${path}" | cut -f 1)
      if [ $size -le $EXTRACT_MAXSIZE ]; then
        tar vuf /tmp/artefacts/proc_network_file.tar $path
      fi
      if [ ! -x "$(which md5sum)" ]; then
        md5sum $path >> /tmp/artefacts/proc_network_file_hash
      fi
    fi
  done
  gzip /tmp/artefacts/proc_network_file.tar
fi
##static file extract, extract max 5mo
for i in $(grep -i 'statically linked' /tmp/artefacts/all_files | awk '{print $1}'|sed 's/://g'); do
  KEEPP=1
  if [ -f "/tmp/artefacts/packages_deb-list_files" ] && grep -F "${i}" /tmp/artefacts/packages_deb-list_files > /dev/null
  then
    KEEPP=0
  fi
  if [ -f "/tmp/artefacts/packages_rpm-list_files" ] && grep -F "${i}" /tmp/artefacts/packages_rpm-list_files > /dev/null
  then
    KEEPP=0
  fi
  if [ -f "/tmp/artefacts/packages-integrity-deb" ] && grep -F "${i}" /tmp/artefacts/packages-integrity-deb > /dev/null
  then
    KEEPP=1
  fi
  if [ -f "/tmp/artefacts/packages-integrity-rpm" ] && grep -F "${i}" /tmp/artefacts/packages-integrity-rpm > /dev/null
  then
    KEEPP=1
  fi
  if [ $KEEPP == 1 ]
  then
    size=$(du -m "${i}" | cut -f 1)
    if [ $size -le $EXTRACT_MAXSIZE ]; then
      tar vuf /tmp/artefacts/static_file.tar $i
    fi
    if [ ! -x "$(which md5sum)" ]; then
      md5sum $i >> /tmp/artefacts/static_file_hash
    fi
  fi
done
gzip /tmp/artefacts/static_file.tar

#extract binary integrity package broken
if [ -f "/tmp/artefacts/packages-integrity-deb" ]
then
  for path in $(for i in $(awk '{print $NF}' /tmp/artefacts/packages-integrity-deb);do file $i|grep 'ELF ';done); do
    size=$(du -m "${path}" | cut -f 1)
    if [ $size -le $EXTRACT_MAXSIZE ]; then
      tar vuf /tmp/artefacts/bin_package_suspect.tar $path
    fi
    if [ ! -x "$(which md5sum)" ]; then
      md5sum $path >> /tmp/artefacts/bin_package_suspect_hash
    fi
  done
fi
if [ -f "/tmp/artefacts/packages-integrity-rpm" ]
then
  for path in $(for i in $(awk '{print $NF}' /tmp/artefacts/packages-integrity-rpm);do file $i|grep 'ELF ';done); do
    size=$(du -m "${path}" | cut -f 1)
    if [ $size -le $EXTRACT_MAXSIZE ]; then
      tar vuf /tmp/artefacts/bin_package_suspect.tar $path
    fi
    if [ ! -x "$(which md5sum)" ]; then
      md5sum $path >> /tmp/artefacts/bin_package_suspect_hash
    fi
  done
fi
gzip /tmp/artefacts/bin_package_suspect.tar

##Extract systemd, rc.local, init.d
#list service & verify path of execute (date & path standard)
echo -e "#####Artefact Services#####\n" > /tmp/artefacts/services
if [ $OS == 2 ]; then ls -l /etc/rc.d/init.d/* >> /tmp/artefacts/services_init;fi
#extract all path if exist and check package
if [ $OS == 2 ]; then lssrc -a >> /tmp/artefacts/services;fi
if [ $OS == 2 ]; then ls -l /etc/inittab >> /tmp/artefacts/services_inittab ; cat /etc/inittab >> /tmp/artefacts/services_inittab;fi
if [ $OS == 1 ]; then ls -laR /etc/init.d/ >> /tmp/artefacts/services_init;fi
#if [ $OS == 1 ];then if which dpkg; then for path in $(ls -l /etc/init.d/|awk '{print $NF}');do dpkg -S $path;done;fi;fi > /tmp/artefacts/services_init-package_deb
#if [ $OS == 1 ];then if which rpm; then for path in $(ls -l /etc/init.d/|awk '{print $NF}');do rpm -qf $path;done;fi;fi > /tmp/artefacts/services_init-package_rpm
if [ $OS == 1 ]; then ls -laR /etc/systemd/ >> /tmp/artefacts/services_systemd;fi
if [ $OS == 1 ]; then systemctl list-units --type=service > /tmp/artefacts/services_systemd_list;fi
if [ $OS == 1 ]; then ls -laR /run/systemd >> /tmp/artefacts/services_systemd_runtime;fi
#check contains variable: ExecStart, ExecStop, ExecReload (path exist and from package)
for path in $(grep -iER 'ExecStart=|ExecReload=|ExecStop=' /etc/systemd |grep -vE '^#'|awk -F '=' '{print $2}'|awk '{print $1}');do echo check $path;done >/tmp/artefacts/service-systemd
if [ $OS == 1 ]; then ls -la /etc/rc.local >> /tmp/artefacts/services_rclocal;fi
grep -iER '(^|\s+)DAEMON\=|(^|\s+)NAME\=|(^|\s+)COMMAND\=|(^|\S+)[A-Z][A-Z0-9]*_BIN\=' /etc/init.d/ > /tmp/artefacts/services-initd_exe

#identify promiscus mode sur une interface => https://attack.mitre.org/techniques/T1040/
echo -e "-------\nInterface in promiscous mode:\n-------" >> /tmp/artefacts/network
ifconfig -a|grep -i promisc >> /tmp/artefacts/network

##trap list
echo -e "#####Artefact Trap#####\n" > /tmp/artefacts/trap
trap -p >> /tmp/artefacts/trap

##env pour chaque user (LD_PRELOAD, LD_LIBRARY_PATH => https://attack.mitre.org/techniques/T1055/) + (HISTCONTROL content  => https://attack.mitre.org/techniques/T1148/)
echo -e "#####Artefact Env#####\n" > /tmp/artefacts/env
for user in $(cat /etc/passwd | cut -f1 -d: ); do echo Env for user: $user >> /tmp/artefacts/env; su - $user -c env >> /tmp/artefacts/env; done

##clipboard
echo -e "#####Artefact Clipboard#####\n" > /tmp/artefacts/clipboard
if which xsel; then for user in $(cat /etc/passwd | cut -f1 -d: ); do echo clipboard for user: $user >> /tmp/artefacts/clipboard; su - $user -c xsel >> /tmp/artefacts/clipboard; done ;fi


##RAT package or process >> plaso
##browserextension >> plaso

#Memoire & Mount
df > /tmp/artefacts/disk_df
mount > /tmp/artefacts/disk_mount
for path in $(mount|grep -i tmpfs|grep -v ',noexec,'|awk '{out=""; for(i=0;i<=NF;i++){out=out"\n"$i}; print out}'|grep '\/'|grep -v 'tmpfs'|grep -vE '/dev$'); do 
  if [ -x "$(which stat)" ] && [[ $TESTSTAT == "STAT:"* ]] ; then
    find $path -type f -exec stat -c 'STAT:%i|%b|%A|%h|%U|%G|%s|%t|%T|%w|%x|%y|%z|%n|%N' {} \; > /tmp/artefacts/files_in_tmpfs
  else
    ls -laR --full-time --time=ctime $path > /tmp/artefacts/files_in_tmpfs
    ls -laR --full-time --time=atime $path >> /tmp/artefacts/files_in_tmpfs
    ls -laR --full-time $path >> /tmp/artefacts/files_in_tmpfs
  fi
done
if [ -x "$(which stat)" ] && [[ $TESTSTAT == "STAT:"* ]] ; then
    find /dev -type f -exec stat -c 'STAT:%i|%b|%A|%h|%U|%G|%s|%t|%T|%w|%x|%y|%z|%n|%N' {} \; > /tmp/artefacts/files_in_dev
    if which md5sum;then
      find /dev -type f -exec md5sum {} \; >> /tmp/artefacts/files_in_dev
    fi
else
    find /dev -type f -exec ls -dits --full-time --time=ctime {} \; >> /tmp/artefacts/files_in_dev
    find /dev -type f -exec ls -dits --full-time --time=atime {} \; >> /tmp/artefacts/files_in_dev
    find /dev -type f -exec ls -dits --full-time {} \; >> /tmp/artefacts/files_in_dev
    if which md5sum;then
      find /dev -type f -exec md5sum {} \; >> /tmp/artefacts/files_in_dev
    fi
fi
##CRONTAB
#Linux
if [ $OS == 1 ]; then for user in $(cat /etc/passwd | cut -f1 -d: ); do echo Crontab user: $user; crontab -l -u $user|grep -vE '^#'; done > /tmp/artefacts/crontab ;fi
if [ $OS == 1 ]; then for path in $(for user in $(cat /etc/passwd | cut -f1 -d: ); do if crontab -l -u $user >/dev/null 2>1;then crontab -l -u $user|grep -E '^[0-9\*]'|sed 's/>.*//g'|awk '{out=""; for(i=6;i<=NF;i++){out=out"\n"$i}; print out}'|grep '^/';fi; done);do if [[ -f "$path" ]]; then ls -la $path >> /tmp/artefacts/crontab_rw;fi;done;fi
#AIX
if [ $OS == 2 ]; then for user in $(cat /etc/passwd | cut -f1 -d: );  do echo Crontab user: $user; crontab -l $user|grep -vE '^#'; done > /tmp/artefacts/crontab ;fi
if [ $OS == 2 ]; then for path in $(for user in $(cat /etc/passwd | cut -f1 -d: ); do if crontab -l $user >/dev/null 2>1;then crontab -l $user|grep -E '^[0-9\*]'|sed 's/>.*//g'|awk '{out=""; for(i=6;i<=NF;i++){out=out"\n"$i}; print out}'|grep '^/';fi; done);do if [[ -f "$path" ]]; then ls -la $path >> /tmp/artefacts/crontab_rw ;fi;done;fi
##SUDOERS
if [ $OS == 1 ]; then for user in $(cat /etc/passwd | cut -f1 -d: ); do echo Sudo user: $user; sudo -l -U $user|grep -vE '^#'; done > /tmp/artefacts/sudoers ;fi
if [ $OS == 2 ]; then for user in $(cat /etc/passwd | cut -f1 -d: ); do echo Sudo user: $user; sudo -l -u $user|grep -vE '^#'; done > /tmp/artefacts/sudoers ;fi
#keep spool cron
if [ $OS == 1 ]; then tar zcvpf /tmp/artefacts/spool_cron.tgz /var/spool/cron;fi
if [ $OS == 2 ]; then tar cvpf - /var/spool/cron|gzip -c >/tmp/artefacts/spool_cron.tgz;fi

##LAST command
if which last;then last > /tmp/artefacts/last_cmd;fi

##process/services bonus
#debian popularity-contest & debsecan
#send debsecan and source (https://security-tracker.debian.org/tracker/debsecan/release/1/GENERIC)
mkdir /tmp/debsecan

#debsecan VERSION = "0.4" -- openssl base64 < debsecan > debsecan_b64
cat << EOF > /tmp/debsecan/debsecan_b64
IyEvdXNyL2Jpbi9weXRob24zCiMgZGVic2VjYW4gLSBEZWJpYW4gU2VjdXJpdHkg
QW5hbHl6ZXIKIyBDb3B5cmlnaHQgKEMpIDIwMDUtMjAxOSBGbG9yaWFuIFdlaW1l
ciBhbmQgY29udHJpYnV0b3JzCiMgQ29weXJpZ2h0IChDKSAyMDE1IE1pY2hhZWwg
R2lsYmVydCA8bWdpbGJlcnRAZGViaWFuLm9yZz4KIwojIFRoaXMgcHJvZ3JhbSBp
cyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Ig
bW9kaWZ5CiMgaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQ
dWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkKIyB0aGUgRnJlZSBTb2Z0d2Fy
ZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBv
cgojIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uCiMKIyBUaGlz
IHByb2dyYW0gaXMgZGlzdHJpYnV0ZWQgaW4gdGhlIGhvcGUgdGhhdCBpdCB3aWxs
IGJlIHVzZWZ1bCwKIyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQg
ZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZgojIE1FUkNIQU5UQUJJTElUWSBv
ciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUKIyBH
TlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLgojCiMg
WW91IHNob3VsZCBoYXZlIHJlY2VpdmVkIGEgY29weSBvZiB0aGUgR05VIEdlbmVy
YWwgUHVibGljIExpY2Vuc2UKIyBhbG9uZyB3aXRoIHRoaXMgcHJvZ3JhbTsgaWYg
bm90LCB3cml0ZSB0byB0aGUgRnJlZSBTb2Z0d2FyZQojIEZvdW5kYXRpb24sIElu
Yy4sIDUxIEZyYW5rbGluIFN0LCBGaWZ0aCBGbG9vciwgQm9zdG9uLCBNQSAgMDIx
MTAtMTMwMSBVU0EKClZFUlNJT04gPSAiMC40IgoKaW1wb3J0IGNvbGxlY3Rpb25z
CmltcG9ydCBjb3B5CmZyb20gaW8gaW1wb3J0IFN0cmluZ0lPCmZyb20gb3B0cGFy
c2UgaW1wb3J0IE9wdGlvblBhcnNlcgppbXBvcnQgb3MKaW1wb3J0IG9zLnBhdGgK
aW1wb3J0IHJlCmltcG9ydCBzb2NrZXQKaW1wb3J0IHN5cwppbXBvcnQgdGltZQpp
bXBvcnQgdHlwZXMKaW1wb3J0IHVybGxpYi5yZXF1ZXN0CmltcG9ydCB6bGliCmlt
cG9ydCBhcHRfcGtnCgoKYXB0X3BrZy5pbml0KCkKdHJ5OgogICAgdmVyc2lvbl9j
b21wYXJlID0gYXB0X3BrZy52ZXJzaW9uX2NvbXBhcmUKZXhjZXB0IEF0dHJpYnV0
ZUVycm9yOgogICAgdmVyc2lvbl9jb21wYXJlID0gYXB0X3BrZy5WZXJzaW9uQ29t
cGFyZQoKIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwojIEZyb20gZGViaWFuX3N1cHBv
cnQgaW4gdGhlIHNlY3VyZS10ZXN0aW5nIHJlcG9zaXRvcnkuICBOZWVkcyB0byBi
ZQojIGtlcHQgaW4gc3luYyBtYW51YWxseS4gIChXZSBkdXBsaWNhdGUgaGVyZSB0
byBhdm9pZCBhIGxpYnJhcnkKIyBkZXBlbmRlbmN5LCBhbmQgbWFrZSBpdCBlYXN5
IHRvIHJ1biB0aGUgc2NyaXB0IGV2ZW4gd2hlbiBpdCBpcyBub3QKIyBpbnN0YWxs
ZWQgb24gdGhlIHN5c3RlbS4pCgpjbGFzcyBQYXJzZUVycm9yKEV4Y2VwdGlvbik6
CiAgICAiIiJBbiBleGNlcHRpb24gd2hpY2ggaXMgdXNlZCB0byBzaWduYWwgYSBw
YXJzZSBmYWlsdXJlLgoKICAgIEF0dHJpYnV0ZXM6CgogICAgZmlsZW5hbWUgLSBu
YW1lIG9mIHRoZSBmaWxlCiAgICBsaW5lbm8gLSBsaW5lIG51bWJlciBpbiB0aGUg
ZmlsZQogICAgbXNnIC0gZXJyb3IgbWVzc2FnZQoKICAgICIiIgoKICAgIGRlZiBf
X2luaXRfXyhzZWxmLCBmaWxlbmFtZSwgbGluZW5vLCBtc2cpOgogICAgICAgIGFz
c2VydCB0eXBlKGxpbmVubykgPT0gaW50CiAgICAgICAgc2VsZi5maWxlbmFtZSA9
IGZpbGVuYW1lCiAgICAgICAgc2VsZi5saW5lbm8gPSBsaW5lbm8KICAgICAgICBz
ZWxmLm1zZyA9IG1zZwoKICAgIGRlZiBfX3N0cl9fKHNlbGYpOgogICAgICAgIHJl
dHVybiBzZWxmLm1zZwoKICAgIGRlZiBfX3JlcHJfXyhzZWxmKToKICAgICAgICBy
ZXR1cm4gIlBhcnNlRXJyb3IoJXMsICVkLCAlcykiICUgKHJlcHIoc2VsZi5maWxl
bmFtZSksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICBzZWxmLmxpbmVubywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgIHJlcHIoc2VsZi5tc2cpKQoKICAgIGRlZiBwcmludE91dChzZWxm
LCBmaWxlKToKICAgICAgICAiIiJXcml0ZXMgYSBtYWNoaW5lLXBhcnNhYmxlIGVy
cm9yIG1lc3NhZ2UgdG8gZmlsZS4iIiIKICAgICAgICBmaWxlLndyaXRlKCIlczol
ZDogJXNcbiIgJSAoc2VsZi5maWxlbmFtZSwgc2VsZi5saW5lbm8sIHNlbGYubXNn
KSkKICAgICAgICBmaWxlLmZsdXNoKCkKCmNsYXNzIFZlcnNpb246CiAgICAiIiJW
ZXJzaW9uIGNsYXNzIHdoaWNoIHVzZXMgdGhlIG9yaWdpbmFsIEFQVCBjb21wYXJp
c29uIGFsZ29yaXRobS4iIiIKICAgIGRlZiBfX2luaXRfXyhzZWxmLCB2ZXJzaW9u
KToKICAgICAgICAiIiJDcmVhdGVzIGEgbmV3IFZlcnNpb24gb2JqZWN0LiIiIgog
ICAgICAgIGFzc2VydCB0eXBlKHZlcnNpb24pID09IHN0ciwgcmVwcih2ZXJzaW9u
KQogICAgICAgIGFzc2VydCB2ZXJzaW9uICE9ICIiCiAgICAgICAgc2VsZi5fX2Fz
U3RyaW5nID0gdmVyc2lvbgoKICAgIGRlZiBfX3N0cl9fKHNlbGYpOgogICAgICAg
IHJldHVybiBzZWxmLl9fYXNTdHJpbmcKCiAgICBkZWYgX19yZXByX18oc2VsZik6
CiAgICAgICAgcmV0dXJuICdWZXJzaW9uKCVzKScgJSByZXByKHNlbGYuX19hc1N0
cmluZykKCiAgICBkZWYgX19sdF9fKHNlbGYsIG90aGVyKToKICAgICAgICByZXR1
cm4gdmVyc2lvbl9jb21wYXJlKHNlbGYuX19hc1N0cmluZywgb3RoZXIuX19hc1N0
cmluZykgPCAwCgogICAgZGVmIF9fZXFfXyhzZWxmLCBvdGhlcik6CiAgICAgICAg
cmV0dXJuIHZlcnNpb25fY29tcGFyZShzZWxmLl9fYXNTdHJpbmcsIG90aGVyLl9f
YXNTdHJpbmcpID09IDAKCiAgICBkZWYgX19ndF9fKHNlbGYsIG90aGVyKToKICAg
ICAgICByYWlzZSBOb3RJbXBsZW1lbnRlZEVycm9yKCkKCiAgICBkZWYgX19sZV9f
KHNlbGYsIG90aGVyKToKICAgICAgICByYWlzZSBOb3RJbXBsZW1lbnRlZEVycm9y
KCkKCiAgICBkZWYgX19nZV9fKHNlbGYsIG90aGVyKToKICAgICAgICByYWlzZSBO
b3RJbXBsZW1lbnRlZEVycm9yKCkKCiAgICBkZWYgX19uZV9fKHNlbGYsIG90aGVy
KToKICAgICAgICByYWlzZSBOb3RJbXBsZW1lbnRlZEVycm9yKCkKCiAgICBkZWYg
Y29tcGFyZShzZWxmLCBvdGhlcik6CiAgICAgICAgcmV0dXJuIHZlcnNpb25fY29t
cGFyZShzZWxmLl9fYXNTdHJpbmcsIG90aGVyLl9fYXNTdHJpbmcpCgpjbGFzcyBQ
YWNrYWdlRmlsZToKICAgICIiIkEgRGViaWFuIHBhY2thZ2UgZmlsZS4KCiAgICBP
YmplY3RzIG9mIHRoaXMgY2xhc3MgY2FuIGJlIHVzZWQgdG8gcmVhZCBEZWJpYW4n
cyBTb3VyY2UgYW5kCiAgICBQYWNrYWdlcyBmaWxlcy4iIiIKCiAgICByZV9maWVs
ZCA9IHJlLmNvbXBpbGUocideKFtBLVphLXpdW0EtWmEtejAtOS1dKyk6KD86XHMr
KC4qPykpP1xzKiQnKQoKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBuYW1lLCBmaWxl
T2JqPU5vbmUpOgogICAgICAgICIiIkNyZWF0ZXMgYSBuZXcgcGFja2FnZSBmaWxl
IG9iamVjdC4KCiAgICAgICAgbmFtZSAtIHRoZSBuYW1lIG9mIHRoZSBmaWxlIHRo
ZSBkYXRhIGNvbWVzIGZyb20KICAgICAgICBmaWxlT2JqIC0gYW4gYWx0ZXJuYXRl
IGRhdGEgc291cmNlOyB0aGUgZGVmYXVsdCBpcyB0byBvcGVuIHRoZQogICAgICAg
ICAgICAgICAgICBmaWxlIHdpdGggdGhlIGluZGljYXRlZCBuYW1lLgogICAgICAg
ICIiIgogICAgICAgIGlmIGZpbGVPYmogaXMgTm9uZToKICAgICAgICAgICAgZmls
ZU9iaiA9IHNhZmVfb3BlbihuYW1lKQogICAgICAgIHNlbGYubmFtZSA9IG5hbWUK
ICAgICAgICBzZWxmLmZpbGUgPSBmaWxlT2JqCiAgICAgICAgc2VsZi5saW5lbm8g
PSAwCgogICAgZGVmIF9faXRlcl9fKHNlbGYpOgogICAgICAgIGxpbmUgPSBzZWxm
LmZpbGUucmVhZGxpbmUoKQogICAgICAgIHNlbGYubGluZW5vICs9IDEKICAgICAg
ICBwa2cgPSBbXQogICAgICAgIHdoaWxlIGxpbmU6CiAgICAgICAgICAgIGlmIGxp
bmUgPT0gJ1xuJzoKICAgICAgICAgICAgICAgIGlmIGxlbihwa2cpID09IDA6CiAg
ICAgICAgICAgICAgICAgICAgc2VsZi5yYWlzZVN5bnRheEVycm9yKCdleHBlY3Rl
ZCBwYWNrYWdlIHJlY29yZCcpCiAgICAgICAgICAgICAgICB5aWVsZCBwa2cKICAg
ICAgICAgICAgICAgIHBrZyA9IFtdCiAgICAgICAgICAgICAgICBsaW5lID0gc2Vs
Zi5maWxlLnJlYWRsaW5lKCkKICAgICAgICAgICAgICAgIHNlbGYubGluZW5vICs9
IDEKICAgICAgICAgICAgICAgIGNvbnRpbnVlCgogICAgICAgICAgICBtYXRjaCA9
IHNlbGYucmVfZmllbGQubWF0Y2gobGluZSkKICAgICAgICAgICAgaWYgbm90IG1h
dGNoOgogICAgICAgICAgICAgICAgc2VsZi5yYWlzZVN5bnRheEVycm9yKCJleHBl
Y3RlZCBwYWNrYWdlIGZpZWxkLCBnb3QgIiArIHJlcHIobGluZSkpCiAgICAgICAg
ICAgIChuYW1lLCBjb250ZW50cykgPSBtYXRjaC5ncm91cHMoKQogICAgICAgICAg
ICBjb250ZW50cyA9IGNvbnRlbnRzIG9yICcnCgogICAgICAgICAgICB3aGlsZSBU
cnVlOgogICAgICAgICAgICAgICAgbGluZSA9IHNlbGYuZmlsZS5yZWFkbGluZSgp
CiAgICAgICAgICAgICAgICBzZWxmLmxpbmVubyArPSAxCiAgICAgICAgICAgICAg
ICBpZiBsaW5lIGFuZCBsaW5lWzBdIGluICIgXHQiOgogICAgICAgICAgICAgICAg
ICAgIG5jb250ZW50cyA9IGxpbmVbMTpdCiAgICAgICAgICAgICAgICAgICAgaWYg
bmNvbnRlbnRzOgogICAgICAgICAgICAgICAgICAgICAgICBpZiBuY29udGVudHNb
LTFdID09ICdcbic6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBuY29udGVu
dHMgPSBuY29udGVudHNbOi0xXQogICAgICAgICAgICAgICAgICAgIGVsc2U6CiAg
ICAgICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICAgICAg
Y29udGVudHMgPSAiJXNcbiVzIiAlIChjb250ZW50cywgbmNvbnRlbnRzKQogICAg
ICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICBicmVhawogICAg
ICAgICAgICBwa2cuYXBwZW5kKChuYW1lLCBjb250ZW50cykpCiAgICAgICAgaWYg
cGtnOgogICAgICAgICAgICB5aWVsZCBwa2cKCiAgICBkZWYgcmFpc2VTeW50YXhF
cnJvcihzZWxmLCBtc2csIGxpbmVubz1Ob25lKToKICAgICAgICBpZiBsaW5lbm8g
aXMgTm9uZToKICAgICAgICAgICAgbGluZW5vID0gc2VsZi5saW5lbm8KICAgICAg
ICByYWlzZSBQYXJzZUVycm9yKHNlbGYubmFtZSwgbGluZW5vLCBtc2cpCgojIEVu
ZCBvZiBjb2RlIGZyb20gZGViaWFuX3N1cHBvcnQKIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj
IyMjIwoKIyBHZW5lcmFsIHN1cHBvcnQgcm91dGluZXMKCmRlZiBzYWZlX29wZW4o
bmFtZSwgbW9kZT0iciIpOgogICAgdHJ5OgogICAgICAgIHJldHVybiBvcGVuKG5h
bWUsIG1vZGUpCiAgICBleGNlcHQgSU9FcnJvciBhcyBlOgogICAgICAgIHN5cy5z
dGRvdXQud3JpdGUoImVycm9yOiBjb3VsZCBub3Qgb3BlbiAlczogJXNcbiIgJSAo
cmVwcihuYW1lKSwgZS5zdHJlcnJvcikpCiAgICAgICAgc3lzLmV4aXQoMikKCiMg
Q29uZmlndXJhdGlvbiBmaWxlIHBhcnNlcgoKY2xhc3MgQ29uZmlnUGFyc2VyOgog
ICAgZGVmIF9faW5pdF9fKHNlbGYsIG5hbWUsIGZpbGU9Tm9uZSk6CiAgICAgICAg
c2VsZi5uYW1lID0gbmFtZQogICAgICAgIGlmIGZpbGUgaXMgTm9uZToKICAgICAg
ICAgICAgaWYgb3MucGF0aC5leGlzdHMobmFtZSk6CiAgICAgICAgICAgICAgICBz
ZWxmLmZpbGUgPSBzYWZlX29wZW4obmFtZSkKICAgICAgICAgICAgZWxzZToKICAg
ICAgICAgICAgICAgIHNlbGYuZmlsZSA9IE5vbmUKICAgICAgICBlbHNlOgogICAg
ICAgICAgICBzZWxmLmZpbGUgPSBmaWxlCgogICAgZGVmIG9uQ29tbWVudChzZWxm
LCBsaW5lLCBudW1iZXIpOgogICAgICAgIHBhc3MKCiAgICBkZWYgb25LZXkoc2Vs
ZiwgbGluZSwgbnVtYmVyLCBrZXksIHZhbHVlLCB0cmFpbGVyKToKICAgICAgICBw
YXNzCgogICAgZGVmIG9uRXJyb3Ioc2VsZiwgbGluZSwgbnVtYmVyKToKICAgICAg
ICBzeXMuc3RkZXJyLndyaXRlKCIlczolZDogaW52YWxpZCBjb25maWd1cmF0aW9u
IGZpbGUgc3ludGF4XG4iCiAgICAgICAgICAgICAgICAgICAgICAgICAlIChzZWxm
Lm5hbWUsIG51bWJlcikpCiAgICAgICAgc3lzLmV4aXQoMikKCiAgICBkZWYgcGFy
c2Uoc2VsZiwgcmVfY29tbWVudD1yZS5jb21waWxlKHInXlxzKig/OiMuKik/JCcp
LAogICAgICAgICAgICAgIHJlX2tleT1yZS5jb21waWxlKHInXlxzKihbQS1aX10r
KT0oLio/KVxzKiQnKSwKICAgICAgICAgICAgICByZV9xdW90ZT1yZS5jb21waWxl
KHInXiIoLiopIlxzKiQnKSk6CiAgICAgICAgaWYgc2VsZi5maWxlIGlzIE5vbmU6
CiAgICAgICAgICAgIHJldHVybgogICAgICAgIGxpbmVubyA9IDAKICAgICAgICBm
b3IgbGluZSBpbiBzZWxmLmZpbGU6CiAgICAgICAgICAgIGxpbmVubyArPSAxCiAg
ICAgICAgICAgIG1hdGNoID0gcmVfY29tbWVudC5tYXRjaChsaW5lKQogICAgICAg
ICAgICBpZiBtYXRjaCBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAgIHNlbGYu
b25Db21tZW50KGxpbmUsIGxpbmVubykKICAgICAgICAgICAgICAgIGNvbnRpbnVl
CgogICAgICAgICAgICBtYXRjaCA9IHJlX2tleS5tYXRjaChsaW5lKQogICAgICAg
ICAgICBpZiBtYXRjaCBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAgIChrLCB2
KSA9IG1hdGNoLmdyb3VwcygpCiAgICAgICAgICAgICAgICBtYXRjaCA9IHJlX3F1
b3RlLm1hdGNoKHYpCiAgICAgICAgICAgICAgICBpZiBtYXRjaCBpcyBub3QgTm9u
ZToKICAgICAgICAgICAgICAgICAgICAjIFRoaXMgaXMgbm90IHBlcmZlY3QsIGJ1
dCBwcm9wZXIgcGFyc2luZyBpcwogICAgICAgICAgICAgICAgICAgICMgcHJvYmFi
bHkgbm90IHdvcnRoIHRoZSBlZmZvcnQuCiAgICAgICAgICAgICAgICAgICAgKHYs
KSA9IG1hdGNoLmdyb3VwcygpCiAgICAgICAgICAgICAgICBzZWxmLm9uS2V5KGxp
bmUsIGxpbmVubywgaywgdiwgJ1xuJykKICAgICAgICAgICAgICAgIGNvbnRpbnVl
CgogICAgICAgICAgICBzZWxmLm9uRXJyb3IobGluZSwgbGluZW5vKQoKZGVmIHJl
YWRfY29uZmlnKG5hbWUsIGZpbGU9Tm9uZSk6CiAgICAiIiJSZWFkIHRoZSBjb25m
aWd1cmF0aW9uIGZpbGUgTkFNRSBpbnRvIGEgZGljdGlvbmFyeSBhbmQgcmV0dXJu
IGl0LiIiIgogICAgY29uZmlnID0ge30KICAgIGNsYXNzIFBhcnNlcihDb25maWdQ
YXJzZXIpOgogICAgICAgIGRlZiBvbktleShzZWxmLCBsaW5lLCBudW1iZXIsIGtl
eSwgdmFsdWUsIHRyYWlsZXIpOgogICAgICAgICAgICBjb25maWdba2V5XSA9IHZh
bHVlCiAgICBQYXJzZXIobmFtZSwgZmlsZSkucGFyc2UoKQogICAgcmV0dXJuIGNv
bmZpZwoKZGVmIHVwZGF0ZV9jb25maWcobmFtZSk6CiAgICAiIiJVcGRhdGUgdGhl
IGNvbmZpZ3VyYXRpb24gZmlsZSBOQU1FIHdpdGggZGF0YSBmcm9tIHN0YW5kYXJk
IGlucHV0LiIiIgogICAgbmV3X2NvbmZpZyA9IHJlYWRfY29uZmlnKCc8c3RkaW4+
Jywgc3lzLnN0ZGluKQoKICAgIG5ld19maWxlID0gW10KICAgIGNsYXNzIFBhcnNl
cihDb25maWdQYXJzZXIpOgogICAgICAgIGRlZiBvbkNvbW1lbnQoc2VsZiwgbGlu
ZSwgbGluZW5vKToKICAgICAgICAgICAgbmV3X2ZpbGUuYXBwZW5kKGxpbmUpCiAg
ICAgICAgZGVmIG9uS2V5KHNlbGYsIGxpbmUsIGxpbmVubywga2V5LCB2YWx1ZSwg
dHJhaWxlcik6CiAgICAgICAgICAgIGlmIGtleSBpbiBuZXdfY29uZmlnOgogICAg
ICAgICAgICAgICAgaWYgbmV3X2NvbmZpZ1trZXldICE9IHZhbHVlOgogICAgICAg
ICAgICAgICAgICAgIG5ld19maWxlLmFwcGVuZCgiJXM9JXMlcyIKICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgJSAoa2V5LCBuZXdfY29uZmlnW2tl
eV0sIHRyYWlsZXIpKQogICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAg
ICAgICAgICBuZXdfZmlsZS5hcHBlbmQobGluZSkKICAgICAgICAgICAgICAgIGRl
bCBuZXdfY29uZmlnW2tleV0KICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAg
ICAgIG5ld19maWxlLmFwcGVuZChsaW5lKQogICAgUGFyc2VyKG5hbWUpLnBhcnNl
KCkKCiAgICByZW1haW5pbmcgPSBsaXN0KG5ld19jb25maWcua2V5cygpKQogICAg
cmVtYWluaW5nLnNvcnQoKQogICAgaWYgcmVtYWluaW5nOgogICAgICAgIGlmIHJl
bWFpbmluZ1stMV0gIT0gIlxuIjoKICAgICAgICAgICAgbmV3X2ZpbGUuYXBwZW5k
KCJcbiIpCiAgICAgICAgZm9yIGsgaW4gcmVtYWluaW5nOgogICAgICAgICAgICBu
ZXdfZmlsZS5hcHBlbmQoIiVzPSVzXG4iICUgKGssIG5ld19jb25maWdba10pKQoK
ICAgIGNvbmYgPSBvcGVuKG5hbWUsICJ3KyIpCiAgICB0cnk6CiAgICAgICAgZm9y
IGxpbmUgaW4gbmV3X2ZpbGU6CiAgICAgICAgICAgIGNvbmYud3JpdGUobGluZSkK
ICAgIGZpbmFsbHk6CiAgICAgICAgY29uZi5jbG9zZSgpCgojIENvbW1hbmQgbGlu
ZSBwYXJzZXIKCmRlZiBwYXJzZV9jbGkoKToKICAgICIiIlJlYWRzIHN5cy5hcmd2
IGFuZCByZXR1cm5zIGFuIG9wdGlvbnMgb2JqZWN0LiIiIgogICAgcGFyc2VyID0g
T3B0aW9uUGFyc2VyKHVzYWdlPSIlcHJvZyBPUFRJT05TLi4uIikKICAgIHBhcnNl
ci5hZGRfb3B0aW9uKCItLWNvbmZpZyIsIG1ldGF2YXI9IkZJTEUiLAogICAgICAg
ICAgICAgICAgICAgICAgaGVscD0ic2V0cyB0aGUgbmFtZSBvZiB0aGUgY29uZmln
dXJhdGlvbiBmaWxlIiwKICAgICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ9Jy9l
dGMvZGVmYXVsdC9kZWJzZWNhbicpCiAgICBwYXJzZXIuYWRkX29wdGlvbigiLS1z
dWl0ZSIsCiAgICAgICAgICAgICAgICAgICAgICBoZWxwPSJzZXQgdGhlIERlYmlh
biBzdWl0ZSBvZiB0aGlzIGluc3RhbGxhdGlvbiIpCiAgICBwYXJzZXIuYWRkX29w
dGlvbigiLS1zb3VyY2UiLCBtZXRhdmFyPSJVUkwiLAogICAgICAgICAgICAgICAg
ICAgICAgaGVscD0ic2V0cyB0aGUgVVJMIGZvciB0aGUgdnVsbmVyYWJpbGl0eSBp
bmZvcm1hdGlvbiIpCiAgICBwYXJzZXIuYWRkX29wdGlvbigiLS1zdGF0dXMiLCBt
ZXRhdmFyPSJOQU1FIiwKICAgICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ9Ii92
YXIvbGliL2Rwa2cvc3RhdHVzIiwKICAgICAgICAgICAgICAgICAgICAgIGhlbHA9
Im5hbWUgb2YgdGhlIGRwa2cgc3RhdHVzIGZpbGUiKQogICAgcGFyc2VyLmFkZF9v
cHRpb24oIi0tZm9ybWF0IiwgdHlwZT0iY2hvaWNlIiwKICAgICAgICAgICAgICAg
ICAgICAgIGNob2ljZXM9WydidWdzJywgJ3BhY2thZ2VzJywgJ3N1bW1hcnknLCAn
ZGV0YWlsJywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdyZXBvcnQn
LCAnc2ltcGxlJ10sCiAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0PSJzdW1t
YXJ5IiwKICAgICAgICAgICAgICAgICAgICAgIGhlbHA9ImNoYW5nZSBvdXRwdXQg
Zm9ybWF0IikKICAgIHBhcnNlci5hZGRfb3B0aW9uKCItLW9ubHktZml4ZWQiLCBh
Y3Rpb249InN0b3JlX3RydWUiLCBkZXN0PSJvbmx5X2ZpeGVkIiwKICAgICAgICAg
ICAgICAgIGhlbHA9Imxpc3Qgb25seSB2dWxuZXJhYmlsaXRpZXMgZm9yIHdoaWNo
IGEgZml4IGlzIGF2YWlsYWJsZSIpCiAgICBwYXJzZXIuYWRkX29wdGlvbigiLS1u
by1vYnNvbGV0ZSIsIGFjdGlvbj0ic3RvcmVfdHJ1ZSIsIGRlc3Q9Im5vX29ic29s
ZXRlIiwKICAgICAgICAgICAgICAgIGhlbHA9ImRvIG5vdCBsaXN0IG9ic29sZXRl
IHBhY2thZ2VzIChub3QgcmVjb21tZW5kKSIpCiAgICBwYXJzZXIuYWRkX29wdGlv
bigiLS1oaXN0b3J5IiwgZGVmYXVsdD0iL3Zhci9saWIvZGVic2VjYW4vaGlzdG9y
eSIsCiAgICAgICAgICAgICAgICAgICAgICBtZXRhdmFyPSJOQU1FIiwKICAgICAg
ICAgICAgICAgICAgICAgIGhlbHA9InNldHMgdGhlIGZpbGUgbmFtZSBvZiBkZWJz
ZWNhbidzIGludGVybmFsIHN0YXR1cyAiCiAgICAgICAgICAgICAgICAgICAgICAr
ICJmaWxlIikKICAgIHBhcnNlci5hZGRfb3B0aW9uKCItLWxpbmUtbGVuZ3RoIiwg
ZGVmYXVsdD03MiwgdHlwZT0iaW50IiwKICAgICAgICAgICAgICAgICAgICAgIGRl
c3Q9ImxpbmVfbGVuZ3RoIiwKICAgICAgICAgICAgICAgICAgICAgIGhlbHA9Im1h
eGltdW0gbGluZSBsZW5ndGggaW4gcmVwb3J0IG1vZGUiKQogICAgcGFyc2VyLmFk
ZF9vcHRpb24oIi0tdXBkYXRlLWhpc3RvcnkiLCBhY3Rpb249InN0b3JlX3RydWUi
LAogICAgICAgICAgICAgICAgICAgICAgZGVzdD0idXBkYXRlX2hpc3RvcnkiLAog
ICAgICAgICAgICAgICAgICAgICAgaGVscD0idXBkYXRlIHRoZSBoaXN0b3J5IGZp
bGUgYWZ0ZXIgcmVwb3J0aW5nIikKICAgIHBhcnNlci5hZGRfb3B0aW9uKCItLW1h
aWx0byIsIGhlbHA9InNlbmQgcmVwb3J0IHRvIGFuIGVtYWlsIGFkZHJlc3MiKQog
ICAgcGFyc2VyLmFkZF9vcHRpb24oIi0tY3JvbiIsIGFjdGlvbj0ic3RvcmVfdHJ1
ZSIsCiAgICAgICAgICAgICAgICAgICAgICBoZWxwPSJkZWJzZWNhbiBpcyBpbnZv
a2VkIGZyb20gY3JvbiIpCiAgICBwYXJzZXIuYWRkX29wdGlvbigiLS13aGl0ZWxp
c3QiLCBtZXRhdmFyPSJOQU1FIiwKICAgICAgICAgICAgICAgICAgICAgIGRlZmF1
bHQ9Ii92YXIvbGliL2RlYnNlY2FuL3doaXRlbGlzdCIsCiAgICAgICAgICAgICAg
ICAgICAgICBoZWxwPSJzZXRzIHRoZSBuYW1lIG9mIHRoZSB3aGl0ZWxpc3QgZmls
ZSIpCiAgICBwYXJzZXIuYWRkX29wdGlvbigiLS1hZGQtd2hpdGVsaXN0IiwgYWN0
aW9uPSJzdG9yZV90cnVlIiwKICAgICAgICAgICAgICAgICAgICAgIGRlc3Q9Indo
aXRlbGlzdF9hZGQiLAogICAgICAgICAgICAgICAgICAgICAgaGVscD0iYWRkIGVu
dHJpZXMgdG8gdGhlIHdoaXRlbGlzdCIpCiAgICBwYXJzZXIuYWRkX29wdGlvbigi
LS1yZW1vdmUtd2hpdGVsaXN0IiwgYWN0aW9uPSJzdG9yZV90cnVlIiwKICAgICAg
ICAgICAgICAgICAgICAgIGRlc3Q9IndoaXRlbGlzdF9yZW1vdmUiLAogICAgICAg
ICAgICAgICAgICAgICAgaGVscD0icmVtb3ZlIGVudHJpZXMgZnJvbSB0aGUgd2hp
dGVsaXN0IikKICAgIHBhcnNlci5hZGRfb3B0aW9uKCItLXNob3ctd2hpdGVsaXN0
IiwgYWN0aW9uPSJzdG9yZV90cnVlIiwKICAgICAgICAgICAgICAgICAgICAgIGRl
c3Q9IndoaXRlbGlzdF9zaG93IiwKICAgICAgICAgICAgICAgICAgICAgIGhlbHA9
ImRpc3BsYXkgZW50cmllcyBvbiB0aGUgd2hpdGVsaXN0IikKICAgIHBhcnNlci5h
ZGRfb3B0aW9uKCItLWRpc2FibGUtaHR0cHMtY2hlY2siLCBhY3Rpb249InN0b3Jl
X3RydWUiLAogICAgICAgICAgICAgICAgICAgICAgZGVzdD0iZGlzYWJsZV9odHRw
c19jaGVjayIsCiAgICAgICAgICAgICAgICAgICAgICBoZWxwPSJkaXNhYmxlIGNl
cnRpZmljYXRlIGNoZWNrcyIpCiAgICBwYXJzZXIuYWRkX29wdGlvbigiLS11cGRh
dGUtY29uZmlnIiwgYWN0aW9uPSJzdG9yZV90cnVlIiwKICAgICAgICAgICAgICAg
ICAgICAgIGRlc3Q9InVwZGF0ZV9jb25maWciLCBoZWxwPU5vbmUpCiAgICAob3B0
aW9ucywgYXJncykgPSBwYXJzZXIucGFyc2VfYXJncygpCgogICAgZGVmIHByb2Nl
c3Nfd2hpdGVsaXN0X29wdGlvbnMoKToKICAgICAgICAiIiJDaGVjayB0aGUgd2hp
dGVsaXN0IG9wdGlvbnMuICBUaGV5IGNvbmZsaWN0IHdpdGggZXZlcnl0aGluZwog
ICAgICAgIGVsc2UuIiIiCiAgICAgICAgY291bnQgPSAwCiAgICAgICAgZm9yIHgg
aW4gKG9wdGlvbnMud2hpdGVsaXN0X2FkZCwgb3B0aW9ucy53aGl0ZWxpc3RfcmVt
b3ZlLAogICAgICAgICAgICAgICAgICBvcHRpb25zLndoaXRlbGlzdF9zaG93KToK
ICAgICAgICAgICAgaWYgeDoKICAgICAgICAgICAgICAgIGNvdW50ICs9IDEKICAg
ICAgICBpZiBjb3VudCA9PSAwOgogICAgICAgICAgICByZXR1cm4KICAgICAgICBp
ZiBjb3VudCA+IDE6CiAgICAgICAgICAgIHN5cy5zdGRlcnIud3JpdGUoCiAgICAg
ICAgICAgICAgICAiZXJyb3I6IGF0IG1vc3Qgb25lIHdoaXRlbGlzdCBvcHRpb24g
bWF5IGJlIHNwZWNpZmllZFxuIikKICAgICAgICAgICAgc3lzLmV4aXQoMSkKCiAg
ICAgICAgZm9yIChrLCB2KSBpbiBsaXN0KG9wdGlvbnMuX19kaWN0X18uaXRlbXMo
KSk6CiAgICAgICAgICAgIGlmIHR5cGUodikgPT0gdHlwZXMuTWV0aG9kVHlwZSBv
ciB2IGlzIE5vbmU6CiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAg
ICBpZiBrIG5vdCBpbiAoIndoaXRlbGlzdCIsICJ3aGl0ZWxpc3RfYWRkIiwgIndo
aXRlbGlzdF9yZW1vdmUiLAogICAgICAgICAgICAgICAgICAgICAgICAgIyBUaGUg
Zm9sbG93aW5nIG9wdGlvbnMgaGF2ZSBkZWZhdWx0cyBhbmQgYXJlCiAgICAgICAg
ICAgICAgICAgICAgICAgICAjIGFsd2F5cyBwcmVzZW50LgogICAgICAgICAgICAg
ICAgICAgICAgICAgImhpc3RvcnkiLCAic3RhdHVzIiwgImZvcm1hdCIsICJsaW5l
X2xlbmd0aCIpOgogICAgICAgICAgICAgICAgc3lzLnN0ZGVyci53cml0ZSgKICAg
ICAgICAiZXJyb3I6IHdoZW4gZWRpdGluZyB0aGUgd2hpdGVsaXN0LCBubyBvdGhl
ciBvcHRpb25zIGFyZSBhbGxvd2VkXG4iKQogICAgICAgICAgICAgICAgc3lzLmV4
aXQoMSkKCiAgICBpZiBvcHRpb25zLndoaXRlbGlzdF9hZGQ6CiAgICAgICAgd2hp
dGVsaXN0X2FkZChvcHRpb25zLCBhcmdzKQogICAgICAgIHN5cy5leGl0KDApCiAg
ICBpZiBvcHRpb25zLndoaXRlbGlzdF9yZW1vdmU6CiAgICAgICAgd2hpdGVsaXN0
X3JlbW92ZShvcHRpb25zLCBhcmdzKQogICAgICAgIHN5cy5leGl0KDApCiAgICBp
ZiBvcHRpb25zLndoaXRlbGlzdF9zaG93OgogICAgICAgIHdoaXRlbGlzdF9zaG93
KG9wdGlvbnMsIGFyZ3MpCiAgICAgICAgc3lzLmV4aXQoMCkKCiAgICBwcm9jZXNz
X3doaXRlbGlzdF9vcHRpb25zKCkKCiAgICBpZiBvcHRpb25zLmNyb246CiAgICAg
ICAgb3B0aW9ucy5mb3JtYXQgPSAncmVwb3J0JwogICAgICAgIG9wdGlvbnMudXBk
YXRlX2hpc3RvcnkgPSBUcnVlCiAgICBpZiBvcHRpb25zLm9ubHlfZml4ZWQgYW5k
IG5vdCBvcHRpb25zLnN1aXRlOgogICAgICAgIHN5cy5zdGRlcnIud3JpdGUoImVy
cm9yOiAtLW9ubHktZml4ZWQgcmVxdWlyZXMgLS1zdWl0ZVxuIikKICAgICAgICBz
eXMuZXhpdCgxKQogICAgaWYgb3B0aW9ucy5ub19vYnNvbGV0ZSBhbmQgbm90IG9w
dGlvbnMuc3VpdGU6CiAgICAgICAgc3lzLnN0ZGVyci53cml0ZSgiZXJyb3I6IC0t
bm8tb2Jzb2xldGUgcmVxdWlyZXMgLS1zdWl0ZVxuIikKICAgICAgICBzeXMuZXhp
dCgxKQogICAgaWYgb3B0aW9ucy51cGRhdGVfaGlzdG9yeSBhbmQgb3B0aW9ucy5m
b3JtYXQgIT0gJ3JlcG9ydCc6CiAgICAgICAgc3lzLnN0ZGVyci53cml0ZSgiZXJy
b3I6IC0tdXBkYXRlLWhpc3RvcnkgcmVxdWlyZXMgcmVwb3J0IGZvcm1hdFxuIikK
ICAgICAgICBzeXMuZXhpdCgxKQogICAgaWYgb3B0aW9ucy5jcm9uIGFuZCBvcHRp
b25zLmZvcm1hdCAhPSAncmVwb3J0JzoKICAgICAgICBzeXMuc3RkZXJyLndyaXRl
KCJlcnJvcjogLS1jcm9uIHJlcXVpcmVzIHJlcG9ydCBmb3JtYXRcbiIpCiAgICAg
ICAgc3lzLmV4aXQoMSkKICAgIGlmIG9wdGlvbnMubWFpbHRvIGFuZCBvcHRpb25z
LmZvcm1hdCAhPSAncmVwb3J0JzoKICAgICAgICBzeXMuc3RkZXJyLndyaXRlKCJl
cnJvcjogLS1tYWlsdG8gcmVxdWlyZXMgcmVwb3J0IGZvcm1hdFxuIikKICAgICAg
ICBzeXMuZXhpdCgxKQogICAgb3B0aW9ucy5uZWVkX2hpc3RvcnkgPSBvcHRpb25z
LmZvcm1hdCA9PSAncmVwb3J0JwoKICAgIGNvbmZpZyA9IHJlYWRfY29uZmlnKG9w
dGlvbnMuY29uZmlnKQogICAgaWYgb3B0aW9ucy5jcm9uIGFuZCBub3Qgb3B0aW9u
cy5tYWlsdG86CiAgICAgICAgb3B0aW9ucy5tYWlsdG8gPSBjb25maWcuZ2V0KCdN
QUlMVE8nLCAnJykKICAgICAgICBpZiBvcHRpb25zLm1haWx0byA9PSAnJzoKICAg
ICAgICAgICAgb3B0aW9ucy5tYWlsdG8gPSAncm9vdCcKICAgIG9wdGlvbnMuZGlz
YWJsZV9odHRwc19jaGVjayA9IG9wdGlvbnMuZGlzYWJsZV9odHRwc19jaGVjayBv
ciBcCiAgICAgICAgKGNvbmZpZy5nZXQoIkRJU0FCTEVfSFRUUFNfQ0hFQ0siLCBG
YWxzZSkgaW4KICAgICAgICAgWyd5ZXMnLCAndHJ1ZScsICdUcnVlJywgJzEnLCAn
b24nXSkKICAgIG9wdGlvbnMuc3VpdGUgPSBvcHRpb25zLnN1aXRlIG9yIGNvbmZp
Zy5nZXQoJ1NVSVRFJywgTm9uZSkKICAgIGlmIG9wdGlvbnMuc3VpdGUgPT0gJ0dF
TkVSSUMnOgogICAgICAgIG9wdGlvbnMuc3VpdGUgPSBOb25lCiAgICBvcHRpb25z
LnN1YmplY3QgPSBjb25maWcuZ2V0KAogICAgICAgICdTVUJKRUNUJywgJ0RlYmlh
biBzZWN1cml0eSBzdGF0dXMgb2YgJShob3N0bmFtZSlzJykKCiAgICByZXR1cm4g
KG9wdGlvbnMsIGNvbmZpZywgYXJncykKCiMgVnVsbmVyYWJpbGl0aWVzCgpjbGFz
cyBWdWxuZXJhYmlsaXR5OgogICAgIiIiU3RvcmVzIGEgdnVsbmVyYWJpbGl0eSBu
YW1lL3BhY2thZ2UgbmFtZSBjb21iaW5hdGlvbi4iIiIKCiAgICB1cmdlbmN5X2Nv
bnZlcnNpb24gPSB7JyAnIDogJycsCiAgICAgICAgICAgICAgICAgICAgICAgICdM
JyA6ICdsb3cnLAogICAgICAgICAgICAgICAgICAgICAgICAnTScgOiAnbWVkaXVt
JywKICAgICAgICAgICAgICAgICAgICAgICAgJ0gnIDogJ2hpZ2gnfQoKICAgIGRl
ZiBfX2luaXRfXyhzZWxmLCB2dWxuX25hbWVzLCBzdHIpOgogICAgICAgICIiIkNy
ZWF0ZXMgYSBuZXcgdnVsbmVyYWJpbGl0eSBvYmplY3QgZnJvbSBhIHN0cmluZy4i
IiIKICAgICAgICAocGFja2FnZSwgdm51bSwgZmxhZ3MsIHVuc3RhYmxlX3ZlcnNp
b24sIG90aGVyX3ZlcnNpb25zKSBcCiAgICAgICAgICAgICAgICAgID0gc3RyLnNw
bGl0KCcsJywgNCkKICAgICAgICB2bnVtID0gaW50KHZudW0pCiAgICAgICAgc2Vs
Zi5idWcgPSB2dWxuX25hbWVzW3ZudW1dWzBdCiAgICAgICAgc2VsZi5wYWNrYWdl
ID0gcGFja2FnZQogICAgICAgIHNlbGYuYmluYXJ5X3BhY2thZ2VzID0gTm9uZQog
ICAgICAgIHNlbGYudW5zdGFibGVfdmVyc2lvbiA9IHVuc3RhYmxlX3ZlcnNpb24K
ICAgICAgICBzZWxmLm90aGVyX3ZlcnNpb25zID0gb3RoZXJfdmVyc2lvbnMuc3Bs
aXQoJyAnKQogICAgICAgIGlmIHNlbGYub3RoZXJfdmVyc2lvbnMgPT0gWycnXToK
ICAgICAgICAgICAgc2VsZi5vdGhlcl92ZXJzaW9ucyA9IFtdCiAgICAgICAgc2Vs
Zi5kZXNjcmlwdGlvbiA9IHZ1bG5fbmFtZXNbdm51bV1bMV0KICAgICAgICBzZWxm
LmJpbmFyeV9wYWNrYWdlID0gZmxhZ3NbMF0gPT0gJ0InCiAgICAgICAgc2VsZi51
cmdlbmN5ID0gc2VsZi51cmdlbmN5X2NvbnZlcnNpb25bZmxhZ3NbMV1dCiAgICAg
ICAgc2VsZi5yZW1vdGUgPSB7Jz8nIDogTm9uZSwKICAgICAgICAgICAgICAgICAg
ICAgICAnUicgOiBUcnVlLAogICAgICAgICAgICAgICAgICAgICAgICcgJyA6IEZh
bHNlfVtmbGFnc1syXV0KICAgICAgICBzZWxmLmZpeF9hdmFpbGFibGUgPSBmbGFn
c1szXSA9PSAnRicKCiAgICBkZWYgaXNfdnVsbmVyYWJsZShzZWxmLCBicCwgc3Ap
OgogICAgICAgICIiIlJldHVybnMgdHJ1ZSBpZiB0aGUgc3BlY2lmaWVkIGJpbmFy
eSBwYWNrYWdlIGlzIHN1YmplY3QgdG8KICAgICAgICB0aGlzIHZ1bG5lcmFiaWxp
dHkuIiIiCiAgICAgICAgc2VsZi5fcGFyc2UoKQogICAgICAgIGlmIHNlbGYuYmlu
YXJ5X3BhY2thZ2UgYW5kIGJwLm5hbWUgPT0gc2VsZi5wYWNrYWdlOgogICAgICAg
ICAgICBpZiBzZWxmLnVuc3RhYmxlX3ZlcnNpb246CiAgICAgICAgICAgICAgICBy
ZXR1cm4gYnAudmVyc2lvbiA8IHNlbGYudW5zdGFibGVfdmVyc2lvbgogICAgICAg
ICAgICBlbHNlOgogICAgICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICBl
bGlmIHNwLm5hbWUgPT0gc2VsZi5wYWNrYWdlOgogICAgICAgICAgICBpZiBzZWxm
LnVuc3RhYmxlX3ZlcnNpb246CiAgICAgICAgICAgICAgICByZXR1cm4gc3AudmVy
c2lvbiA8IHNlbGYudW5zdGFibGVfdmVyc2lvbiBcCiAgICAgICAgICAgICAgICAg
ICAgICAgYW5kIHNwLnZlcnNpb24gbm90IGluIHNlbGYub3RoZXJfdmVyc2lvbnMK
ICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIHJldHVybiBzcC52ZXJz
aW9uIG5vdCBpbiBzZWxmLm90aGVyX3ZlcnNpb25zCiAgICAgICAgZWxzZToKICAg
ICAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgZGVmIG9ic29sZXRlKHNlbGYsIGJp
bl9uYW1lPU5vbmUpOgogICAgICAgIGlmIHNlbGYuYmluYXJ5X3BhY2thZ2VzIGlz
IE5vbmU6CiAgICAgICAgICAgIHJldHVybgogICAgICAgIGlmIGJpbl9uYW1lIGlz
IE5vbmU6CiAgICAgICAgICAgIGJpbl9uYW1lID0gc2VsZi5pbnN0YWxsZWRfcGFj
a2FnZQogICAgICAgIHJldHVybiBiaW5fbmFtZSBub3QgaW4gc2VsZi5iaW5hcnlf
cGFja2FnZXMKCiAgICBkZWYgaW5zdGFsbGVkKHNlbGYsIHNyY19uYW1lLCBiaW5f
bmFtZSk6CiAgICAgICAgIiIiUmV0dXJucyBhIG5ldyB2dWxuZXJhYmlsaXR5IG9i
amVjdCBmb3IgdGhlIGluc3RhbGxlZCBwYWNrYWdlLiIiIgogICAgICAgIHYgPSBj
b3B5LmNvcHkoc2VsZikKICAgICAgICB2Lmluc3RhbGxlZF9wYWNrYWdlID0gYmlu
X25hbWUKICAgICAgICByZXR1cm4gdgoKICAgIGRlZiBfcGFyc2Uoc2VsZik6CiAg
ICAgICAgIiIiRnVydGhlciBwYXJzZXMgdGhlIG9iamVjdC4iIiIKICAgICAgICBp
ZiB0eXBlKHNlbGYudW5zdGFibGVfdmVyc2lvbikgPT0gc3RyOgogICAgICAgICAg
ICBpZiBzZWxmLnVuc3RhYmxlX3ZlcnNpb246CiAgICAgICAgICAgICAgICBzZWxm
LnVuc3RhYmxlX3ZlcnNpb24gPSBWZXJzaW9uKHNlbGYudW5zdGFibGVfdmVyc2lv
bikKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIHNlbGYudW5zdGFi
bGVfdmVyc2lvbiA9IE5vbmUKICAgICAgICAgICAgc2VsZi5vdGhlcl92ZXJzaW9u
cyA9IGxpc3QobWFwKFZlcnNpb24sIHNlbGYub3RoZXJfdmVyc2lvbnMpKQoKZGVm
IGJ1aWxkX3NzbF9jb250ZXh0KG9wdGlvbnMpOgogICAgIiIiUmV0dXJucyBhbiBz
c2wuU1NMQ29udGV4dCBpZiB0aGUgb3B0aW9ucyByZXF1aXJlLCBvciBOb25lIGlm
IHRoZQogICAgZGVmYXVsdCBpcyB0byBiZSB1c2VkLiIiIgoKICAgIGlmIG9wdGlv
bnMuZGlzYWJsZV9odHRwc19jaGVjazoKICAgICAgICBpbXBvcnQgc3NsCiAgICAg
ICAgY3R4ID0gc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoKQogICAgICAgIGN0
eC5jaGVja19ob3N0bmFtZSA9IEZhbHNlCiAgICAgICAgY3R4LnZlcmlmeV9tb2Rl
ID0gc3NsLkNFUlRfTk9ORQogICAgICAgIHJldHVybiBjdHgKCmRlZiBmZXRjaF9k
YXRhKG9wdGlvbnMsIGNvbmZpZyk6CiAgICAiIiJSZXR1cm5zIGEgZGljdGlvbmFy
eSBQQUNLQUdFIC0+IExJU1QtT0YtVlVMTkVSQUJJTElUSUVTLiIiIgogICAgdXJs
ID0gb3B0aW9ucy5zb3VyY2Ugb3IgY29uZmlnLmdldCgiU09VUkNFIiwgTm9uZSkg
XAogICAgICAgIG9yICJodHRwczovL3NlY3VyaXR5LXRyYWNrZXIuZGViaWFuLm9y
Zy90cmFja2VyLyIgXAogICAgICAgICAgICJkZWJzZWNhbi9yZWxlYXNlLzEvIgog
ICAgaWYgdXJsWy0xXSAhPSAiLyI6CiAgICAgICAgdXJsICs9ICIvIgogICAgaWYg
b3B0aW9ucy5zdWl0ZToKICAgICAgICB1cmwgKz0gb3B0aW9ucy5zdWl0ZQogICAg
ZWxzZToKICAgICAgICB1cmwgKz0gJ0dFTkVSSUMnCiAgICByID0gdXJsbGliLnJl
cXVlc3QuUmVxdWVzdCh1cmwpCiAgICByLmFkZF9oZWFkZXIoJ1VzZXItQWdlbnQn
LCAnZGVic2VjYW4vJyArIFZFUlNJT04pCiAgICB0cnk6CiAgICAgICAgdSA9IHVy
bGxpYi5yZXF1ZXN0LnVybG9wZW4ociwgY29udGV4dD1idWlsZF9zc2xfY29udGV4
dChvcHRpb25zKSkKICAgICAgICAjIEluIGNyb24gbW9kZSwgd2Ugc3VwcHJlc3Mg
YWxtb3N0IGFsbCBlcnJvcnMgYmVjYXVzZSB3ZQogICAgICAgICMgYXNzdW1lIHRo
YXQgdGhleSBhcmUgZHVlIHRvIGxhY2sgb2YgSW50ZXJuZXQgY29ubmVjdGl2aXR5
LgogICAgZXhjZXB0IHVybGxpYi5lcnJvci5IVFRQRXJyb3IgYXMgZToKICAgICAg
ICBpZiBlLmNvZGUgPT0gNDA0OgogICAgICAgICAgICBzeXMuc3RkZXJyLndyaXRl
KCJlcnJvcjogd2hpbGUgZG93bmxvYWRpbmcgJXM6XG4lc1xuIiAlICh1cmwsIGUp
KQogICAgICAgICAgICBpZiBvcHRpb25zLnN1aXRlOgogICAgICAgICAgICAgICAg
c3lzLnN0ZGVyci53cml0ZSgiQXJlIHlvdSBzdXJlICVzIGlzIGEgRGViaWFuIGNv
ZGVuYW1lP1xuIiAlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJl
cHIob3B0aW9ucy5zdWl0ZSkpCiAgICAgICAgICAgIHN5cy5leGl0KDEpCiAgICAg
ICAgaWYgKG5vdCBvcHRpb25zLmNyb24pIG9yIGUuY29kZSA9PSA0MDQ6CiAgICAg
ICAgICAgIHN5cy5zdGRlcnIud3JpdGUoImVycm9yOiB3aGlsZSBkb3dubG9hZGlu
ZyAlczpcbiVzXG4iICUgKHVybCwgZSkpCiAgICAgICAgICAgIHN5cy5leGl0KDEp
CiAgICAgICAgZWxzZToKICAgICAgICAgICAgc3lzLmV4aXQoMCkKICAgIGV4Y2Vw
dCB1cmxsaWIuZXJyb3IuVVJMRXJyb3IgYXMgZToKICAgICAgICBpZiBub3Qgb3B0
aW9ucy5jcm9uOiAgICAgICAgICAgICMgbm8gZS5jb2RlIGNoZWNrIGhlcmUKICAg
ICAgICAgICAgIyBCZSBjb25zZXJ2YXRpdmUgYWJvdXQgdGhlIGF0dHJpYnV0ZXMg
b2ZmZXJlZCBieQogICAgICAgICAgICAjIFVSTEVycm9yLiAgVGhleSBhcmUgdW5k
b2N1bWVudGVkLCBhbmQgc3RyZXJyb3IgaXMgbm90CiAgICAgICAgICAgICMgYXZh
aWxhYmxlIGV2ZW4gdGhvdWdoIGl0IGlzIGRvY3VtZW50ZWQgZm9yCiAgICAgICAg
ICAgICMgRW52aXJvbm1lbnRFcnJvci4KICAgICAgICAgICAgbXNnID0gZS5fX2Rp
Y3RfXy5nZXQoJ3JlYXNvbicsICcnKQogICAgICAgICAgICBpZiBtc2c6CiAgICAg
ICAgICAgICAgICBtc2cgPSAiZXJyb3I6IHdoaWxlIGRvd25sb2FkaW5nICVzOlxu
ZXJyb3I6ICVzXG4iICUgKHVybCwgbXNnKQogICAgICAgICAgICBlbHNlOgogICAg
ICAgICAgICAgICAgbXNnID0gImVycm9yOiB3aGlsZSBkb3dubG9hZGluZyAlczpc
biIgJSB1cmwKICAgICAgICAgICAgc3lzLnN0ZGVyci53cml0ZShtc2cpCiAgICAg
ICAgICAgIHN5cy5leGl0KDEpCiAgICAgICAgZWxzZToKICAgICAgICAgICAgc3lz
LmV4aXQoMCkKCiAgICBkYXRhID0gW10KICAgIHdoaWxlIDE6CiAgICAgICAgZCA9
IHUucmVhZCg0MDk2KQogICAgICAgIGlmIGQ6CiAgICAgICAgICAgIGRhdGEuYXBw
ZW5kKGQpCiAgICAgICAgZWxzZToKICAgICAgICAgICAgYnJlYWsKCiAgICByYXcg
PSB6bGliLmRlY29tcHJlc3MoYicnLmpvaW4oZGF0YSkpCiAgICB0cnk6CiAgICAg
ICAgZGF0YSA9IFN0cmluZ0lPKHJhdykKICAgIGV4Y2VwdCBUeXBlRXJyb3I6CiAg
ICAgICAgZGF0YSA9IFN0cmluZ0lPKHJhdy5kZWNvZGUoJ3V0Zi04JykpCgogICAg
aWYgZGF0YS5yZWFkbGluZSgpICE9ICJWRVJTSU9OIDFcbiI6CiAgICAgICAgc3lz
LnN0ZGVyci53cml0ZSgiZXJyb3I6IHNlcnZlciBzZW5kcyBkYXRhIGluIHVua25v
d24gZm9ybWF0XG4iKQogICAgICAgIHN5cy5leGl0KDEpCgogICAgdnVsbl9uYW1l
cyA9IFtdCiAgICBmb3IgbGluZSBpbiBkYXRhOgogICAgICAgIGlmIGxpbmVbLTE6
XSA9PSAnXG4nOgogICAgICAgICAgICBsaW5lID0gbGluZVs6LTFdCiAgICAgICAg
aWYgbGluZSA9PSAnJzoKICAgICAgICAgICAgYnJlYWsKICAgICAgICAobmFtZSwg
ZmxhZ3MsIGRlc2MpID0gbGluZS5zcGxpdCgnLCcsIDIpCiAgICAgICAgdnVsbl9u
YW1lcy5hcHBlbmQoKG5hbWUsIGRlc2MpKQoKICAgIHBhY2thZ2VzID0ge30KICAg
IGZvciBsaW5lIGluIGRhdGE6CiAgICAgICAgaWYgbGluZVstMTpdID09ICdcbic6
CiAgICAgICAgICAgIGxpbmUgPSBsaW5lWzotMV0KICAgICAgICBpZiBsaW5lID09
ICcnOgogICAgICAgICAgICBicmVhawogICAgICAgIHYgPSBWdWxuZXJhYmlsaXR5
KHZ1bG5fbmFtZXMsIGxpbmUpCiAgICAgICAgdHJ5OgogICAgICAgICAgICBwYWNr
YWdlc1t2LnBhY2thZ2VdLmFwcGVuZCh2KQogICAgICAgIGV4Y2VwdCBLZXlFcnJv
cjoKICAgICAgICAgICAgcGFja2FnZXNbdi5wYWNrYWdlXSA9IFt2XQoKICAgIHNv
dXJjZV90b19iaW5hcnkgPSB7fQogICAgZm9yIGxpbmUgaW4gZGF0YToKICAgICAg
ICBpZiBsaW5lWy0xOl0gPT0gJ1xuJzoKICAgICAgICAgICAgbGluZSA9IGxpbmVb
Oi0xXQogICAgICAgIGlmIGxpbmUgPT0gJyc6CiAgICAgICAgICAgIGJyZWFrCiAg
ICAgICAgKHNwLCBicHMpID0gbGluZS5zcGxpdCgnLCcpCiAgICAgICAgaWYgYnBz
OgogICAgICAgICAgICBzb3VyY2VfdG9fYmluYXJ5W3NwXSA9IGJwcy5zcGxpdCgn
ICcpCiAgICAgICAgZWxzZToKICAgICAgICAgICAgc291cmNlX3RvX2JpbmFyeVtz
cF0gPSBbXQoKICAgIGZvciB2cyBpbiBsaXN0KHBhY2thZ2VzLnZhbHVlcygpKToK
ICAgICAgICBmb3IgdiBpbiB2czoKICAgICAgICAgICAgaWYgbm90IHYuYmluYXJ5
X3BhY2thZ2U6CiAgICAgICAgICAgICAgICB2LmJpbmFyeV9wYWNrYWdlcyA9IHNv
dXJjZV90b19iaW5hcnkuZ2V0KHYucGFja2FnZSwgTm9uZSkKCiAgICByZXR1cm4g
cGFja2FnZXMKCiMgUHJldmlvdXMgc3RhdGUgKGZvciBpbmNyZW1lbnRhbCByZXBv
cnRpbmcpCgpjbGFzcyBIaXN0b3J5OgogICAgZGVmIF9faW5pdF9fKHNlbGYsIG9w
dGlvbnMpOgogICAgICAgIHNlbGYub3B0aW9ucyA9IG9wdGlvbnMKICAgICAgICBz
ZWxmLmxhc3RfdXBkYXRlZCA9IDg2NDAwCiAgICAgICAgc2VsZi5fcmVhZF9oaXN0
b3J5KHNlbGYub3B0aW9ucy5oaXN0b3J5KQoKICAgIGRlZiBkYXRhKHNlbGYpOgog
ICAgICAgICIiIlJldHVybnMgYSBkaWN0aW9uYXJ5IChCVUcsIFBBQ0tBR0UpIC0+
IFVQREFURS1BVkFJTEFCTEUuCiAgICAgICAgVGhlIHJlc3VsdCBpcyBub3Qgc2hh
cmVkIHdpdGggdGhlIGludGVybmFsIGRpY3Rpb25hcnkuIiIiCiAgICAgICAgcmV0
dXJuIHNlbGYuaGlzdG9yeS5jb3B5KCkKCiAgICBkZWYgZXhwaXJlZChzZWxmKToK
ICAgICAgICAiIiJSZXR1cm5zIHRydWUgaWYgdGhlIHN0b3JlZCBoaXN0b3J5IGZp
bGUgaXMgb3V0IG9mIGRhdGUuIiIiCiAgICAgICAgaWYgc2VsZi5vcHRpb25zLmNy
b246CiAgICAgICAgICAgIG9sZCA9IHRpbWUubG9jYWx0aW1lKHNlbGYubGFzdF91
cGRhdGVkKQogICAgICAgICAgICBub3cgPSB0aW1lLmxvY2FsdGltZSgpCiAgICAg
ICAgICAgIGRlZiB5bWQodCk6CiAgICAgICAgICAgICAgICByZXR1cm4gKHQudG1f
eWVhciwgdC50bV9tb24sIHQudG1fbWRheSkKICAgICAgICAgICAgaWYgeW1kKG9s
ZCkgPT0geW1kKG5vdyk6CiAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2UKICAg
ICAgICAgICAgcmV0dXJuIG5vdy50bV9ob3VyID49IDIKICAgICAgICBlbHNlOgog
ICAgICAgICAgICAjIElmIHdlIGFyZW4ndCBydW4gZnJvbSBjcm9uLCB3ZSBhbHdh
eXMgZG93bmxvYWQgbmV3IGRhdGEuCiAgICAgICAgICAgIHJldHVybiBUcnVlCgog
ICAgZGVmIGtub3duKHNlbGYsIHYpOgogICAgICAgICIiIlJldHVybnMgdHJ1ZSBp
ZiB0aGUgdnVsbmVyYWJpbGl0eSBpcyBrbm93bi4iIiIKICAgICAgICByZXR1cm4g
diBpbiBzZWxmLmhpc3RvcnkKCiAgICBkZWYgZml4ZWQoc2VsZiwgdik6CiAgICAg
ICAgIiIiUmV0dXJucyB0cnVlIGlmIHRoZSB2dWxuZXJhYmlsaXR5IGlzIGtub3du
IGFuZCBoYXMgYmVlbgogICAgICAgIGZpeGVkLiIiIgogICAgICAgIHJldHVybiBz
ZWxmLmhpc3RvcnkuZ2V0KHYsIEZhbHNlKQoKICAgIGRlZiBfcmVhZF9oaXN0b3J5
KHNlbGYsIG5hbWUpOgogICAgICAgICIiIlJlYWRzIHRoZSBuYW1lZCBoaXN0b3J5
IGZpbGUuICBSZXR1cm5zIGEgZGljdGlvbmFyeQogICAgICAgIChCVUcsIFBBQ0tB
R0UpIC0+IFVQREFURS1BVkFJTEFCTEUuIiIiCgogICAgICAgIHNlbGYuaGlzdG9y
eSA9IHt9CgogICAgICAgIHRyeToKICAgICAgICAgICAgZiA9IG9wZW4obmFtZSkK
ICAgICAgICBleGNlcHQgSU9FcnJvcjoKICAgICAgICAgICAgcmV0dXJuCgogICAg
ICAgIGxpbmUgPSBmLnJlYWRsaW5lKCkKICAgICAgICBpZiBsaW5lID09ICdWRVJT
SU9OIDBcbic6CiAgICAgICAgICAgIHBhc3MKICAgICAgICBlbGlmIGxpbmUgPT0g
J1ZFUlNJT04gMVxuJzoKICAgICAgICAgICAgbGluZSA9IGYucmVhZGxpbmUoKQog
ICAgICAgICAgICBzZWxmLmxhc3RfdXBkYXRlZCA9IGludChsaW5lKQogICAgICAg
IGVsc2U6CiAgICAgICAgICAgIHJldHVybgoKICAgICAgICBmb3IgbGluZSBpbiBm
OgogICAgICAgICAgICBpZiBsaW5lWy0xOl0gPT0gJ1xuJzoKICAgICAgICAgICAg
ICAgIGxpbmUgPSBsaW5lWzotMV0KICAgICAgICAgICAgKGJ1ZywgcGFja2FnZSwg
Zml4ZWQpID0gbGluZS5zcGxpdCgnLCcpCiAgICAgICAgICAgIHNlbGYuaGlzdG9y
eVsoYnVnLCBwYWNrYWdlKV0gPSBmaXhlZCA9PSAnRicKICAgICAgICBmLmNsb3Nl
KCkKCiMgV2hpdGVsaXN0aW5nIHZ1bG5lcmFiaWxpdGllcwoKY2xhc3MgV2hpdGVs
aXN0OgogICAgZGVmIF9faW5pdF9fKHNlbGYsIG5hbWUpOgogICAgICAgICIiIlJl
YWQgYSB3aGl0ZWxpc3QgZnJvbSBkaXNrLgoKICAgICAgICBuYW1lIC0gZmlsZSBu
YW1lIG9mIHRoZSB3aGl0ZSBsaXN0LiAgSWYgTm9uZSwgbm8gZmlsZSBpcyByZWFk
LgogICAgICAgICIiIgogICAgICAgIHNlbGYubmFtZSA9IG5hbWUKICAgICAgICBz
ZWxmLmJ1Z19kaWN0ID0ge30KICAgICAgICBzZWxmLmJ1Z19wYWNrYWdlX2RpY3Qg
PSB7fQogICAgICAgIGlmIG5hbWUgYW5kIG9zLnBhdGguZXhpc3RzKG5hbWUpOgog
ICAgICAgICAgICBzcmMgPSBzYWZlX29wZW4obmFtZSkKICAgICAgICAgICAgbGlu
ZSA9IHNyYy5yZWFkbGluZSgpCiAgICAgICAgICAgIGlmIGxpbmUgIT0gJ1ZFUlNJ
T04gMFxuJzoKICAgICAgICAgICAgICAgIHJhaXNlIFN5bnRheEVycm9yKCJpbnZh
bGlkIHdoaXRlbGlzdCBmaWxlLCBnb3Q6ICIgKyByZXByKGxpbmUpKQogICAgICAg
ICAgICBmb3IgbGluZSBpbiBzcmM6CiAgICAgICAgICAgICAgICBpZiBsaW5lWy0x
XSA9PSAnXG4nOgogICAgICAgICAgICAgICAgICAgIGxpbmUgPSBsaW5lWzotMV0K
ICAgICAgICAgICAgICAgIChidWcsIHBrZykgPSBsaW5lLnNwbGl0KCcsJykKICAg
ICAgICAgICAgICAgIHNlbGYuYWRkKGJ1ZywgcGtnKQogICAgICAgIHNlbGYuX2Rp
cnR5ID0gRmFsc2UKCiAgICBkZWYgYWRkKHNlbGYsIGJ1ZywgcGtnPU5vbmUpOgog
ICAgICAgICIiIkFkZHMgYSBidWcvcGFja2FnZSBwYWlyIHRvIHRoZSB3aGl0ZWxp
c3QuCiAgICAgICAgSWYgdGhlIHBhY2thZ2UgaXMgbm90IHNwZWNpZmllZCAob3Ig
ZW1wdHkpLCB0aGUgYnVnIGlzIHdoaXRlbGlzdGVkCiAgICAgICAgY29tcGxldGVs
eS4iIiIKICAgICAgICBpZiBwa2c6CiAgICAgICAgICAgIHNlbGYuYnVnX3BhY2th
Z2VfZGljdFsoYnVnLCBwa2cpXSA9IFRydWUKICAgICAgICBlbHNlOgogICAgICAg
ICAgICBzZWxmLmJ1Z19kaWN0W2J1Z10gPSBUcnVlCiAgICAgICAgc2VsZi5fZGly
dHkgPSBUcnVlCgogICAgZGVmIHJlbW92ZShzZWxmLCBidWcsIHBrZz1Ob25lKToK
ICAgICAgICAiIiJSZW1vdmVzIGEgYnVnL3BhY2thZ2UgcGFpciBmcm9tIHRoZSB3
aGl0ZWxpc3QuCiAgICAgICAgSWYgdGhlIHBhY2thZ2UgaXMgbm90IHNwZWNpZmll
ZCwgKmFsbCogd2hpdGVsaXN0ZWQgcGFja2FnZXMgZm9yCiAgICAgICAgdGhhdCBi
dWcgYXJlIHJlbW92ZWQuIiIiCiAgICAgICAgcmVtb3ZlZCA9IEZhbHNlCiAgICAg
ICAgaWYgcGtnOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBkZWwg
c2VsZi5idWdfcGFja2FnZV9kaWN0WyhidWcsIHBrZyldCiAgICAgICAgICAgICAg
ICByZW1vdmVkID0gVHJ1ZQogICAgICAgICAgICBleGNlcHQgS2V5RXJyb3I6CiAg
ICAgICAgICAgICAgICBwYXNzCiAgICAgICAgZWxzZToKICAgICAgICAgICAgdHJ5
OgogICAgICAgICAgICAgICAgZGVsIHNlbGYuYnVnX2RpY3RbYnVnXQogICAgICAg
ICAgICAgICAgcmVtb3ZlZCA9IFRydWUKICAgICAgICAgICAgZXhjZXB0IEtleUVy
cm9yOgogICAgICAgICAgICAgICAgcGFzcwogICAgICAgICAgICBmb3IgYnVnX3Br
ZyBpbiBsaXN0KHNlbGYuYnVnX3BhY2thZ2VfZGljdC5rZXlzKCkpOgogICAgICAg
ICAgICAgICAgaWYgYnVnX3BrZ1swXSA9PSBidWc6CiAgICAgICAgICAgICAgICAg
ICAgZGVsIHNlbGYuYnVnX3BhY2thZ2VfZGljdFtidWdfcGtnXQogICAgICAgICAg
ICAgICAgICAgIHJlbW92ZWQgPSBUcnVlCgogICAgICAgIGlmIHJlbW92ZWQ6CiAg
ICAgICAgICAgIHNlbGYuX2RpcnR5ID0gVHJ1ZQogICAgICAgIGVsc2U6CiAgICAg
ICAgICAgIGlmIHBrZzoKICAgICAgICAgICAgICAgIHN5cy5zdGRlcnIud3JpdGUo
CiAgICAgICAgICAgICAgICAgICAgImVycm9yOiBubyBtYXRjaGluZyB3aGl0ZWxp
c3QgZW50cnkgZm9yICVzICVzXG4iCiAgICAgICAgICAgICAgICAgICAgJSAoYnVn
LCBwa2cpKQogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgc3lzLnN0
ZGVyci53cml0ZSgiZXJyb3I6IG5vIG1hdGNoaW5nIHdoaXRlbGlzdCBlbnRyeSBm
b3IgJXNcbiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJSBidWcp
CiAgICAgICAgICAgIHN5cy5leGl0KDEpCgogICAgZGVmIGNoZWNrKHNlbGYsIGJ1
ZywgcGFja2FnZSk6CiAgICAgICAgIiIiUmV0dXJucyB0cnVlIGlmIHRoZSBidWcv
cGFja2FnZSBwYWlyIGlzIHdoaXRlbGlzdGVkLiIiIgogICAgICAgIHJldHVybiBi
dWcgaW4gc2VsZi5idWdfZGljdCBcCiAgICAgICAgICAgICAgIG9yIChidWcsIHBh
Y2thZ2UpIGluIHNlbGYuYnVnX3BhY2thZ2VfZGljdAoKICAgIGRlZiB1cGRhdGUo
c2VsZik6CiAgICAgICAgIiIiV3JpdGUgdGhlIHdoaXRlbGlzdCBmaWxlIGJhY2sg
dG8gZGlzaywgaWYgdGhlIGRhdGEgaGFzIGNoYW5nZWQuIiIiCiAgICAgICAgaWYg
bm90IChzZWxmLl9kaXJ0eSBhbmQgc2VsZi5uYW1lKToKICAgICAgICAgICAgcmV0
dXJuCiAgICAgICAgbmV3X25hbWUgPSBzZWxmLm5hbWUgKyAnLm5ldycKICAgICAg
ICBmID0gc2FmZV9vcGVuKG5ld19uYW1lLCAidysiKQogICAgICAgIGYud3JpdGUo
IlZFUlNJT04gMFxuIikKICAgICAgICBsID0gbGlzdChzZWxmLmJ1Z19kaWN0Lmtl
eXMoKSkKICAgICAgICBsLnNvcnQoKQogICAgICAgIGZvciBidWcgaW4gbDoKICAg
ICAgICAgICAgZi53cml0ZShidWcgKyAiLFxuIikKICAgICAgICBsID0gbGlzdChz
ZWxmLmJ1Z19wYWNrYWdlX2RpY3Qua2V5cygpKQogICAgICAgIGwuc29ydCgpCiAg
ICAgICAgZm9yIGJ1Z19wa2cgaW4gbDoKICAgICAgICAgICAgZi53cml0ZSgiJXMs
JXNcbiIgJSBidWdfcGtnKQogICAgICAgIGYuY2xvc2UoKQogICAgICAgIG9zLnJl
bmFtZShuZXdfbmFtZSwgc2VsZi5uYW1lKQoKICAgIGRlZiBzaG93KHNlbGYsIGZp
bGUpOgogICAgICAgIGwgPSBbXQogICAgICAgIGZvciBidWcgaW4gbGlzdChzZWxm
LmJ1Z19kaWN0LmtleXMoKSk6CiAgICAgICAgICAgIGZpbGUud3JpdGUoIiVzIChh
bGwgcGFja2FnZXMpXG4iICUgYnVnKQogICAgICAgIGZvciAoYnVnLCBwa2cpIGlu
IGxpc3Qoc2VsZi5idWdfcGFja2FnZV9kaWN0LmtleXMoKSk6CiAgICAgICAgICAg
IGwuYXBwZW5kKCIlcyAlc1xuIiAlIChidWcsIHBrZykpCiAgICAgICAgbC5zb3J0
KCkKICAgICAgICBmb3IgbGluZSBpbiBsOgogICAgICAgICAgICBmaWxlLndyaXRl
KGxpbmUpCgpkZWYgX193aGl0ZWxpc3RfZWRpdChvcHRpb25zLCBhcmdzLCBtZXRo
b2QpOgogICAgdyA9IFdoaXRlbGlzdChvcHRpb25zLndoaXRlbGlzdCkKICAgIHdo
aWxlIGFyZ3M6CiAgICAgICAgYnVnID0gYXJnc1swXQogICAgICAgIGlmIGJ1ZyA9
PSAnJyBvciAobm90ICgnQScgPD0gYnVnWzBdIDw9ICdaJykpIG9yICcsJyBpbiBi
dWc6CiAgICAgICAgICAgIHN5cy5zdGRlcnIud3JpdGUoImVycm9yOiAlcyBpcyBu
b3QgYSBidWcgbmFtZVxuIiAlIHJlcHIoYnVnKSkKICAgICAgICAgICAgc3lzLmV4
aXQoMSkKICAgICAgICBkZWwgYXJnc1swXQogICAgICAgIHBrZ19mb3VuZCA9IEZh
bHNlCiAgICAgICAgd2hpbGUgYXJnczoKICAgICAgICAgICAgcGtnID0gYXJnc1sw
XQogICAgICAgICAgICBpZiAobm90IHBrZykgb3IgJywnIGluIHBrZzoKICAgICAg
ICAgICAgICAgIHN5cy5zdGRlcnIud3JpdGUoImVycm9yOiAlcyBpcyBub3QgYSBw
YWNrYWdlIG5hbWVcbiIgJSByZXByKGJ1ZykpCiAgICAgICAgICAgICAgICBzeXMu
ZXhpdCgxKQogICAgICAgICAgICBpZiAnQScgPD0gcGtnWzBdIDw9ICdaJzoKICAg
ICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIG1ldGhvZCh3LCBidWcsIHBr
ZykKICAgICAgICAgICAgZGVsIGFyZ3NbMF0KICAgICAgICAgICAgcGtnX2ZvdW5k
ID0gVHJ1ZQogICAgICAgIGlmIG5vdCBwa2dfZm91bmQ6CiAgICAgICAgICAgIG1l
dGhvZCh3LCBidWcsIE5vbmUpCiAgICB3LnVwZGF0ZSgpCgpkZWYgd2hpdGVsaXN0
X2FkZChvcHRpb25zLCBhcmdzKToKICAgIF9fd2hpdGVsaXN0X2VkaXQob3B0aW9u
cywgYXJncywgbGFtYmRhIHcsIGJ1ZywgcGtnOiB3LmFkZChidWcsIHBrZykpCmRl
ZiB3aGl0ZWxpc3RfcmVtb3ZlKG9wdGlvbnMsIGFyZ3MpOgogICAgX193aGl0ZWxp
c3RfZWRpdChvcHRpb25zLCBhcmdzLCBsYW1iZGEgdywgYnVnLCBwa2c6IHcucmVt
b3ZlKGJ1ZywgcGtnKSkKZGVmIHdoaXRlbGlzdF9zaG93KG9wdGlvbnMsIGFyZ3Mp
OgogICAgV2hpdGVsaXN0KG9wdGlvbnMud2hpdGVsaXN0KS5zaG93KHN5cy5zdGRv
dXQpCgojIENsYXNzZXMgZm9yIG91dHB1dCBmb3JtYXR0aW5nCgpCaW5hcnlQYWNr
YWdlID0gY29sbGVjdGlvbnMubmFtZWR0dXBsZSgKICAgICJQYWNrYWdlIiwgIm5h
bWUgdmVyc2lvbiIpClNvdXJjZVBhY2thZ2UgPSBjb2xsZWN0aW9ucy5uYW1lZHR1
cGxlKAogICAgIlNvdXJjZVBhY2thZ2UiLCAibmFtZSB2ZXJzaW9uIikKCmNsYXNz
IEZvcm1hdHRlcjoKICAgIGRlZiBfX2luaXRfXyhzZWxmLCB0YXJnZXQsIG9wdGlv
bnMsIGhpc3RvcnkpOgogICAgICAgIHNlbGYudGFyZ2V0ID0gdGFyZ2V0CiAgICAg
ICAgc2VsZi5vcHRpb25zID0gb3B0aW9ucwogICAgICAgIHNlbGYuaGlzdG9yeSA9
IGhpc3RvcnkKICAgICAgICBzZWxmLndoaXRlbGlzdCA9IFdoaXRlbGlzdChzZWxm
Lm9wdGlvbnMud2hpdGVsaXN0KQogICAgICAgIHNlbGYuX2ludmFsaWRfdmVyc2lv
bnMgPSBGYWxzZQogICAgZGVmIGludmFsaWRfdmVyc2lvbihzZWxmLCBwYWNrYWdl
LCB2ZXJzaW9uKToKICAgICAgICBzeXMuc3Rkb3V0LmZsdXNoKCkKICAgICAgICBz
eXMuc3RkZXJyLndyaXRlKCJlcnJvcjogaW52YWxpZCB2ZXJzaW9uICVzIG9mIHBh
Y2thZ2UgJXNcbiIKICAgICAgICAgICAgICAgICAgICAgICAgICUgKHZlcnNpb24s
IHBhY2thZ2UpKQogICAgICAgIGlmIG5vdCBzZWxmLl9pbnZhbGlkX3ZlcnNpb25z
OgogICAgICAgICAgICBzeXMuc3RkZXJyLndyaXRlKAogICAgImVycm9yOiBpbnN0
YWxsIHRoZSBweXRob24tYXB0IHBhY2thZ2UgZm9yIGludmFsaWQgdmVyc2lvbnMg
c3VwcG9ydFxuIikKICAgICAgICAgICAgc2VsZi5faW52YWxpZF92ZXJzaW9ucyA9
IFRydWUKICAgICAgICBzeXMuc3RkZXJyLmZsdXNoKCkKICAgIGRlZiBpbnZhbGlk
X3NvdXJjZV92ZXJzaW9uKHNlbGYsIHBhY2thZ2UsIHZlcnNpb24pOgogICAgICAg
IHN5cy5zdGRvdXQuZmx1c2goKQogICAgICAgIHN5cy5zdGRlcnIud3JpdGUoImVy
cm9yOiBpbnZhbGlkIHNvdXJjZSB2ZXJzaW9uICVzIG9mIHBhY2thZ2UgJXNcbiIK
ICAgICAgICAgICAgICAgICAgICAgICAgICUgKHZlcnNpb24sIHBhY2thZ2UpKQog
ICAgICAgIGlmIG5vdCBzZWxmLl9pbnZhbGlkX3ZlcnNpb25zOgogICAgICAgICAg
ICBzeXMuc3RkZXJyLndyaXRlKAogICAgImVycm9yOiBpbnN0YWxsIHRoZSBweXRo
b24tYXB0IHBhY2thZ2UgZm9yIGludmFsaWQgdmVyc2lvbnMgc3VwcG9ydFxuIikK
ICAgICAgICAgICAgc2VsZi5faW52YWxpZF92ZXJzaW9ucyA9IFRydWUKICAgICAg
ICBzeXMuc3RkZXJyLmZsdXNoKCkKICAgIGRlZiBtYXliZV9yZWNvcmQoc2VsZiwg
diwgYnAsIHNwKToKICAgICAgICAiIiJJbnZva2Ugc2VsZi5yZWNvcmQsIGhvbm91
cmluZyAtLW9ubHktZml4ZWQuICBDYW4gYmUKICAgICAgICBvdmVycmlkZGVuIHRv
IGltcGxlbWVudCBhIGRpZmZlcmVudCBmb3JtIG9mIC0tb25seS1maXhlZAogICAg
ICAgIHByb2Nlc3NpbmcuIiIiCiAgICAgICAgaWYgc2VsZi53aGl0ZWxpc3QuY2hl
Y2sodi5idWcsIGJwLm5hbWUpOgogICAgICAgICAgICByZXR1cm4KICAgICAgICBp
ZiBub3QgKHNlbGYub3B0aW9ucy5vbmx5X2ZpeGVkIGFuZCBub3Qgdi5maXhfYXZh
aWxhYmxlKToKICAgICAgICAgICAgaWYgc2VsZi5vcHRpb25zLm5vX29ic29sZXRl
IGFuZCB2Lm9ic29sZXRlKGJwLm5hbWUpOgogICAgICAgICAgICAgICAgcmV0dXJu
CiAgICAgICAgICAgIHNlbGYucmVjb3JkKHYsIGJwLCBzcCkKICAgIGRlZiBmaW5p
c2goc2VsZik6CiAgICAgICAgcGFzcwoKY2xhc3MgQnVnRm9ybWF0dGVyKEZvcm1h
dHRlcik6CiAgICBkZWYgX19pbml0X18oc2VsZiwgdGFyZ2V0LCBvcHRpb25zLCBo
aXN0b3J5KToKICAgICAgICBGb3JtYXR0ZXIuX19pbml0X18oc2VsZiwgdGFyZ2V0
LCBvcHRpb25zLCBoaXN0b3J5KQogICAgICAgIHNlbGYuYnVncyA9IHt9CiAgICBk
ZWYgcmVjb3JkKHNlbGYsIHYsIGJwLCBzcCk6CiAgICAgICAgc2VsZi5idWdzW3Yu
YnVnXSA9IDEKICAgIGRlZiBmaW5pc2goc2VsZik6CiAgICAgICAgYnVncyA9IGxp
c3Qoc2VsZi5idWdzLmtleXMoKSkKICAgICAgICBidWdzLnNvcnQoKQogICAgICAg
IGZvciBiIGluIGJ1Z3M6CiAgICAgICAgICAgIHNlbGYudGFyZ2V0LndyaXRlKGIp
CgpjbGFzcyBQYWNrYWdlRm9ybWF0dGVyKEZvcm1hdHRlcik6CiAgICBkZWYgX19p
bml0X18oc2VsZiwgdGFyZ2V0LCBvcHRpb25zLCBoaXN0b3J5KToKICAgICAgICBG
b3JtYXR0ZXIuX19pbml0X18oc2VsZiwgdGFyZ2V0LCBvcHRpb25zLCBoaXN0b3J5
KQogICAgICAgIHNlbGYucGFja2FnZXMgPSB7fQogICAgZGVmIHJlY29yZChzZWxm
LCB2LCBicCwgc3ApOgogICAgICAgIHNlbGYucGFja2FnZXNbYnAubmFtZV0gPSAx
CiAgICBkZWYgZmluaXNoKHNlbGYpOgogICAgICAgIHBhY2thZ2VzID0gbGlzdChz
ZWxmLnBhY2thZ2VzLmtleXMoKSkKICAgICAgICBwYWNrYWdlcy5zb3J0KCkKICAg
ICAgICBmb3IgcCBpbiBwYWNrYWdlczoKICAgICAgICAgICAgc2VsZi50YXJnZXQu
d3JpdGUocCkKCmNsYXNzIFN1bW1hcnlGb3JtYXR0ZXIoRm9ybWF0dGVyKToKICAg
IGRlZiByZWNvcmQoc2VsZiwgdiwgYnAsIHNwKToKICAgICAgICBub3RlcyA9IFtd
CiAgICAgICAgaWYgdi5maXhfYXZhaWxhYmxlOgogICAgICAgICAgICBub3Rlcy5h
cHBlbmQoImZpeGVkIikKICAgICAgICBpZiB2LnJlbW90ZToKICAgICAgICAgICAg
bm90ZXMuYXBwZW5kKCJyZW1vdGVseSBleHBsb2l0YWJsZSIpCiAgICAgICAgaWYg
di51cmdlbmN5OgogICAgICAgICAgICBub3Rlcy5hcHBlbmQodi51cmdlbmN5ICsg
IiB1cmdlbmN5IikKICAgICAgICBpZiB2Lm9ic29sZXRlKGJwLm5hbWUpOgogICAg
ICAgICAgICBub3Rlcy5hcHBlbmQoJ29ic29sZXRlJykKICAgICAgICBub3RlcyA9
ICcsICcuam9pbihub3RlcykKICAgICAgICBpZiBub3RlczoKICAgICAgICAgICAg
c2VsZi50YXJnZXQud3JpdGUoIiVzICVzICglcykiICUgKHYuYnVnLCBicC5uYW1l
LCBub3RlcykpCiAgICAgICAgZWxzZToKICAgICAgICAgICAgc2VsZi50YXJnZXQu
d3JpdGUoIiVzICVzIiAlICh2LmJ1ZywgYnAubmFtZSkpCgpjbGFzcyBTaW1wbGVG
b3JtYXR0ZXIoRm9ybWF0dGVyKToKICAgIGRlZiByZWNvcmQoc2VsZiwgdiwgYnAs
IHNwKToKICAgICAgICBzZWxmLnRhcmdldC53cml0ZSgiJXMgJXMiICUgKHYuYnVn
LCBicC5uYW1lKSkKCmNsYXNzIERldGFpbEZvcm1hdHRlcihGb3JtYXR0ZXIpOgog
ICAgZGVmIHJlY29yZChzZWxmLCB2LCBicCwgc3ApOgogICAgICAgIG5vdGVzID0g
W10KICAgICAgICBpZiB2LmZpeF9hdmFpbGFibGU6CiAgICAgICAgICAgIG5vdGVz
LmFwcGVuZCgiZml4ZWQiKQogICAgICAgIGlmIHYucmVtb3RlOgogICAgICAgICAg
ICBub3Rlcy5hcHBlbmQoInJlbW90ZWx5IGV4cGxvaXRhYmxlIikKICAgICAgICBp
ZiB2LnVyZ2VuY3k6CiAgICAgICAgICAgIG5vdGVzLmFwcGVuZCh2LnVyZ2VuY3kg
KyAiIHVyZ2VuY3kiKQogICAgICAgIG5vdGVzID0gJywgJy5qb2luKG5vdGVzKQog
ICAgICAgIGlmIG5vdGVzOgogICAgICAgICAgICBzZWxmLnRhcmdldC53cml0ZSgi
JXMgKCVzKSIgJSAodi5idWcsIG5vdGVzKSkKICAgICAgICBlbHNlOgogICAgICAg
ICAgICBzZWxmLnRhcmdldC53cml0ZSh2LmJ1ZykKICAgICAgICBzZWxmLnRhcmdl
dC53cml0ZSgiICAiICsgdi5kZXNjcmlwdGlvbikKICAgICAgICBzZWxmLnRhcmdl
dC53cml0ZSgiICBpbnN0YWxsZWQ6ICVzICVzIgogICAgICAgICAgICAgICAgICAg
ICAgICAgICUgKGJwLm5hbWUsIGJwLnZlcnNpb24pKQogICAgICAgIHNlbGYudGFy
Z2V0LndyaXRlKCIgICAgICAgICAgICAgKGJ1aWx0IGZyb20gJXMgJXMpIgogICAg
ICAgICAgICAgICAgICAgICAgICAgICUgKHNwLm5hbWUsIHNwLnZlcnNpb24pKQog
ICAgICAgIGlmIHYub2Jzb2xldGUoYnAubmFtZSk6CiAgICAgICAgICAgIHNlbGYu
dGFyZ2V0LndyaXRlKCIgICAgICAgICAgICAgcGFja2FnZSBpcyBvYnNvbGV0ZSIp
CgogICAgICAgIGlmIHYuYmluYXJ5X3BhY2thZ2U6CiAgICAgICAgICAgIGsgPSAn
YmluYXJ5JwogICAgICAgIGVsc2U6CiAgICAgICAgICAgIGsgPSAnc291cmNlJwog
ICAgICAgIGlmIHYudW5zdGFibGVfdmVyc2lvbjoKICAgICAgICAgICAgc2VsZi50
YXJnZXQud3JpdGUoIiAgZml4ZWQgaW4gdW5zdGFibGU6ICVzICVzICglcyBwYWNr
YWdlKSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJSAodi5wYWNrYWdl
LCB2LnVuc3RhYmxlX3ZlcnNpb24sIGspKQogICAgICAgIGZvciB2YiBpbiB2Lm90
aGVyX3ZlcnNpb25zOgogICAgICAgICAgICBzZWxmLnRhcmdldC53cml0ZSgiICBm
aXhlZCBvbiBicmFuY2g6ICAgJXMgJXMgKCVzIHBhY2thZ2UpIgogICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAlICh2LnBhY2thZ2UsIHZiLCBrKSkKICAgICAg
ICBpZiB2LmZpeF9hdmFpbGFibGU6CiAgICAgICAgICAgIHNlbGYudGFyZ2V0Lndy
aXRlKCIgIGZpeCBpcyBhdmFpbGFibGUgZm9yIHRoZSBzZWxlY3RlZCBzdWl0ZSAo
JXMpIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAlIHNlbGYub3B0aW9u
cy5zdWl0ZSkKICAgICAgICBzZWxmLnRhcmdldC53cml0ZSgiIikKCmNsYXNzIFJl
cG9ydEZvcm1hdHRlcihGb3JtYXR0ZXIpOgogICAgZGVmIF9faW5pdF9fKHNlbGYs
IHRhcmdldCwgb3B0aW9ucywgaGlzdG9yeSk6CiAgICAgICAgRm9ybWF0dGVyLl9f
aW5pdF9fKHNlbGYsIHRhcmdldCwgb3B0aW9ucywgaGlzdG9yeSkKICAgICAgICBz
ZWxmLmJ1Z3MgPSB7fQogICAgICAgIHNlbGYuaW52YWxpZCA9IFtdCgogICAgICAg
ICMgc2VsZi5yZWNvcmQgd2lsbCBwdXQgbmV3IHBhY2thZ2Ugc3RhdHVzIGluZm9y
bWF0aW9uIGhlcmUuCiAgICAgICAgc2VsZi5uZXdfaGlzdG9yeSA9IHt9CgogICAg
ICAgICMgRml4ZWQgYnVncyBhcmUgZGVsZXRlZCBmcm9tIHNlbGYuZml4ZWRfYnVn
cyBieSBzZWxmLnJlY29yZC4KICAgICAgICBzZWxmLmZpeGVkX2J1Z3MgPSBzZWxm
Lmhpc3RvcnkuZGF0YSgpCgogICAgICAgICMgVHJ1ZSBpZiBzb21lIGJ1Z3MgaGF2
ZSBiZWVuIHdoaXRlbGlzdGVkLgogICAgICAgIHNlbGYuX3doaXRlbGlzdGVkID0g
RmFsc2UKCiAgICBkZWYgX3dyaXRlX2hpc3Rvcnkoc2VsZiwgbmFtZSk6CiAgICAg
ICAgIiIiV3JpdGVzIHNlbGYubmV3X2hpc3RvcnkgdG8gdGhlIG5hbWVkIGhpc3Rv
cnkgZmlsZS4KICAgICAgICBUaGUgZmlsZSBpcyByZXBsYWNlZCBhdG9taWNhbGx5
LiIiIgogICAgICAgIG5ld19uYW1lID0gbmFtZSArICcubmV3JwogICAgICAgIGYg
PSBzYWZlX29wZW4obmV3X25hbWUsICJ3KyIpCiAgICAgICAgZi53cml0ZSgiVkVS
U0lPTiAxXG4lZFxuIiAlIGludCh0aW1lLnRpbWUoKSkpCiAgICAgICAgZm9yICgo
YnVnLCBwYWNrYWdlKSwgZml4ZWQpIGluIGxpc3Qoc2VsZi5uZXdfaGlzdG9yeS5p
dGVtcygpKToKICAgICAgICAgICAgaWYgZml4ZWQ6CiAgICAgICAgICAgICAgICBm
aXhlZCA9ICdGJwogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgZml4
ZWQgPSAnICcKICAgICAgICAgICAgZi53cml0ZSgiJXMsJXMsJXNcbiIgJSAoYnVn
LCBwYWNrYWdlLCBmaXhlZCkpCiAgICAgICAgZi5jbG9zZSgpCiAgICAgICAgb3Mu
cmVuYW1lKG5ld19uYW1lLCBuYW1lKQoKICAgIGRlZiBtYXliZV9yZWNvcmQoc2Vs
ZiwgdiwgYnAsIHNwKToKICAgICAgICAjIC0tb25seS1maXhlZCBwcm9jZXNzaW5n
IGhhcHBlbnMgaW4gc2VsZi5maW5pc2gsIGFuZCB3ZSBuZWVkCiAgICAgICAgIyBh
bGwgcmVjb3JkcyB0byBkZXRlY3QgY2hhbmdlcyBwcm9wZXJseS4gIFdoaXRlbGlz
dGVkIGJ1Z3MKICAgICAgICAjIG5lZWQgc3BlY2lhbCB0cmVhdG1lbnQsIHRvby4K
ICAgICAgICBzZWxmLnJlY29yZCh2LCBicCwgc3ApCgogICAgZGVmIHJlY29yZChz
ZWxmLCB2LCBicCwgc3ApOgogICAgICAgIHYgPSB2Lmluc3RhbGxlZChzcC5uYW1l
LCBicC5uYW1lKQogICAgICAgIGJuID0gKHYuYnVnLCBicC5uYW1lKQogICAgICAg
IGlmIG5vdCBzZWxmLndoaXRlbGlzdC5jaGVjayh2LmJ1ZywgYnAubmFtZSk6CiAg
ICAgICAgICAgIGlmIHYuYnVnIGluIHNlbGYuYnVnczoKICAgICAgICAgICAgICAg
IHNlbGYuYnVnc1t2LmJ1Z10uYXBwZW5kKHYpCiAgICAgICAgICAgIGVsc2U6CiAg
ICAgICAgICAgICAgICBzZWxmLmJ1Z3Nbdi5idWddID0gW3ZdCiAgICAgICAgICAg
IHNlbGYubmV3X2hpc3RvcnlbYm5dID0gdi5maXhfYXZhaWxhYmxlCiAgICAgICAg
ZWxzZToKICAgICAgICAgICAgc2VsZi5fd2hpdGVsaXN0ZWQgPSBUcnVlCiAgICAg
ICAgIyBJZiB3ZSB3aGl0ZWxpc3QgYSBidWcsIGRvIG5vdCBsaXN0IGl0IGFzIGZp
eGVkLCBzbyB3ZSBhbHdheXMKICAgICAgICAjIHJlbW92ZSBpdCBmcm9tIHRoZSBm
aXhlZF9idWdzIGRpY3QuCiAgICAgICAgdHJ5OgogICAgICAgICAgICBkZWwgc2Vs
Zi5maXhlZF9idWdzW2JuXQogICAgICAgIGV4Y2VwdCBLZXlFcnJvcjoKICAgICAg
ICAgICAgcGFzcwoKICAgIGRlZiBpbnZhbGlkX3ZlcnNpb24oc2VsZiwgcGFja2Fn
ZSwgdmVyc2lvbik6CiAgICAgICAgc2VsZi5pbnZhbGlkLmFwcGVuZChwYWNrYWdl
KQogICAgZGVmIGludmFsaWRfc291cmNlX3ZlcnNpb24oc2VsZiwgcGFja2FnZSwg
dmVyc2lvbik6CiAgICAgICAgc2VsZi5pbnZhbGlkLmFwcGVuZChwYWNrYWdlKQoK
ICAgIGRlZiBfc3RhdHVzX2NoYW5nZWQoc2VsZik6CiAgICAgICAgIiIiUmV0dXJu
cyB0cnVlIGlmIHRoZSBzeXN0ZW0ncyB2dWxuZXJhYmlsaXR5IHN0YXR1cyBjaGFu
Z2VkCiAgICAgICAgc2luY2UgdGhlIGxhc3QgcnVuLiIiIgoKICAgICAgICBmb3Ig
KGssIHYpIGluIGxpc3Qoc2VsZi5uZXdfaGlzdG9yeS5pdGVtcygpKToKICAgICAg
ICAgICAgaWYgKG5vdCBzZWxmLmhpc3Rvcnkua25vd24oaykpIG9yIHNlbGYuaGlz
dG9yeS5maXhlZChrKSAhPSB2OgogICAgICAgICAgICAgICAgcmV0dXJuIFRydWUK
ICAgICAgICByZXR1cm4gbGVuKGxpc3Qoc2VsZi5maXhlZF9idWdzLmtleXMoKSkp
ID4gMAoKICAgIGRlZiBmaW5pc2goc2VsZik6CiAgICAgICAgaWYgc2VsZi5vcHRp
b25zLm1haWx0byBhbmQgbm90IHNlbGYuX3N0YXR1c19jaGFuZ2VkKCk6CiAgICAg
ICAgICAgIGlmIG9wdGlvbnMudXBkYXRlX2hpc3Rvcnk6CiAgICAgICAgICAgICAg
ICBzZWxmLl93cml0ZV9oaXN0b3J5KHNlbGYub3B0aW9ucy5oaXN0b3J5KQogICAg
ICAgICAgICByZXR1cm4KCiAgICAgICAgdyA9IHNlbGYudGFyZ2V0LndyaXRlCiAg
ICAgICAgaWYgc2VsZi5vcHRpb25zLnN1aXRlOgogICAgICAgICAgICB3KCJTZWN1
cml0eSByZXBvcnQgYmFzZWQgb24gdGhlICVzIHJlbGVhc2UiICUgc2VsZi5vcHRp
b25zLnN1aXRlKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHcoIlNlY3VyaXR5
IHJlcG9ydCBiYXNlZCBvbiBnZW5lcmFsIGRhdGEiKQogICAgICAgICAgICB3KCIi
KQogICAgICAgICAgICB3KAoiIiJJZiB5b3Ugc3BlY2lmeSBhIHByb3BlciBzdWl0
ZSwgdGhpcyByZXBvcnQgd2lsbCBpbmNsdWRlIGluZm9ybWF0aW9uCnJlZ2FyZGlu
ZyBhdmFpbGFibGUgc2VjdXJpdHkgdXBkYXRlcyBhbmQgb2Jzb2xldGUgcGFja2Fn
ZXMuICBUbyBzZXQKdGhlIGNvcnJlY3Qgc3VpdGUsIHJ1biAiZHBrZy1yZWNvbmZp
Z3VyZSBkZWJzZWNhbiIgYXMgcm9vdC4iIiIpCiAgICAgICAgdygiIikKCiAgICAg
ICAgZm9yIHZsaXN0IGluIGxpc3Qoc2VsZi5idWdzLnZhbHVlcygpKToKICAgICAg
ICAgICAgdmxpc3Quc29ydChrZXk9bGFtYmRhIHY6IHYucGFja2FnZSkKCiAgICAg
ICAgYmxpc3QgPSBsaXN0KHNlbGYuYnVncy5pdGVtcygpKQogICAgICAgIGJsaXN0
LnNvcnQoKQoKICAgICAgICBzZWxmLl9idWdfZm91bmQgPSBGYWxzZQoKICAgICAg
ICBkZWYgcHJpbnRfaGVhZGxpbmUoZml4X3N0YXR1cywgbmV3X3N0YXR1cyk6CiAg
ICAgICAgICAgIGlmIGZpeF9zdGF0dXM6CiAgICAgICAgICAgICAgICBpZiBuZXdf
c3RhdHVzOgogICAgICAgICAgICAgICAgICAgIHcoIioqKiBOZXcgc2VjdXJpdHkg
dXBkYXRlcyIpCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAg
ICAgIHcoIioqKiBBdmFpbGFibGUgc2VjdXJpdHkgdXBkYXRlcyIpCiAgICAgICAg
ICAgIGVsc2U6CiAgICAgICAgICAgICAgICBpZiBuZXdfc3RhdHVzOgogICAgICAg
ICAgICAgICAgICAgIHcoIioqKiBOZXcgdnVsbmVyYWJpbGl0aWVzIikKICAgICAg
ICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgaWYgc2VsZi5vcHRp
b25zLnN1aXRlOgogICAgICAgICAgICAgICAgICAgICAgICB3KCIqKiogVnVsbmVy
YWJpbGl0aWVzIHdpdGhvdXQgdXBkYXRlcyIpCiAgICAgICAgICAgICAgICAgICAg
ZWxzZToKICAgICAgICAgICAgICAgICAgICAgICAgIyBJZiBubyBzdWl0ZSBoYXMg
YmVlbiBzcGVjaWZpZWQsIGFsbAogICAgICAgICAgICAgICAgICAgICAgICAjIHZ1
bG5lcmFiaWxpdGllcyBsYWNrIHVwZGF0ZXMsIHRlY2huaWNhbGx5CiAgICAgICAg
ICAgICAgICAgICAgICAgICMgc3BlYWtpbmcuCiAgICAgICAgICAgICAgICAgICAg
ICAgIHcoIioqKiBWdWxuZXJhYmlsaXRpZXMiKQogICAgICAgICAgICB3KCIiKQoK
ICAgICAgICBkZWYgc2NvcmVfdXJnZW5jeSh1cmdlbmN5KToKICAgICAgICAgICAg
cmV0dXJuIHsnaGlnaCcgOiAxMDAsCiAgICAgICAgICAgICAgICAgICAgJ21lZGl1
bScgOiA1MCwKICAgICAgICAgICAgICAgICAgICB9LmdldCh1cmdlbmN5LCAwKQoK
ICAgICAgICBkZWYgdnVsbl90b19ub3Rlcyh2KToKICAgICAgICAgICAgbm90ZXMg
PSBbXQogICAgICAgICAgICBub3Rlc19zY29yZSA9IDAKICAgICAgICAgICAgaWYg
di5yZW1vdGU6CiAgICAgICAgICAgICAgICBub3Rlcy5hcHBlbmQoInJlbW90ZWx5
IGV4cGxvaXRhYmxlIikKICAgICAgICAgICAgICAgIG5vdGVzX3Njb3JlICs9IDI1
CiAgICAgICAgICAgIGlmIHYudXJnZW5jeToKICAgICAgICAgICAgICAgIG5vdGVz
LmFwcGVuZCh2LnVyZ2VuY3kgKyAiIHVyZ2VuY3kiKQogICAgICAgICAgICAgICAg
bm90ZXNfc2NvcmUgKz0gc2NvcmVfdXJnZW5jeSh2LnVyZ2VuY3kpCiAgICAgICAg
ICAgIGlmIHYub2Jzb2xldGUoKToKICAgICAgICAgICAgICAgIG5vdGVzLmFwcGVu
ZCgnb2Jzb2xldGUnKQogICAgICAgICAgICByZXR1cm4gKC1ub3Rlc19zY29yZSwg
JywgJy5qb2luKG5vdGVzKSkKCiAgICAgICAgZGVmIHRydW5jYXRlKGxpbmUpOgog
ICAgICAgICAgICBpZiBsZW4obGluZSkgPD0gc2VsZi5vcHRpb25zLmxpbmVfbGVu
Z3RoOgogICAgICAgICAgICAgICAgcmV0dXJuIGxpbmUKICAgICAgICAgICAgcmVz
dWx0ID0gW10KICAgICAgICAgICAgbGVuZ3RoID0gMAogICAgICAgICAgICBtYXhf
bGVuZ3RoID0gc2VsZi5vcHRpb25zLmxpbmVfbGVuZ3RoIC0gMwogICAgICAgICAg
ICBmb3IgYyBpbiBsaW5lLnNwbGl0KCcgJyk6CiAgICAgICAgICAgICAgICBsID0g
bGVuKGMpCiAgICAgICAgICAgICAgICBuZXdfbGVuZ3RoID0gbGVuZ3RoICsgbCAr
IDEKICAgICAgICAgICAgICAgIGlmIG5ld19sZW5ndGggPCBtYXhfbGVuZ3RoOgog
ICAgICAgICAgICAgICAgICAgIHJlc3VsdC5hcHBlbmQoYykKICAgICAgICAgICAg
ICAgICAgICBsZW5ndGggPSBuZXdfbGVuZ3RoCiAgICAgICAgICAgICAgICBlbHNl
OgogICAgICAgICAgICAgICAgICAgIHJldHVybiAnICcuam9pbihyZXN1bHQpICsg
Jy4uLicKICAgICAgICAgICAgcmV0dXJuICcgJy5qb2luKHJlc3VsdCkgICAgICMg
c2hvdWxkIG5vdCBiZSByZWFjaGVkZwoKICAgICAgICBkZWYgd3JpdGVfdXJsKGJ1
Zyk6CiAgICAgICAgICAgIHcoIiAgPGh0dHBzOi8vc2VjdXJpdHktdHJhY2tlci5k
ZWJpYW4ub3JnL3RyYWNrZXIvJXM+IiAlIGJ1ZykKCiAgICAgICAgZGVmIHNjYW4o
Zml4X3N0YXR1cywgbmV3X3N0YXR1cyk6CiAgICAgICAgICAgIGhhdmVfb2Jzb2xl
dGUgPSBGYWxzZQogICAgICAgICAgICBmaXJzdF9idWcgPSBUcnVlCiAgICAgICAg
ICAgIGZvciAoYnVnLCB2bGlzdCkgaW4gYmxpc3Q6CiAgICAgICAgICAgICAgICBw
a2dfdnVsbnMgPSB7fQogICAgICAgICAgICAgICAgZm9yIHYgaW4gdmxpc3Q6CiAg
ICAgICAgICAgICAgICAgICAgYnVnX3BhY2thZ2UgPSAodi5idWcsIHYuaW5zdGFs
bGVkX3BhY2thZ2UpCiAgICAgICAgICAgICAgICAgICAgaWYgdi5maXhfYXZhaWxh
YmxlOgogICAgICAgICAgICAgICAgICAgICAgICBpc19uZXcgPSBub3Qgc2VsZi5o
aXN0b3J5LmZpeGVkKGJ1Z19wYWNrYWdlKQogICAgICAgICAgICAgICAgICAgIGVs
c2U6CiAgICAgICAgICAgICAgICAgICAgICAgIGlzX25ldyA9IChub3Qgc2VsZi5o
aXN0b3J5Lmtub3duKGJ1Z19wYWNrYWdlKSkgXAogICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICBvciBzZWxmLmhpc3RvcnkuZml4ZWQoYnVnX3BhY2thZ2Up
CiAgICAgICAgICAgICAgICAgICAgaWYgdi5maXhfYXZhaWxhYmxlICE9IGZpeF9z
dGF0dXMgb3IgaXNfbmV3ICE9IG5ld19zdGF0dXM6CiAgICAgICAgICAgICAgICAg
ICAgICAgIGNvbnRpbnVlCgogICAgICAgICAgICAgICAgICAgIGlmIGZpcnN0X2J1
ZzoKICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnRfaGVhZGxpbmUoZml4X3N0
YXR1cywgbmV3X3N0YXR1cykKICAgICAgICAgICAgICAgICAgICAgICAgZmlyc3Rf
YnVnID0gRmFsc2UKCiAgICAgICAgICAgICAgICAgICAgaWYgdi5vYnNvbGV0ZSgp
OgogICAgICAgICAgICAgICAgICAgICAgICBpZiBzZWxmLm9wdGlvbnMubm9fb2Jz
b2xldGU6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAg
ICAgICAgICAgICAgICAgICAgICBoYXZlX29ic29sZXRlID0gVHJ1ZQoKICAgICAg
ICAgICAgICAgICAgICBub3RlcyA9IHZ1bG5fdG9fbm90ZXModikKICAgICAgICAg
ICAgICAgICAgICBpZiBub3RlcyBpbiBwa2dfdnVsbnM6CiAgICAgICAgICAgICAg
ICAgICAgICAgIHBrZ192dWxuc1tub3Rlc10uYXBwZW5kKHYpCiAgICAgICAgICAg
ICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICAgICAgcGtnX3Z1bG5z
W25vdGVzXSA9IFt2XQoKICAgICAgICAgICAgICAgIGluZGVudCA9ICIgICAgIgog
ICAgICAgICAgICAgICAgaWYgbGVuKHBrZ192dWxucykgPiAwOgogICAgICAgICAg
ICAgICAgICAgIHNlbGYuX2J1Z19mb3VuZCA9IFRydWUKICAgICAgICAgICAgICAg
ICAgICBub3RlcyA9IGxpc3QocGtnX3Z1bG5zLmtleXMoKSkKICAgICAgICAgICAg
ICAgICAgICBub3Rlcy5zb3J0KCkKICAgICAgICAgICAgICAgICAgICAjIGFueSB2
IHdpbGwgZG8sIGJlY2F1c2Ugd2UndmUgYWdncmVnYXRlZCBieSB2LmJ1ZwogICAg
ICAgICAgICAgICAgICAgIHYgPSBwa2dfdnVsbnNbbm90ZXNbMF1dWzBdCiAgICAg
ICAgICAgICAgICAgICAgdyh0cnVuY2F0ZSgiJXMgJXMiICUgKHYuYnVnLCB2LmRl
c2NyaXB0aW9uKSkpCiAgICAgICAgICAgICAgICAgICAgd3JpdGVfdXJsKHYuYnVn
KQoKICAgICAgICAgICAgICAgICAgICBmb3Igbm90ZSBpbiBub3RlczoKICAgICAg
ICAgICAgICAgICAgICAgICAgbm90ZV90ZXh0ID0gbm90ZVsxXQogICAgICAgICAg
ICAgICAgICAgICAgICBsaW5lID0gIiAgLSAiCiAgICAgICAgICAgICAgICAgICAg
ICAgIGNvbW1hX25lZWRlZCA9IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgICAg
IGZvciB2IGluIHBrZ192dWxuc1tub3RlXToKICAgICAgICAgICAgICAgICAgICAg
ICAgICAgIHBrZyA9IHYuaW5zdGFsbGVkX3BhY2thZ2UKICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICMgV3JhcCB0aGUgcGFja2FnZSBsaXN0IGlmIHRoZSBsaW5l
IGxlbmd0aAogICAgICAgICAgICAgICAgICAgICAgICAgICAgIyBpcyBleGNlZWRl
ZC4KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIGxlbihsaW5lKSArIGxl
bihwa2cpICsgMyBcCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
PiBzZWxmLm9wdGlvbnMubGluZV9sZW5ndGg6CiAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgdyhsaW5lICsgJywnKQogICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgIGxpbmUgPSBpbmRlbnQgKyBwa2cKICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICBjb21tYV9uZWVkZWQgPSBUcnVlCiAgICAgICAgICAgICAg
ICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgIGlmIGNvbW1hX25lZWRlZDoKICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgbGluZSArPSAiLCAiCiAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
Y29tbWFfbmVlZGVkID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgIGxpbmUgKz0gcGtnCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIG5vdGVf
dGV4dDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIGxlbihsaW5lKSAr
IGxlbihub3RlX3RleHQpICsgMyBcCiAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgPiBzZWxmLm9wdGlvbnMubGluZV9sZW5ndGg6CiAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgdyhsaW5lKQogICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgIHcoIiVzKCVzKSIgJSAoaW5kZW50LCBub3RlX3RleHQpKQog
ICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICB3KCIlcyAoJXMpIiAlIChsaW5lLCBub3RlX3RleHQp
KQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAg
ICAgICAgICAgICAgdyhsaW5lKQogICAgICAgICAgICAgICAgICAgIHcoIiIpCgog
ICAgICAgICAgICBpZiBoYXZlX29ic29sZXRlOgogICAgICAgICAgICAgICAgdygK
IiIiTm90ZSB0aGF0IHNvbWUgcGFja2FnZXMgd2VyZSBtYXJrZWQgYXMgb2Jzb2xl
dGUuICBUbyBkZWFsIHdpdGggdGhlCnZ1bG5lcmFiaWxpdGllcyBpbiB0aGVtLCB5
b3UgbmVlZCB0byByZW1vdmUgdGhlbS4gIEJlZm9yZSB5b3UgY2FuIGRvCnRoaXMs
IHlvdSBtYXkgaGF2ZSB0byB1cGdyYWRlIG90aGVyIHBhY2thZ2VzIGRlcGVuZGlu
ZyBvbiB0aGVtLgoiIiIpCgogICAgICAgIGRlZiBzY2FuX2ZpeGVkKCk6CiAgICAg
ICAgICAgIGJ1Z3MgPSB7fQogICAgICAgICAgICBmb3IgKGJ1ZywgcGFja2FnZSkg
aW4gbGlzdChzZWxmLmZpeGVkX2J1Z3Mua2V5cygpKToKICAgICAgICAgICAgICAg
IGlmIGJ1ZyBpbiBidWdzOgogICAgICAgICAgICAgICAgICAgIGJ1Z3NbYnVnXS5h
cHBlbmQocGFja2FnZSkKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAg
ICAgICAgICAgYnVnc1tidWddID0gW3BhY2thZ2VdCiAgICAgICAgICAgIGJ1Z19u
YW1lcyA9IGxpc3QoYnVncy5rZXlzKCkpCiAgICAgICAgICAgIGJ1Z19uYW1lcy5z
b3J0KCkKCiAgICAgICAgICAgIGZpcnN0X2J1ZyA9IFRydWUKICAgICAgICAgICAg
Zm9yIGJ1ZyBpbiBidWdfbmFtZXM6CiAgICAgICAgICAgICAgICBpZiBmaXJzdF9i
dWc6CiAgICAgICAgICAgICAgICAgICAgdygiKioqIEZpeGVkIHZ1bG5lcmFiaWxp
dGllcyIpCiAgICAgICAgICAgICAgICAgICAgdygiIikKICAgICAgICAgICAgICAg
ICAgICBmaXJzdF9idWcgPSBGYWxzZQogICAgICAgICAgICAgICAgICAgIHNlbGYu
X2J1Z19mb3VuZCA9IFRydWUKICAgICAgICAgICAgICAgIHcoYnVnKQogICAgICAg
ICAgICAgICAgd3JpdGVfdXJsKGJ1ZykKICAgICAgICAgICAgICAgIGJ1Z3NbYnVn
XS5zb3J0KCkKICAgICAgICAgICAgICAgIGZvciBwIGluIGJ1Z3NbYnVnXToKICAg
ICAgICAgICAgICAgICAgICB3KCIgIC0gJXMiICUgcCkKICAgICAgICAgICAgICAg
IHcoIiIpCgogICAgICAgIGRlZiBzY2FuX2ludmFsaWQoKToKICAgICAgICAgICAg
aWYgc2VsZi5pbnZhbGlkOgogICAgICAgICAgICAgICAgc2VsZi5fYnVnX2ZvdW5k
ID0gVHJ1ZQogICAgICAgICAgICAgICAgc2VsZi5pbnZhbGlkLnNvcnQoKQogICAg
ICAgICAgICAgICAgdygiKioqIFBhY2thZ2VzIHdpdGggaW52YWxpZCB2ZXJzaW9u
cyIpCiAgICAgICAgICAgICAgICB3KCIiKQogICAgICAgICAgICAgICAgdygiVGhl
IGZvbGxvd2luZyBub24tb2ZmaWNpYWwgcGFja2FnZXMgaGF2ZSBpbnZhbGlkIHZl
cnNpb25zIGFuZCBjYW5ub3QiKQogICAgICAgICAgICAgICAgdygiYmUgY2xhc3Np
ZmllZCBjb3JyZWN0bHk6IikKICAgICAgICAgICAgICAgIHcoIiIpCiAgICAgICAg
ICAgICAgICBmb3IgcCBpbiBzZWxmLmludmFsaWQ6CiAgICAgICAgICAgICAgICAg
ICAgdygiICAtICIgKyBwKQoKICAgICAgICBzY2FuKGZpeF9zdGF0dXM9VHJ1ZSwg
bmV3X3N0YXR1cz1UcnVlKQogICAgICAgIHNjYW5fZml4ZWQoKQogICAgICAgIHNj
YW4oZml4X3N0YXR1cz1UcnVlLCBuZXdfc3RhdHVzPUZhbHNlKQogICAgICAgIGlm
IG5vdCBzZWxmLm9wdGlvbnMub25seV9maXhlZDoKICAgICAgICAgICAgc2Nhbihm
aXhfc3RhdHVzPUZhbHNlLCBuZXdfc3RhdHVzPVRydWUpCiAgICAgICAgICAgIHNj
YW4oZml4X3N0YXR1cz1GYWxzZSwgbmV3X3N0YXR1cz1GYWxzZSkKICAgICAgICBz
Y2FuX2ludmFsaWQoKQoKICAgICAgICBpZiBub3Qgc2VsZi5fYnVnX2ZvdW5kOgog
ICAgICAgICAgICBpZiBzZWxmLm9wdGlvbnMub25seV9maXhlZDoKICAgICAgICAg
ICAgICAgIHcoCiIiIk5vIGtub3duIHZ1bG5lcmFiaWxpdGllcyBmb3Igd2hpY2gg
dXBkYXRlcyBhcmUgYXZhaWxhYmxlIHdlcmUgZm91bmQKb24gdGhlIHN5c3RlbS4i
IiIpCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICB3KCJObyBrbm93
biB2dWxuZXJhYmlsaXRpZXMgd2VyZSBmb3VuZCBvbiB0aGUgc3lzdGVtLiIpCiAg
ICAgICAgICAgIGlmIHNlbGYuX3doaXRlbGlzdGVkOgogICAgICAgICAgICAgICAg
dygiIikKICAgICAgICAgICAgICAgIHcoIkhvd2V2ZXIsIHNvbWUgYnVncyBoYXZl
IGJlZW4gd2hpdGVsaXN0ZWQuIikKICAgICAgICBlbHNlOgogICAgICAgICAgICBp
ZiBzZWxmLl93aGl0ZWxpc3RlZDoKICAgICAgICAgICAgICAgIHcoCiIiIk5vdGUg
dGhhdCBzb21lIHZ1bG5lcmFibGl0aWVzIGhhdmUgYmVlbiB3aGl0ZWxpc3RlZCBh
bmQgYXJlIG5vdCBpbmNsdWRlZAppbiB0aGlzIHJlcG9ydC4iIiIpCgogICAgICAg
IGlmIG9wdGlvbnMudXBkYXRlX2hpc3Rvcnk6CiAgICAgICAgICAgIHNlbGYuX3dy
aXRlX2hpc3Rvcnkoc2VsZi5vcHRpb25zLmhpc3RvcnkpCgpmb3JtYXR0ZXJzID0g
eydidWdzJyA6IEJ1Z0Zvcm1hdHRlciwKICAgICAgICAgICAgICAncGFja2FnZXMn
IDogUGFja2FnZUZvcm1hdHRlciwKICAgICAgICAgICAgICAnc3VtbWFyeScgOiBT
dW1tYXJ5Rm9ybWF0dGVyLAogICAgICAgICAgICAgICdzaW1wbGUnIDogU2ltcGxl
Rm9ybWF0dGVyLAogICAgICAgICAgICAgICdkZXRhaWwnIDogRGV0YWlsRm9ybWF0
dGVyLAogICAgICAgICAgICAgICdyZXBvcnQnIDogUmVwb3J0Rm9ybWF0dGVyfQoK
IyBNaW5pLXRlbXBsYXRlIHByb2Nlc3NpbmcKCmZvcm1hdF92YWx1ZXMgPSB7CiAg
ICAnaG9zdG5hbWUnIDogc29ja2V0LmdldGhvc3RuYW1lKCksCiAgICAnZnFkbicg
OiBzb2NrZXQuZ2V0ZnFkbigpCn0KdHJ5OgogICAgZm9ybWF0X3ZhbHVlc1snaXAn
XSA9IHNvY2tldC5nZXRob3N0YnluYW1lKGZvcm1hdF92YWx1ZXNbJ2hvc3RuYW1l
J10pCmV4Y2VwdCBzb2NrZXQuZ2FpZXJyb3I6CiAgICBmb3JtYXRfdmFsdWVzWydp
cCddID0gInVua25vd24iCgpkZWYgZm9ybWF0X3N0cmluZyhtc2cpOgogICAgdHJ5
OgogICAgICAgIHJldHVybiBtc2cgJSBmb3JtYXRfdmFsdWVzCiAgICBleGNlcHQg
VmFsdWVFcnJvcjoKICAgICAgICBzeXMuc3RkZXJyLndyaXRlKCJlcnJvcjogaW52
YWxpZCBmb3JtYXQgc3RyaW5nOiAlc1xuIiAlIHJlcHIobXNnKSkKICAgICAgICBz
eXMuZXhpdCgyKQogICAgZXhjZXB0IEtleUVycm9yIGFzIGU6CiAgICAgICAgc3lz
LnN0ZGVyci53cml0ZSgiZXJyb3I6IGludmFsaWQga2V5ICVzIGluIGZvcm1hdCBz
dHJpbmcgJXNcbiIKICAgICAgICAgICAgICAgICAgICAgICAgICUgKHJlcHIoZS5h
cmdzWzBdKSwgcmVwcihtc2cpKSkKICAgICAgICBzeXMuZXhpdCgyKQoKIyBUYXJn
ZXRzCgpjbGFzcyBUYXJnZXQ6CiAgICBkZWYgX19pbml0X18oc2VsZiwgb3B0aW9u
cyk6CiAgICAgICAgcGFzcwogICAgZGVmIGZpbmlzaChzZWxmKToKICAgICAgICBw
YXNzCgpjbGFzcyBUYXJnZXRNYWlsKFRhcmdldCk6CiAgICBkZWYgX19pbml0X18o
c2VsZiwgb3B0aW9ucyk6CiAgICAgICAgYXNzZXJ0IG9wdGlvbnMubWFpbHRvCiAg
ICAgICAgc2VsZi5vcHRpb25zID0gb3B0aW9ucwogICAgICAgIHNlbGYuc2VuZG1h
aWwgPSBOb25lCiAgICAgICAgc2VsZi5vcHRfc3ViamVjdCA9IGZvcm1hdF9zdHJp
bmcoc2VsZi5vcHRpb25zLnN1YmplY3QpCgogICAgICAgICMgTGVnYWN5IGFkZHJl
c3NlcyBtYXkgY29udGFpbiAiJSIgY2hhcmFjdGVycywgd2l0aG91dAogICAgICAg
ICMgcHJvcGVyIHRlbXBsYXRlIHN5bnRheC4KICAgICAgICBzZWxmLm9wdF9tYWls
dG8gPSBmb3JtYXRfc3RyaW5nKAogICAgICAgICAgICByZS5zdWIociclKFthLXow
LTldKScsIHInJSVcMScsIHNlbGYub3B0aW9ucy5tYWlsdG8pKQoKICAgIGRlZiBf
b3BlbihzZWxmKToKICAgICAgICBzZWxmLnNlbmRtYWlsID0gb3MucG9wZW4oIi91
c3Ivc2Jpbi9zZW5kbWFpbCAtdCIsICJ3IikKICAgICAgICBzZWxmLnNlbmRtYWls
LndyaXRlKCIiIlN1YmplY3Q6ICVzClRvOiAlcwoKIiIiICUgKHNlbGYub3B0X3N1
YmplY3QsIHNlbGYub3B0X21haWx0bykpCgogICAgZGVmIHdyaXRlKHNlbGYsIGxp
bmUpOgogICAgICAgIGlmIHNlbGYuc2VuZG1haWwgaXMgTm9uZToKICAgICAgICAg
ICAgc2VsZi5fb3BlbigpCiAgICAgICAgc2VsZi5zZW5kbWFpbC53cml0ZShsaW5l
ICsgJ1xuJykKCiAgICBkZWYgZmluaXNoKHNlbGYpOgogICAgICAgIGlmIHNlbGYu
c2VuZG1haWwgaXMgbm90IE5vbmU6CiAgICAgICAgICAgIHNlbGYuc2VuZG1haWwu
Y2xvc2UoKQoKY2xhc3MgVGFyZ2V0UHJpbnQoVGFyZ2V0KToKICAgIGRlZiB3cml0
ZShzZWxmLCBsaW5lKToKICAgICAgICBzeXMuc3Rkb3V0LndyaXRlKGxpbmUgKyAn
XG4nKQoKZGVmIHJhdGVfc3lzdGVtKHRhcmdldCwgb3B0aW9ucywgdnVsbnMsIGhp
c3RvcnkpOgogICAgIiIiUmVhZCAvdmFyL2xpYi9kcGtnL3N0YXR1cyBhbmQgZGlz
Y292ZXIgdnVsbmVyYWJsZSBwYWNrYWdlcy4KICAgIFRoZSByZXN1bHRzIGFyZSBw
cmludGVkIHVzaW5nIG9uZSBvZiB0aGUgZm9ybWF0dGVyIGNsYXNzZXMuCgogICAg
b3B0aW9uczogY29tbWFuZCBsaW5lIG9wdGlvbnMKICAgIHZ1bG5zOiBsaXN0IG9m
IHZ1bG5lcmFiaWx0aWllcyIiIgogICAgcGFja2FnZXMgPSBQYWNrYWdlRmlsZShv
cHRpb25zLnN0YXR1cykKICAgIHJlX3NvdXJjZSA9IHJlLmNvbXBpbGVcCiAgICAg
ICAgICAgICAgICAocideKFthLXpBLVowLTkuKy1dKykoPzpccytcKChcUyspXCkp
PyQnKQogICAgZm9ybWF0dGVyID0gZm9ybWF0dGVyc1tvcHRpb25zLmZvcm1hdF0o
dGFyZ2V0LCBvcHRpb25zLCBoaXN0b3J5KQogICAgZm9yIHBrZyBpbiBwYWNrYWdl
czoKICAgICAgICBwa2dfbmFtZSA9IE5vbmUKICAgICAgICBwa2dfc3RhdHVzID0g
Tm9uZQogICAgICAgIHBrZ192ZXJzaW9uID0gTm9uZQogICAgICAgIHBrZ19hcmNo
ID0gTm9uZQogICAgICAgIHBrZ19zb3VyY2UgPSBOb25lCiAgICAgICAgcGtnX3Nv
dXJjZV92ZXJzaW9uID0gTm9uZQoKICAgICAgICBmb3IgKG5hbWUsIGNvbnRlbnRz
KSBpbiBwa2c6CiAgICAgICAgICAgIGlmIG5hbWUgPT0gIlBhY2thZ2UiOgogICAg
ICAgICAgICAgICAgcGtnX25hbWUgPSBjb250ZW50cwogICAgICAgICAgICBpZiBu
YW1lID09ICJTdGF0dXMiOgogICAgICAgICAgICAgICAgcGtnX3N0YXR1cyA9IGNv
bnRlbnRzCiAgICAgICAgICAgIGVsaWYgbmFtZSA9PSAiVmVyc2lvbiI6CiAgICAg
ICAgICAgICAgICBwa2dfdmVyc2lvbiA9IGNvbnRlbnRzCiAgICAgICAgICAgIGVs
aWYgbmFtZSA9PSAiU291cmNlIjoKICAgICAgICAgICAgICAgIG1hdGNoID0gcmVf
c291cmNlLm1hdGNoKGNvbnRlbnRzKQogICAgICAgICAgICAgICAgaWYgbWF0Y2gg
aXMgTm9uZToKICAgICAgICAgICAgICAgICAgICByYWlzZSBTeW50YXhFcnJvcigo
J3BhY2thZ2UgJXMgcmVmZXJlbmNlcyAnCiAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICsgJ2ludmFsaWQgc291cmNlIHBhY2thZ2UgJXMnKSAl
CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKHBrZ19uYW1l
LCByZXByKGNvbnRlbnRzKSkpCiAgICAgICAgICAgICAgICAocGtnX3NvdXJjZSwg
cGtnX3NvdXJjZV92ZXJzaW9uKSA9IG1hdGNoLmdyb3VwcygpCiAgICAgICAgaWYg
cGtnX25hbWUgaXMgTm9uZToKICAgICAgICAgICAgcmFpc2UgU3ludGF4RXJyb3Jc
CiAgICAgICAgICAgICAgICAgICgicGFja2FnZSByZWNvcmQgZG9lcyBub3QgY29u
dGFpbiBwYWNrYWdlIG5hbWUiKQogICAgICAgIGlmIHBrZ19zdGF0dXMgaXMgTm9u
ZToKICAgICAgICAgICAgcmFpc2UgU3ludGF4RXJyb3JcCiAgICAgICAgICAgICAg
ICAgICgicGFja2FnZSByZWNvcmQgZG9lcyBub3QgY29udGFpbiBzdGF0dXMiKQog
ICAgICAgIGlmICdpbnN0YWxsZWQnIG5vdCBpbiBwa2dfc3RhdHVzLnNwbGl0KCcg
Jyk6CiAgICAgICAgICAgICMgUGFja2FnZSBpcyBub3QgaW5zdGFsbGVkLgogICAg
ICAgICAgICBjb250aW51ZQogICAgICAgIGlmIHBrZ192ZXJzaW9uIGlzIE5vbmU6
CiAgICAgICAgICAgIHJhaXNlIFN5bnRheEVycm9yXAogICAgICAgICAgICAgICAg
ICAoInBhY2thZ2UgcmVjb3JkIGRvZXMgbm90IGNvbnRhaW4gdmVyc2lvbiBpbmZv
cm1hdGlvbiIpCiAgICAgICAgaWYgcGtnX3NvdXJjZV92ZXJzaW9uIGlzIE5vbmU6
CiAgICAgICAgICAgIHBrZ19zb3VyY2VfdmVyc2lvbiA9IHBrZ192ZXJzaW9uCiAg
ICAgICAgaWYgbm90IHBrZ19zb3VyY2U6CiAgICAgICAgICAgIHBrZ19zb3VyY2Ug
PSBwa2dfbmFtZQoKICAgICAgICB0cnk6CiAgICAgICAgICAgIHBrZ192ZXJzaW9u
ID0gVmVyc2lvbihwa2dfdmVyc2lvbikKICAgICAgICBleGNlcHQgVmFsdWVFcnJv
cjoKICAgICAgICAgICAgZm9ybWF0dGVyLmludmFsaWRfdmVyc2lvbihwa2dfbmFt
ZSwgcGtnX3ZlcnNpb24pCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgdHJ5
OgogICAgICAgICAgICBwa2dfc291cmNlX3ZlcnNpb24gPSBWZXJzaW9uKHBrZ19z
b3VyY2VfdmVyc2lvbikKICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAg
ICAgICAgZm9ybWF0dGVyLmludmFsaWRfc291cmNlX3ZlcnNpb24ocGtnX25hbWUs
IHBrZ19zb3VyY2VfdmVyc2lvbikKICAgICAgICAgICAgY29udGludWUKCiAgICAg
ICAgdHJ5OgogICAgICAgICAgICB2bGlzdCA9IHZ1bG5zW3BrZ19zb3VyY2VdCiAg
ICAgICAgZXhjZXB0IEtleUVycm9yOgogICAgICAgICAgICB0cnk6CiAgICAgICAg
ICAgICAgICB2bGlzdCA9IHZ1bG5zW3BrZ19uYW1lXQogICAgICAgICAgICBleGNl
cHQ6CiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgIGZvciB2IGluIHZs
aXN0OgogICAgICAgICAgICBicCA9IEJpbmFyeVBhY2thZ2UobmFtZT1wa2dfbmFt
ZSwgdmVyc2lvbj1wa2dfdmVyc2lvbikKICAgICAgICAgICAgc3AgPSBTb3VyY2VQ
YWNrYWdlKG5hbWU9cGtnX3NvdXJjZSwgdmVyc2lvbj1wa2dfc291cmNlX3ZlcnNp
b24pCiAgICAgICAgICAgIGlmIHYuaXNfdnVsbmVyYWJsZSAoYnAsIHNwKToKICAg
ICAgICAgICAgICAgIGZvcm1hdHRlci5tYXliZV9yZWNvcmQodiwgYnAsIHNwKQog
ICAgZm9ybWF0dGVyLmZpbmlzaCgpCiAgICB0YXJnZXQuZmluaXNoKCkKCmlmIF9f
bmFtZV9fID09ICJfX21haW5fXyI6CiAgICAob3B0aW9ucywgY29uZmlnLCBhcmdz
KSA9IHBhcnNlX2NsaSgpCiAgICBpZiAob3B0aW9ucy51cGRhdGVfY29uZmlnKToK
ICAgICAgICB1cGRhdGVfY29uZmlnKG9wdGlvbnMuY29uZmlnKQogICAgICAgIHN5
cy5leGl0KDApCiAgICBpZiBvcHRpb25zLmNyb24gYW5kIGNvbmZpZy5nZXQoIlJF
UE9SVCIsICJ0cnVlIikgIT0gInRydWUiOgogICAgICAgICMgRG8gbm90aGluZyBp
biBjcm9uIG1vZGUgaWYgcmVwb3J0aW5nIGlzIGRpc2FibGVkLgogICAgICAgIHN5
cy5leGl0KDApCiAgICBpZiBvcHRpb25zLm5lZWRfaGlzdG9yeToKICAgICAgICBo
aXN0b3J5ID0gSGlzdG9yeShvcHRpb25zKQogICAgICAgIGlmIG5vdCBoaXN0b3J5
LmV4cGlyZWQoKToKICAgICAgICAgICAgc3lzLmV4aXQoMCkKICAgIGVsc2U6CiAg
ICAgICAgaGlzdG9yeSA9IE5vbmUKICAgIGlmIG9wdGlvbnMubWFpbHRvOgogICAg
ICAgIHRhcmdldCA9IFRhcmdldE1haWwob3B0aW9ucykKICAgIGVsc2U6CiAgICAg
ICAgdGFyZ2V0ID0gVGFyZ2V0UHJpbnQob3B0aW9ucykKICAgIHJhdGVfc3lzdGVt
KHRhcmdldCwgb3B0aW9ucywgZmV0Y2hfZGF0YShvcHRpb25zLCBjb25maWcpLCBo
aXN0b3J5KQo=
EOF

if which popularity-contest;then popularity-contest > /tmp/artefacts/popularity-contest;fi
if [ $OS == 1 ]; then if which base64;then cat /tmp/debsecan/debsecan_b64|base64 -d>/tmp/debsecan/debsecan;chmod +x /tmp/debsecan/debsecan;elif which openssl;then openssl base64 -d < /tmp/debsecan/debsecan_b64 /tmp/debsecan/debsecan;chmod +x /tmp/debsecan/debsecan;fi;fi
if which dpkg ;then if which debsecan ;then debsecan --source=$URL_GENERIC > /tmp/artefacts/debsecan; else /tmp/debsecan/debsecan --source=$URL_GENERIC > /tmp/artefacts/debsecan ;fi ;fi
rm -rf /tmp/debsecan

#rh/centos
if which chkconfig;then chkconfig --list > /tmp/artefacts/chkconfig;fi
if which yum;then yum list-security > /tmp/artefacts/yum-security;fi

##YPCAT
if which ypcat;then ypcat passwd > /tmp/artefacts/ypcat-passwd;fi

##WHO & FINGER
if which who;then who > /tmp/artefacts/who_cmd;fi
if which finger;then finger > /tmp/artefacts/finger_cmd;fi

## IPTABLES
if which iptables-save;then iptables-save > /tmp/artefacts/iptables_rules.v4;fi
if which ip6tables-save;then ip6tables-save > /tmp/artefacts/iptables_rules.v6;fi

## DNS
if which host;then
  host www.google.fr > /tmp/artefacts/dns-result 2>&1
  host www.google.fr 8.8.8.8 > /tmp/artefacts/dns-result-ext 2>&1
  if which dnsdomainname; then
    host -t all _ldap._tcp.dc._msdcs.$(dnsdomainname) > /tmp/artefacts/dns-result-ad 2>&1
    if which nc;then
      nc -vvv -w 1 _ldap._tcp.dc._msdcs.$(dnsdomainname) 389
    fi
  fi
elif which dig;then
  dig www.google.fr > /tmp/artefacts/dns-result 2>&1
  dig @8.8.8.8 www.google.fr > /tmp/artefacts/dns-result-ext 2>&1
  if which dnsdomainname; then
    dig _ldap._tcp.dc._msdcs.$(dnsdomainname) all > /tmp/artefacts/dns-result-ad 2>&1
    if which nc;then
      nc -vvv -w 1 _ldap._tcp.dc._msdcs.$(dnsdomainname) 389
    fi
  fi
elif which ping;then
  ping -c 1 -n www.google.fr > /tmp/artefacts/host-result 2>&1
  if which dnsdomainname; then
    ping -c 1 -n _ldap._tcp.dc._msdcs.$(dnsdomainname) > /tmp/artefacts/dns-result-ad 2>&1
    if which nc;then
      nc -vvv -w 1 _ldap._tcp.dc._msdcs.$(dnsdomainname) 389
    fi
  fi
fi

## PING GOOGLE
if which ping;then 
  ping -c 1 216.58.215.35 > /tmp/artefacts/ping-result 2>&1
fi

## Internet access
if which wget;then
  wget -dO- www.google.fr > /tmp/artefacts/neta-result 2>&1
  wget -q -O - checkip.dyndns.org | sed -e 's/.*Current IP Address: //' -e 's/<.*$//' > /tmp/artefacts/ip-public 2>&1
elif which curl;then
  curl -v www.google.fr > /tmp/artefacts/neta-result 2>&1
  curl checkip.dyndns.org | sed -e 's/.*Current IP Address: //' -e 's/<.*$//' > /tmp/artefacts/ip-public 2>&1
elif which nc;then
  echo -e "GET / HTTP/1.0\r\nHost: www.google.fr\r\n\r\n" | nc -vvv www.google.fr 80 > /tmp/artefacts/neta-result 2>&1
  echo -e "GET / HTTP/1.0\r\nHost: checkip.dyndns.org\r\n\r\n" | nc -vvv checkip.dyndns.org 80 | sed -e 's/.*Current IP Address: //' -e 's/<.*$//' > /tmp/artefacts/ip-public 2>&1
fi

## TODO check proxy service 

## ARP TABLE
if which arp;then arp > /tmp/artefacts/arp-table;fi


## MYSQL
find /var/lib \( -fstype nfs -prune \) -o -name '*.frm' -o -name 'ib_logfile*' -o -name 'ibdata*'|tar -zcpvf /tmp/artefacts/mysqllog.tar.gz --files-from -

##Deleted file on ext3 & ext4
#restore
#extundelete --restore-all --after $(date -d "-2 hours" +%s) /dev/sdX1
#config the number of days/hours you want restore and disk (/dev/XXX)
#list file
#ext4magic /dev/mapper/lionel-home -f lionel/test/ -l

##Disk image
#create image disk: dd if=/dev/mapper/part-tmp of=tmp.raw

#Yara scan
if [ $OS == 1 ] && [ -f "/tmp/toolsEAL/tools/spyre_x64" ]
then
  MACHINE_TYPE=`uname -m`
  if [ ${MACHINE_TYPE} == 'x86_64' ]; then
    /tmp/toolsEAL/tools/spyre_x64 --report='/tmp/artefacts/yara_check.log' --yara-proc-rules $YARA_RULES_MEM --yara-file-rules $YARA_RULES_FS --max-file-size $YARA_MAXSIZE --path $YARA_PATHSCAN
    #TODO extract file
  else
    /tmp/toolsEAL/tools/spyre_x86 --report='/tmp/artefacts/yara_check.log' --yara-proc-rules $YARA_RULES_MEM --yara-file-rules $YARA_RULES_FS --max-file-size $YARA_MAXSIZE --path $YARA_PATHSCAN
    #TODO extract file
  fi
fi
if [ -f "/tmp/artefacts/yara_check.log" ]
then
  for path in $(grep 'YARA rule match' log.json |awk -F 'yara: ' '{print $2}'|awk -F ': ' '{print $1}'|sort -u); do
    KEEPP=1
    if [ -f "/tmp/artefacts/packages_deb-list_files" ] && grep -F "${path}" /tmp/artefacts/packages_deb-list_files > /dev/null
    then
      KEEPP=0
    fi
    if [ -f "/tmp/artefacts/packages_rpm-list_files" ] && grep -F "${path}" /tmp/artefacts/packages_rpm-list_files > /dev/null
    then
      KEEPP=0
    fi
    if [ -f "/tmp/artefacts/packages-integrity-deb" ] && grep -F "${path}" /tmp/artefacts/packages-integrity-deb > /dev/null
    then
      KEEPP=1
    fi
    if [ -f "/tmp/artefacts/packages-integrity-rpm" ] && grep -F "${path}" /tmp/artefacts/packages-integrity-rpm > /dev/null
    then
      KEEPP=1
    fi
    if [ $KEEPP == 1 ]
    then
      size=$(du -m "${path}" | cut -f 1)
      if [ $size -le $EXTRACT_MAXSIZE ]; then
        tar vuf /tmp/artefacts/yara_file.tar $path
      fi
      if [ ! -x "$(which md5sum)" ]; then
        md5sum $path >> /tmp/artefacts/yara_file_hash
      fi
    fi
  done
fi
gzip /tmp/artefacts/yara_file.tar
#clean
if [ $OS == 1 ]; then tar zcvpf /tmp/artefacts-$(hostname).tgz /tmp/artefacts/;fi
if [ $OS == 2 ]; then tar cpvf - /tmp/artefacts/ |gzip -c >/tmp/artefacts-$(hostname).tgz;fi
#encrypt result
if [ -x "$(which openssl)" ] && [ -f "/tmp/toolsEAL/tools/pub_key" ]
then
  openssl smime -encrypt -binary -aes-256-cbc -in /tmp/artefacts-$(hostname).tgz -out /tmp/artefacts-$(hostname).tgz.enc -outform DER /tmp/toolsEAL/tools/pub_key
  #decrypt: openssl smime -decrypt -in file.tgz.enc -binary -inform DEM -inkey orc-key.pem -out file.tgz
  if [ $? -eq 0 ]
  then
    rm -f /tmp/artefacts-$(hostname).tgz 
  fi
fi
rm -rf /tmp/artefacts/

