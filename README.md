# Extract Artefacts Linux for forensic (EAL)
*Extract Artefacts Linux for forensic and create timeline.*

This tool written in bash for extract artefacts, and python(v3) for create timeline in format json. You can import timeline in timesketch to explore!

## Features
- General info
  - uptime
  - user list
  - /etc/passwd date last write
  - /etc/hosts
- home
  - history file
  - known_hosts
  - hidden file
  - ssh keys date
  - browser 
  - cache
- docker
  - json & og
- virsh
  - list vm
- log
  - /var/log/
  - /run/log/
  - all files with end *.log.*
- Mysql
  - Logs files: *.frm, ibdata* 
- etc (all)
- network
  - lsof
  - netstat
  - route
  - rpcinfo
  - identify promiscous mode
  - make relation with files (1)
  - iptables rules
  - arp
  - check dns access
  - internet access
  - ping (google)
  - check ip public output
- process
  - ps
  - /proc/*/fd|exe
  - ldd
  - handle (lsof)
  - make relation with files (1)
- kernel 
  - modules list
  - sysctl
  - /proc/sys artefacts
- files (1)
  - stat or ls
  - type (cmd file)
  - md5sum (slow)
  - deleted files (slow)
- Packages
  - integrity
  - list
  - make relation with files (1)
- autorun
  - systemd
  - init.d
  - rc.local
  - make relation with files (1)
- trap
  - list
- env
  - list
- clipboard
  - display
- mouted
  - list
  - memory space
- crontab
  - list & extract
- sudoers
  - list
- user log
  - last command display
  - who command display  
- CVE check: use https://security-tracker.debian.org/tracker/debsecan/release/1/GENERIC, you can copy on local network (change URL_GENERIC env)

## Usage

### Make custom package
Build a custom script to extract artefacts from linux. Use Dockerfile (require docker: https://docs.docker.com/engine/install/debian/).  
You can cutom to:  
  - edit EAL.config file to configure extracted data
  - use pub key to encrypt result extracted
  - use dump memory (avml: https://github.com/microsoft/avml), if dump not work you can extract process memory
  - use yara scan process and/or file with custom and/or community rules (use spyre: https://github.com/spyre-project/spyre)
~~~
$git clone https://github.com/lprat/EAL/
$cd EAL
$vi EAL.config
$cd build
$docker build -t package_eal .
#to get options:
$docker run --rm -v $(pwd)/output:/tmp/output -v $(pwd)/../EAL.config:/conf/EAL.config -ti package_eal -h 
~~~
Script custom out in output directory, you can copy to the scan linux.  


### Extract artefacts

~~~
$bash -x extract-artefacts.sh > extract.log 2>&1

OR

$URL_GENERIC=http://localnet.local/GENERIC bash -x extract-artefacts.sh 2> extract.log
~~~
Take file: /tmp/artefacts-$(hostname).tgz & extract.log

### Create timeline

- Use script create_timeline.py for make timeline on relation between file - process - package - network - module kernel loaded - crontab - autorun
- Use plaso on files: apache, systemd, syslog, dpkg, apt history, popularity contest on debian, wtmp, docker conf & log, selinux, vsftpd, webhist.
  - bash_history not parsed by plaso if you haven't defined HISTTIMEFORMAT
  - apache error log not parsed by plaso
  
~~~
#if you use crypt archive: uncrypt.py key.pem artefacts-*.tgz.enc artefacts.tgz && tar -zxf artefacts.tgz
$python3 create_timeline.py dir_artefac_extract/
cd dir_artefac_extract/;for i in $(ls *.t*gz);do tar -zxf $i;done;find . -name "*.gz" | xargs gunzip;cd ..
docker pull log2timeline/plaso
docker run --rm -v /data/:/data/ log2timeline/plaso log2timeline.py /data/artefacts_tl.plaso /data/artefacts/
docker run --rm -v /data/:/data/ log2timeline/plaso psort.py -o null --analysis tagging --tagging-file /data/tag_linux.txt /data/artefacts_tl.plaso
#import in timesketch (docker exec -ti docker_timesketch_1 bash)
tsctl import --file /data/artefacts_tl.plaso --username your_user --timeline_name artefac_extract_events
tsctl import --file timeline.jsonl --username your_user --timeline_name artefac_extract_files
~~~

### Timesketch queries
(Lucene query: https://lucene.apache.org/core/2_9_4/queryparsersyntax.html)  

 - select just file
~~~
file_entry_type: file
~~~
 - Use date (if you known the date of the incident)
 - Use file type (if you search specialy file type: cmd file)
~~~
file_type: *static*
~~~
 - Use file stat type (find rare types)
~~~
file_stattype: [1 TO 5] 
~~~
 - Use file extension (if you search specialy file extension: *.php)
~~~
file_ext: php
~~~
 - Use file stat extension (find rare extension)
~~~
file_statext: [1 TO 5] 
~~~
 - Use file name (if you search specialy file name: backdoor)
~~~
file_name: x.*
file_name_withoutext: x
~~~
 - Use file stat filename (find rare filename)
~~~
file_statname: [1 TO 5] 
~~~
 - Use file name suspect 
~~~
tag: suspect_filename
~~~
 - Use file path (if you search specialy file path: )
~~~
file_path: *upload*
~~~
 - Use file stat path (find rare path use)
~~~
file_statpath: [1 TO 5] 
~~~
 - Use file path suspect name
~~~
tag: suspect_pathname
~~~
 - Use file size (in bytes)
~~~
file_sizeint: [1024 TO 2048]
~~~
 - Use owner (if you known user compromised)
~~~
file_owner: user
~~~
 - Use md5sum (the value cannot extracted by default)
~~~
md5sum: md5sum
~~~
 - use package relation
~~~
file_pkgrpm: *ssh*
file_pkgdeb: *ssh*
file_pkgaix: *ssh*
~~~
 - Use tags
~~~
# Event with tag
_exists_:tag
#Event with tag "static_exe" - can indicate backdoor compiled static
tag: static_exe
#Event with tag "filelink" (use with time)
tag: filelink
#Event with tag "file_etc" (use with time)
tag: file_etc
#Event with tag "docker_conf" (use with time)
tag: docker_conf
#Event with tag "file_cfg" (use with time)
tag: file_cfg
#Event with tag "file_history" (ex: bash_history, mysql_history, ...)
tag: file_history
#Event with tag "file_browser" (ex: cache browser)
tag: file_browser
#Event with tag "file_hidden" (depending on the path may be suspect or use with time)
tag: file_hidden
#Event with tag "file_service" (use with time)
tag: file_service
#Event with tag "file_executable" (use with time or path)
tag: file_executable
#Event with tag "executable_nocommun_path" (suspect path for executable)
tag: executable_nocommun_path
#Event with tag "file_suid_guid" (use with time or right ...)
tag: file_suid_guid
#Event with tag "file_writable" (file writable by everybody -> wanring if used in cron/conf/suid/log/....)
tag: file_writable
#Event with tag "file_unknown_owner" (may be suspect)
tag: file_unknown_owner
#Event with tag "file_space_end" (may be used for exploit user: https://attack.mitre.org/techniques/T1036/006/)
tag: file_space_end
#Event with tag "file_from_package" (file from package)
tag: file_from_package
#Event with tag "file_cve" (file from package content CVE vuln)
tag: file_cve
#Event with tag "file_pb_pkg_integrity" (file package integrity error)
tag: file_pb_pkg_integrity
#Event with tag "file_kernelmodule" (file kernel module loaded)
tag: file_kernelmodule
#Event with tag "file_crontab" (file used in crontab
tag: file_crontab
#Event with tag "file_env" (file used in env)
tag: file_env
#Event with tag "file_tmpfs" (file in tmpfs +x => suspect)
tag: file_tmpfs
#Event with tag "file_network" (file used in process create network connexion)
tag: file_network
#Event with tag "file_pid" (file used in process)
tag: file_pid
#Event with tag "file_ldd" (file library used in process
tag: file_ldd
#Event with tag "file_fd" (file used by process)
tag: file_fd
#Event with tag "file_lsof" (file used by process)
tag: file_lsof
#Event with tag "file_ps" (file runned)
tag: file_ps
~~~
## Requirements

- python3: json  

## Externals tools or data used in EAL
  - https://github.com/spyre-project/spyre
  - https://github.com/Hestat/lw-yara
  - https://github.com/Yara-Rules/rules
  - https://github.com/gabrielbouzard/yara-linux-malware
  - https://github.com/airbnb/binaryalert
  - https://github.com/tenable/yara-rules 
  - https://github.com/reversinglabs/reversinglabs-yara-rules/tree/develop/yara 
  - https://github.com/ForensicArtifacts/artifacts/tree/master/data
  - https://github.com/InQuest/awesome-yara
  - https://github.com/microsoft/avml
  - https://github.com/InQuest/awesome-yara
  - https://github.com/plyara/plyara
  
Thank to the community.

## TODO
- Swap extract option

## Contact

lionel.prat9 (at) gmail.com
