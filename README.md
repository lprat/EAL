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
- log
  - /var/log/
  - /run/log/
  - all files with end *.log.*
- etc (all)
- network
  - lsof
  - netstat
  - route
  - rpcinfo
  - identify promiscous mode
  - make relation with files (1)
- process
  - ps
  - /proc/*/fd|exe
  - ldd
  - handle (lsof)
  - make relation with files (1)
- kernel 
  - modules list
  - sysctl 
- files (1)
  - ls
  - type (cmd file)
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


## TODO
- Memory RAM & Swap extract option

## Usage

### Extract artefacts

~~~
$bash -x extract-artefacts.sh 2> extract.log

OR

$URL_GENERIC=http://localnet.local/GENERIC bash -x extract-artefacts.sh 2> extract.log
~~~
Take file: /tmp/artefacts-$(hostname).tgz & extract.log

### Create timeline

~~~
$python3 create_timeline.py dir_artefac_extract/

~~~
Take file: timeline.jsonl and import in timesketch!

## Requirements

- python3: json

## Contact

lionel.prat9 (at) gmail.com
