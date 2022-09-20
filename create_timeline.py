#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Create Json timeline from linux/aix artefacts - Import in TimeSketch !!
# (c) 2019 - 2022, Lionel PRAT <lionel.prat9 (at) gmail.com>
#TODO:
# add tag in file for:
# - type =! ext =! entropy
#   create stat on type and entropy, get moy and identify file > moy
#   create stat of file type uniq & sort
# - md5sum malicious (source: MISP, Threat Intel)
# - much io/fd use
import sys
import os
import json
import re
from datetime import datetime, timedelta;

#convert mounth to number "Jan" "Feb" "Mar" "Apr" "May" "Jun" "Jul" "Aug" "Sep" "Oct" "Nov" "Dec"
# "janv." "févr." "mars"  "avr."  "mai"   "juin"  "juil." "août"  "sept." "oct."  "nov."  "déc."


def main():
    print("Create Json timeline from linux/aix artefacts by lionel.prat9 (at) gmail.com\n")
    if len(sys.argv) != 2:
        print("Usage: ./create_timeline.py dir_artefac_extract/\n")
        sys.exit()
    print("Wait finish parsing...\n")
    filepath = sys.argv[1]
    
    ##############
    debug=True
    find='/all_files'
    find_file='/all_files_file' #aix case
    package_list_deb='/packages_deb-list_files'
    package_list_rpm='/packages_rpm-list_files'
    package_list_aix='/packages_aix-list_files'
    kernel_module_file='/kernel_modules'
    crontab_file='/crontab'
    env_file='/env'
    tmpfs_file='/disk_mount'
    networks_file='/network'
    package_list_deb_int='/packages-integrity-deb'
    package_list_rpm_int='/packages-integrity-rpm' #http://ftp.rpm.org/max-rpm/s1-rpm-verify-output.html
    proccksum_file='/process_cksum'
    process_faout_file='/process_faout'
    procexe_file='/process_exe'
    procldd_file='/process_ldd'
    procfd_file='/process_fd'
    proclsof_file='/process_lsof'
    procps_file='/process_ps'
    systemd_file='service-systemd'
    initd_file='/services-initd_exe'
    aix_services='/services'
    package_cve_deb_file='/debsecan'
    package_cve_rpm_file='/yum-security'
    hostname_file='/general'
    sudoers_file='/sudoers'
    ##############
    if not os.path.isdir(filepath):
        print("Directory path {} does not exist.".format(filepath))
        sys.exit()
    #now
    now = datetime.now()
    #GET HOSTNAME
    hostname = ""
    if not os.path.isfile(filepath+hostname_file):
        print("File extracted hostname {} does not exist.".format(filepath+hostname_file))
    else:
        print("Extract info hostname...")
        with open(filepath+hostname_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            get=False
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r")
                if get:
                    hostname=tmp.strip()
                    print("Hostname is {}".format(hostname))
                    break
                if tmp.startswith('host:'):
                    get=True

    #DEB PACKAGES LIST CVE
    package_cve_deb = []
    if not os.path.isfile(filepath+package_cve_deb_file):
        print("File extracted package list DEB CVE {} does not exist.".format(filepath+package_cve_deb_file))
    else:
        print("Extract info package DEB CVE")
        with open(filepath+package_cve_deb_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            package_current=''
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if len(tmp) > 1:
                    if not tmp[1] in package_cve_deb:
                        package_cve_deb.append(tmp[1])
        if debug:
            with open('result-debcve.json', 'w') as fp:
                json.dump(package_cve_deb, fp, indent=4)
    #DEB PACKAGES LIST
    package_files_deb_service = []
    package_files_deb = {}
    if not os.path.isfile(filepath+package_list_deb):
        print("File extracted package list DEB {} does not exist.".format(filepath+package_list_deb))
    else:
        print("Extract info package DEB")
        with open(filepath+package_list_deb, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            package_current=''
            cve=False
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                if line.startswith('Package Name:'):
                    rtmp=line.split(':')
                    if rtmp and len(rtmp) > 1:
                        package_current=rtmp[1].strip()
                elif '/.' == line:
                    continue
                else:
                    #verify service in package
                    if line.rstrip("\n\r").startswith('/etc/rc') or line.rstrip("\n\r").startswith('/etc/systemd/') or line.rstrip("\n\r").startswith('/etc/init.d/') or line.rstrip("\n\r").startswith('/etc/xinet') or line.rstrip("\n\r").startswith('/etc/rc.d/init.d/'):
                        if not package_current in package_files_deb_service:
                            package_files_deb_service.append(package_current)
                    if line.rstrip("\n\r") in package_files_deb:
                        package_files_deb[line.rstrip("\n\r")]=[package_current]+package_files_deb[line.rstrip("\n\r")]
                    else:
                        package_files_deb[line.rstrip("\n\r")]=[package_current]
        if debug:
            with open('result-deb.json', 'w') as fp:
                json.dump(package_files_deb, fp, indent=4)
    
    #DEB PACKAGES LIST INTEGRITY
    package_files_deb_int = []
    if not os.path.isfile(filepath+package_list_deb_int):
        print("File extracted package list DEB integrity {} does not exist.".format(filepath+package_list_deb_int))
    else:
        print("Extract info package DEB integrity ")
        with open(filepath+package_list_deb_int, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            package_current=''
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if len(tmp) == 3:
                    if not tmp[2] in package_files_deb_int:
                        package_files_deb_int.append(tmp[2])
                elif len(tmp) == 2:
                    if tmp[1].startswith('/') and not tmp[1] in package_files_deb_int:
                        package_files_deb_int.append(tmp[1])
        if debug:
            with open('result-debint.json', 'w') as fp:
                json.dump(package_files_deb_int, fp, indent=4)

    #RPM PACKAGES LIST CVE
    package_cve_rpm = []
    if not os.path.isfile(filepath+package_cve_rpm_file):
        print("File extracted package list RPM CVE {} does not exist.".format(filepath+package_cve_rpm_file))
    else:
        print("Extract info package RPM CVE")
        with open(filepath+package_cve_rpm_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            package_current=''
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if len(tmp) > 2 and 'security'  in tmp[1]:
                    if not tmp[2] in package_cve_rpm:
                        package_cve_rpm.append(tmp[2])
        if debug:
            with open('result-rpmcve.json', 'w') as fp:
                json.dump(package_cve_rpm, fp, indent=4)
    #RPM PACKAGES LIST
    package_files_rpm = {}
    package_files_rpm_service = []
    if not os.path.isfile(filepath+package_list_rpm):
        print("File extracted package list RPM {} does not exist.".format(filepath+package_list_rpm))
    else:
        print("Extract info package RPM")
        with open(filepath+package_list_rpm, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                if line.startswith('Package Name:'):
                    rtmp=line.split(':')
                    if rtmp and len(rtmp) > 1:
                        package_current=rtmp[1].strip()
                else:
                    #verify service in package
                    if line.rstrip("\n\r").startswith('/etc/rc') or line.rstrip("\n\r").startswith('/etc/systemd/') or line.rstrip("\n\r").startswith('/etc/init.d/') or line.rstrip("\n\r").startswith('/etc/xinet') or line.rstrip("\n\r").startswith('/etc/rc.d/init.d/'):
                        if not package_current in package_files_rpm_service:
                            package_files_rpm_service.append(package_current)
                    if line.rstrip("\n\r") in package_files_rpm:
                        package_files_rpm[line.rstrip("\n\r")]=[package_current]+package_files_rpm[line.rstrip("\n\r")]
                    else:
                        package_files_rpm[line.rstrip("\n\r")]=[package_current]
        if debug:
            with open('result-rpm.json', 'w') as fp:
                json.dump(package_files_rpm, fp, indent=4)
    
    #RPM PACKAGES LIST INTEGRITY - http://ftp.rpm.org/max-rpm/s1-rpm-verify-output.html
    package_files_rpm_int = []
    if not os.path.isfile(filepath+package_list_rpm_int):
        print("File extracted package list RPM integrity {} does not exist.".format(filepath+package_list_rpm_int))
    else:
        print("Extract info package RPM integrity ")
        with open(filepath+package_list_rpm_int, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if len(tmp) == 3:
                    if tmp[2].startswith('/') and not tmp[2] in package_files_rpm_int:
                        package_files_rpm_int.append(tmp[2])
                elif len(tmp) == 2:
                    if tmp[1].startswith('/') and not tmp[1] in package_files_rpm_int:
                        package_files_rpm_int.append(tmp[1])
        if debug:
            with open('result-rpmint.json', 'w') as fp:
                json.dump(package_files_rpm_int, fp, indent=4)
                
    #AIX PACKAGES LIST
    package_files_aix = {}
    package_files_aix_service = []
    if not os.path.isfile(filepath+package_list_aix):
        print("File extracted package list AIX {} does not exist.".format(filepath+package_list_aix))
    else:
        print("Extract info package AIX")
        with open(filepath+package_list_aix, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            package_current=''
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                if line.startswith('Package Name:'):
                    rtmp=line.split(':')
                    if rtmp and len(rtmp) > 1:
                        package_current=rtmp[1].strip()
                else:
                    tmp=line.rstrip("\n\r").strip()
                    if tmp.startswith('Path:') or tmp.startswith('----') or tmp.startswith('Fileset') or tmp.startswith('NONE'):
                        continue
                    else:
                        if tmp.startswith('/'):
                            if ' -> ' in tmp:
                                ftmp=tmp.split(' -> ')
                                #verify service in package
                                if ftmp[0].startswith('/etc/rc') or ftmp[0].startswith('/etc/systemd/') or ftmp[0].startswith('/etc/init.d/') or ftmp[0].startswith('/etc/xinet') or ftmp[0].startswith('/etc/rc.d/init.d/') or ftmp[1].startswith('/etc/rc') or ftmp[1].startswith('/etc/systemd/') or ftmp[1].startswith('/etc/init.d/') or ftmp[1].startswith('/etc/xinet') or ftmp[1].startswith('/etc/rc.d/init.d/'):
                                    if not package_current in package_files_aix_service:
                                        package_files_aix_service.append(package_current)
                                if ftmp[0] in package_files_aix:
                                    package_files_aix[ftmp[0]]=[package_current]+package_files_aix[ftmp[0]]
                                else:
                                    package_files_aix[ftmp[0]]=[package_current]
                                if ftmp[1] in package_files_aix:
                                    package_files_aix[ftmp[1]]=[package_current]+package_files_aix[ftmp[1]]
                                else:
                                    package_files_aix[ftmp[1]]=[package_current]
                            else:
                                #verify service in package
                                if tmp.startswith('/etc/rc') or tmp.startswith('/etc/systemd/') or tmp.startswith('/etc/init.d/') or tmp.startswith('/etc/xinet') or tmp.startswith('/etc/rc.d/init.d/'):
                                    if not package_current in package_files_aix_service:
                                        package_files_aix_service.append(package_current)
                                if tmp in package_files_aix:
                                    package_files_aix[tmp]=[package_current]+package_files_aix[tmp]
                                else:
                                    package_files_aix[tmp]=[package_current]
                        elif '/' in tmp:
                            tmpx=tmp.split('/')
                            tmp='/'+'/'.join(tmpx[1:])
                            if ' -> ' in tmp:
                                ftmp=tmp.split(' -> ')
                                #verify service in package
                                if ftmp[0].startswith('/etc/rc') or ftmp[0].startswith('/etc/systemd/') or ftmp[0].startswith('/etc/init.d/') or ftmp[0].startswith('/etc/xinet') or ftmp[0].startswith('/etc/rc.d/init.d/') or ftmp[1].startswith('/etc/rc') or ftmp[1].startswith('/etc/systemd/') or ftmp[1].startswith('/etc/init.d/') or ftmp[1].startswith('/etc/xinet') or ftmp[1].startswith('/etc/rc.d/init.d/'):
                                    if not package_current in package_files_aix_service:
                                        package_files_aix_service.append(package_current)
                                if ftmp[0] in package_files_aix:
                                    package_files_aix[ftmp[0]]=[package_current]+package_files_aix[ftmp[0]]
                                else:
                                    package_files_aix[ftmp[0]]=[package_current]
                                if ftmp[1] in package_files_aix:
                                    package_files_aix[ftmp[1]]=[package_current]+package_files_aix[ftmp[1]]
                                else:
                                    package_files_aix[ftmp[1]]=[package_current]
                            else:
                                #verify service in package
                                if tmp.startswith('/etc/rc') or tmp.startswith('/etc/systemd/') or tmp.startswith('/etc/init.d/') or tmp.startswith('/etc/xinet') or tmp.startswith('/etc/rc.d/init.d/'):
                                    if not package_current in package_files_aix_service:
                                        package_files_aix_service.append(package_current)
                                if tmp in package_files_aix:
                                    package_files_aix[tmp]=[package_current]+package_files_aix[tmp]
                                else:
                                    package_files_aix[tmp]=[package_current]
        if debug:
            with open('result-aix.json', 'w') as fp:
                json.dump(package_files_aix, fp, indent=4)
    
    #AIX integrity TODO!
    
    #kernel module loaded
    kernel_modules = []
    if not os.path.isfile(filepath+kernel_module_file):
        print("File extracted kernel modules loaded{} does not exist.".format(filepath+kernel_module_file))
    else:
        print("Extract info kernel modules loaded")
        with open(filepath+kernel_module_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                if line.startswith('/'):
                    kernel_modules.append(line.rstrip("\n\r"))
                elif '/' in line:
                    #genkex AIX
                    tmpx=line.rstrip("\n\r").split('/')
                    kernel_modules.append('/'+'/'.join(tmpx[1:]))
        if debug:
            with open('result-kernelmodules.json', 'w') as fp:
                json.dump(kernel_modules, fp, indent=4)
    #sudoers_file
    sudoers = []
    if not os.path.isfile(filepath+sudoers_file):
        print("File extracted sudoers call {} does not exist.".format(filepath+sudoers_file))
    else:
        print("Extract info sudoers call")
        with open(filepath+sudoers_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            user_current=''
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if tmp and len(tmp) > 5:
                    for fpat in tmp[5:]:
                        if fpat.startswith('/') or fpat.startswith('./') or fpat.startswith('../'):
                            if not fpat in sudoers:
                                sudoers.append(fpat) 
        if debug:
            with open('result-sudoers.json', 'w') as fp:
                json.dump(sudoers, fp, indent=4)     
    #crontab
    crontab = {}
    if not os.path.isfile(filepath+crontab_file):
        print("File extracted crontab call {} does not exist.".format(filepath+crontab_file))
    else:
        print("Extract info crontab call")
        with open(filepath+crontab_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            user_current=''
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                if line.startswith('Crontab user:'):
                    rtmp=line.split(':')
                    if rtmp and len(rtmp) > 1:
                        user_current=rtmp[1].strip()
                else:
                    tmp=line.rstrip("\n\r").split()
                    if tmp and len(tmp) > 5:
                        for fpat in tmp[5:]:
                            if fpat.startswith('/') or fpat.startswith('./') or fpat.startswith('../'):
                                if fpat in crontab:
                                    if not user_current in crontab[fpat]:
                                        crontab[fpat]=[user_current]+crontab[fpat]
                                else:
                                    crontab[fpat]=[user_current]
        if debug:
            with open('result-crontab.json', 'w') as fp:
                json.dump(crontab, fp, indent=4) 
    #env
    envar = {}
    if not os.path.isfile(filepath+env_file):
        print("File extracted env var {} does not exist.".format(filepath+env_file))
    else:
        print("Extract info env var")
        with open(filepath+env_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                if '=' in line:
                    tmp=line.rstrip("\n\r").split('=')
                    if tmp and len(tmp) > 1:
                        var_current=tmp[0]
                        tmpx=tmp[1].split(':')
                        for tmpy in tmpx:
                            tmpz=tmpy.split()
                            for fpat in tmpz:
                                if fpat.startswith('/') or fpat.startswith('./') or fpat.startswith('../'):
                                    fpat.split()
                                    if fpat in envar:
                                        if not var_current in envar[fpat]:
                                            envar[fpat]=[var_current]+envar[fpat]
                                    else:
                                        envar[fpat]=[var_current]
        if debug:
            with open('result-env.json', 'w') as fp:
                json.dump(envar, fp, indent=4) 
    
    #tmpfs
    tmpfs = []
    if not os.path.isfile(filepath+tmpfs_file):
        print("File extracted tmpfs file {} does not exist.".format(filepath+tmpfs_file))
    else:
        print("Extract info tmpfs file")
        with open(filepath+tmpfs_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            mode = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                if ' tmpfs ' in line and not ',noexec,' in line:
                    tmp=line.rstrip("\n\r").split()
                    if tmp and len(tmp) > 1:
                        for fpat in tmp:
                            if fpat.startswith('/'):
                                if not fpat in tmpfs:
                                    tmpfs.append(fpat)
        if debug:
            with open('result-tmpfs.json', 'w') as fp:
                json.dump(tmpfs, fp, indent=4)     
    #network
    networks = []
    if not os.path.isfile(filepath+networks_file):
        print("File extracted network informations {} does not exist.".format(filepath+networks_file))
    else:
        print("Extract info network informations")
        with open(filepath+networks_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if len(tmp) > 8 and ('TCP' in line or 'UDP' in line):
                    if not tmp[1] in networks:
                        networks.append(tmp[1])
        if debug:
            with open('result-net.json', 'w') as fp:
                json.dump(networks, fp, indent=4) 
    
    #process exe
    procexe = {}
    if not os.path.isfile(filepath+procexe_file):
        print("File extracted process exe {} does not exist.".format(filepath+procexe_file))
    else:
        print("Extract info process exe")
        with open(filepath+procexe_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if len(tmp) == 11 and ' -> ' in line:
                    #extract pid
                    if '/proc/' in tmp[8]:
                        pidx=tmp[8].split('/')
                        if len(pidx) == 4:
                            pid=pidx[2]
                            if tmp[10] in procexe:
                                if not pid in procexe[tmp[10]]:
                                    procexe[tmp[10]]=procexe[tmp[10]]+[pid]
                            else:
                                procexe[tmp[10]]=[pid]
        if debug:
            with open('result-procexe.json', 'w') as fp:
                json.dump(procexe, fp, indent=4)
    process_faout_file
    
    #process aout use procexe var
    if not os.path.isfile(filepath+process_faout_file):
        print("File extracted process aout {} does not exist.".format(filepath+process_faout_file))
    else:
        print("Extract info process aout")
        with open(filepath+process_faout_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if ':' in tmp[0]:
                    if tmp[0][0:-1].isdigit():
                        pid=tmp[0][0:-1]
                        for fpat in tmp[1:]:
                            if fpat.startswith('/'):
                                if fpat in procexe:
                                    if not pid in procexe[fpat]:
                                        procexe[fpat]=procexe[fpat]+[pid]
                                    else:
                                        procexe[fpat]=[pid]
        if debug:
            with open('result-procaout.json', 'w') as fp:
                json.dump(procexe, fp, indent=4)

    #process ldd
    procldd = {}
    if not os.path.isfile(filepath+procldd_file):
        print("File extracted process ldd {} does not exist.".format(filepath+procldd_file))
    else:
        print("Extract info process ldd")
        with open(filepath+procldd_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            current_pid=''
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                if ':' in line:
                    pidx=line.split(':')
                    if len(pidx) == 2:
                        current_pid=pidx[0]
                elif line.startswith('/'):
                    fpat=line.rstrip("\n\r")
                    #aix case
                    if fpat.endswith(']'):
                        tmpz=line.split('[')
                        fpat=tmpz[0]
                    if fpat in procldd:
                        if not current_pid in procldd[fpat]:
                            procldd[fpat]=procldd[fpat]+[current_pid]
                    else:
                        procldd[fpat]=[current_pid]
        if debug:
            with open('result-procldd.json', 'w') as fp:
                json.dump(procldd, fp, indent=4) 
    
    #process fd
    procfd = {}
    if not os.path.isfile(filepath+procfd_file):
        print("File extracted process fd {} does not exist.".format(filepath+procfd_file))
    else:
        print("Extract info process fd")
        with open(filepath+procfd_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            current_pid=''
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                if line.startswith('/proc/') and line.rstrip("\n\r").endswith(':'):
                    pidx=line.rstrip("\n\r").split('/')
                    if len(pidx) == 4:
                        current_pid=pidx[2]
                elif ' -> ' in line:
                    tmp=line.rstrip("\n\r").split(' -> ')
                    if tmp and tmp[-1].startswith('/'):
                        fpat=tmp[-1]
                        if fpat in procfd:
                            if not current_pid in procfd[fpat]:
                                procfd[fpat]=procfd[fpat]+[current_pid]
                        else:
                            procfd[fpat]=[current_pid]
        if debug:
            with open('result-procfd.json', 'w') as fp:
                json.dump(procfd, fp, indent=4)
    
    #process lsof
    proclsof = {}
    if not os.path.isfile(filepath+proclsof_file):
        print("File extracted process lsof {} does not exist.".format(filepath+proclsof_file))
    else:
        print("Extract info process lsof")
        with open(filepath+proclsof_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if tmp[1].isdigit() and tmp[-1].startswith('/') and len(tmp[-1]) > 1:
                    pid=tmp[1]
                    fpat=tmp[-1]
                    if fpat in proclsof:
                        if not pid in proclsof[fpat]:
                            proclsof[fpat]=proclsof[fpat]+[pid]
                    else:
                        proclsof[fpat]=[pid]
        if debug:
            with open('result-proclsof.json', 'w') as fp:
                json.dump(proclsof, fp, indent=4)

    #services aix - pid
    aixservices = []
    if not os.path.isfile(filepath+aix_services):
        print("File extracted Aix Services {} does not exist.".format(filepath+aix_services))
    else:
        print("Extract info Aix Services")
        with open(filepath+aix_services, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if len(tmp) == 4 and tmp[2].isdigit():
                    if not tmp[2] in aixservices:
                        aixservices.append(tmp[1])     
        if debug:
            with open('result-aixservices.json', 'w') as fp:
                json.dump(aixservices, fp, indent=4)

    #process cksum
    proccksum = {}
    if not os.path.isfile(filepath+proccksum_file):
        print("File extracted process cksum {} does not exist.".format(filepath+proccksum_file))
    else:
        print("Extract info process cksum")
        with open(filepath+proccksum_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if len(tmp) == 3 and '/proc/' in tmp[-1]:
                    #extract pid
                    pidx=tmp[-1].split('/')
                    if len(pidx) == 5:
                        pid=pidx[2]
                        tmpf=tmp[0]+' '+tmp[1]
                        if tmpf in proccksum:
                            if not pid in proccksum[tmpf]:
                                proccksum[tmpf]=proccksum[tmpf]+[pid]
                        else:
                            proccksum[tmpf]=[pid]
        if debug:
            with open('result-proccksum.json', 'w') as fp:
                json.dump(proccksum, fp, indent=4)

    #process ps
    procps = {}
    if not os.path.isfile(filepath+procps_file):
        print("File extracted process ps {} does not exist.".format(filepath+procps_file))
    else:
        print("Extract info process ps")
        with open(filepath+procps_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if tmp[1].isdigit():
                    pid=tmp[1]
                    for fpat in tmp:
                        if fpat.startswith('/') and len(fpat) > 1:
                            if fpat in procps:
                                if not pid in procps[fpat]:
                                    procps[fpat]=procps[fpat]+[pid]
                            else:
                                procps[fpat]=[pid]
                #aix case
                elif tmp[4].isdigit():
                    pid=tmp[4]
                    for fpat in tmp:
                        if fpat.startswith('/') and len(fpat) > 1:
                            if fpat in procps:
                                if not pid in procps[fpat]:
                                    procps[fpat]=procps[fpat]+[pid]
                            else:
                                procps[fpat]=[pid]
        if debug:
            with open('result-procps.json', 'w') as fp:
                json.dump(procps, fp, indent=4)
  
    #systemd file
    systemd = []
    if not os.path.isfile(filepath+systemd_file):
        print("File extracted systemd files {} does not exist.".format(filepath+systemd_file))
    else:
        print("Extract info systemd files")
        with open(filepath+systemd_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split()
                if len(tmp) == 2 and tmp[1].startswith('/'):
                    if not tmp[1] in systemd:
                        systemd.append(tmp[1])     
        if debug:
            with open('result-systemd.json', 'w') as fp:
                json.dump(systemd, fp, indent=4)
    #initd file
    initd = []
    if not os.path.isfile(filepath+initd_file):
        print("File extracted initd files {} does not exist.".format(filepath+initd_file))
    else:
        print("Extract info inetd files")
        with open(filepath+initd_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                tmp=line.rstrip("\n\r").split('=')
                if len(tmp) == 2:
                    if tmp[1].startswith('"/'):
                        tmpx=tmp[1].split('"')
                        if not "$" in tmpx[1] and not tmpx[1] in initd:
                            initd.append(tmpx[1]) 
                    elif tmp[1].startswith('/') and not "$" in tmp[1]:
                        if not tmp[1] in initd:
                            initd.append(tmp[1])     
        if debug:
            with open('result-initd.json', 'w') as fp:
                json.dump(initd, fp, indent=4)
    #FIND            
    stat_type={}
    stat_ext={}
    stat_filename={}
    stat_path={}
    stat_filenamewithoutext={}
    files = {}
    if not os.path.isfile(filepath+find_file):
        print("File extracted find file aix {} does not exist.".format(filepath+find_file))
    else:    
        with open(filepath+find_file, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                if line.startswith('/'):
                    #type result
                    #print("TYPE: line {} contents {}".format(cnt, line))
                    rtmp=line.split(': ')
                    if rtmp and len(rtmp) > 1 and not 'ERROR: cannot read' in ': '.join(rtmp[1:]).rstrip("\n\r").strip():
                        if rtmp[0] in files:
                            files[rtmp[0]]['type'] = ': '.join(rtmp[1:]).rstrip("\n\r").strip()
                        else:
                            files[rtmp[0]] = {'type': ': '.join(rtmp[1:]).rstrip("\n\r").strip()}
                        if 'statically linked' in ': '.join(rtmp[1:]).rstrip("\n\r").strip():
                            files[rtmp[0]]['static_executable'] = True
                        if ': '.join(rtmp[1:]).rstrip("\n\r").strip() in stat_type:
                            stat_type[': '.join(rtmp[1:]).rstrip("\n\r").strip()]=stat_type[': '.join(rtmp[1:]).rstrip("\n\r").strip()]+1
                        else:
                            stat_type[': '.join(rtmp[1:]).rstrip("\n\r").strip()]=1
    if not os.path.isfile(filepath+find):
        print("File extracted find {} does not exist.".format(filepath+find))
    else:
        with open(filepath+find, encoding="utf-8", errors='ignore') as fp:
            cnt = 0
            current_file=''
            for line in fp:
                #print("line {} contents {}".format(cnt, line))
                if line.startswith('\''):
                    #entropy result
                    #print("ENT: line {} contents {}".format(cnt, line))
                    rtmp=line.split('\'')
                    if rtmp and len(rtmp) == 4:
                        if rtmp[1] in files:
                            files[rtmp[1]]['entropy'] = rtmp[3]
                        else:
                            files[rtmp[1]] = {'entropy': rtmp[3]}
                elif line.startswith('/'):
                    #type result
                    #print("TYPE: line {} contents {}".format(cnt, line))
                    rtmp=line.split(': ')
                    if rtmp and len(rtmp) > 1 and not ('ERROR: cannot read' in ': '.join(rtmp[1:]).rstrip("\n\r").strip() or 'cannot open' in ': '.join(rtmp[1:]).rstrip("\n\r").strip()):
                        if rtmp[0] in files:
                            files[rtmp[0]]['type'] = ': '.join(rtmp[1:]).rstrip("\n\r").strip()
                        else:
                            files[rtmp[0]] = {'type': ': '.join(rtmp[1:]).rstrip("\n\r").strip()}
                        if 'statically linked' in ': '.join(rtmp[1:]).rstrip("\n\r").strip():
                            files[rtmp[0]]['static_executable'] = True
                        if ': '.join(rtmp[1:]).rstrip("\n\r").strip() in stat_type:
                            stat_type[': '.join(rtmp[1:]).rstrip("\n\r").strip()]=stat_type[': '.join(rtmp[1:]).rstrip("\n\r").strip()]+1
                        else:
                            stat_type[': '.join(rtmp[1:]).rstrip("\n\r").strip()]=1
                elif line.startswith(' ') or line[0].isdigit() or line.startswith('STAT:'):
                    #find result
                    #print("FIND: line {} contents {}".format(cnt, line))
                    rtmp=None
                    vstat=False
                    if line.startswith('STAT:'):
                        rtmp=line[5:].split('|')
                        vstat=True
                    else:
                        rtmp=line.split()
                    #md5sum
                    if rtmp and len(rtmp) == 2 and rtmp[1].startswith('/'):
                        #print("MD5SUM: line {} contents {}".format(cnt, line))
                        if rtmp[1] in files:
                            files[rtmp[1]]['md5sum'] = rtmp[0]
                        else:
                            files[rtmp[1]] = {'md5sum': rtmp[0]}
                    #cksum
                    elif rtmp and len(rtmp) == 3 and rtpm[0].isdigit() and rtpm[1].isdigit() and rtmp[-1].startswith('/'):
                        #print("CKSUM: line {} contents {}".format(cnt, line))
                        if rtmp[-1] in files:
                            files[rtmp[-1]]['cksum'] = rtmp[0]+' '+rtmp[1]
                            if rtmp[0]+' '+rtmp[1] in proccksum:
                                files[rtmp[-1]]['pid']=proccksum[rtmp[0]+' '+rtmp[1]]
                                for pid in proccksum[rtmp[0]+' '+rtmp[1]]:
                                    if pid in aixservices:
                                        files[rtmp[-1]]['service']=True
                        else:
                            files[rtmp[-1]] = {'cksum': rtmp[0]+' '+rtmp[1]}
                            if rtmp[0]+' '+rtmp[1] in proccksum:
                                files[rtmp[-1]]['pid']=proccksum[rtmp[0]+' '+rtmp[1]]
                                for pid in proccksum[rtmp[0]+' '+rtmp[1]]:
                                    if pid in aixservices:
                                        files[rtmp[-1]]['service']=True
                    #check if --time-style=long-iso (linux) or Date: (ls - aix) or stat
                    elif rtmp and len(rtmp) > 8:
                        filetmp=''
                        filelink=''
                        if vstat:
                            filetmp=rtmp[13]
                            if ' -> ' in rtmp[14]:
                                filelink=rtmp[14].split(' -> ')[1][1:-1]
                        else:
                            if '-' in rtmp[7]:
                                filetmp=' '.join(rtmp[9:])
                            else:
                                if ',' in rtmp[6] and rtmp[8][0].isalpha():
                                    filetmp=' '.join(rtmp[11:])
                                else:
                                    filetmp=' '.join(rtmp[10:])
                            ftmp=filetmp.split(' -> ')
                            if len(ftmp) == 2:
                                filetmp=ftmp[0]
                                current_file=filetmp
                                filelink=ftmp[1]
                        if filetmp in files:
                            files[filetmp]['inode'] = rtmp[0]
                            files[filetmp]['blocksize'] = rtmp[1]
                            files[filetmp]['permissions'] = rtmp[2]
                            files[filetmp]['numberoflink'] = rtmp[3]
                            files[filetmp]['owner'] = rtmp[4]
                            files[filetmp]['group'] = rtmp[5]
                            if vstat:
                                files[filetmp]['message']=line[5:].rstrip("\n\r")
                                files[filetmp]['size'] = rtmp[6]
                                files[filetmp]['device_major'] = rtmp[7]
                                files[filetmp]['device_minor'] = rtmp[8]
                                files[filetmp]['createdate'] = rtmp[9]
                                files[filetmp]['lastaccess'] = rtmp[10]
                                files[filetmp]['lastmodified'] = rtmp[11]
                                files[filetmp]['lastchange'] = rtmp[12]
                            else:
                                files[filetmp]['message']=line.rstrip("\n\r")
                                if not ',' in rtmp[6]:
                                    files[filetmp]['size'] = rtmp[6]
                                    if '-' in rtmp[7]:
                                        files[filetmp]['lastmodified'] = " ".join(rtmp[7:9])
                                    else:
                                        files[filetmp]['lastmodified'] = " ".join(rtmp[7:10])
                                else:
                                    files[filetmp]['device_major'] = rtmp[6]
                                    files[filetmp]['device_minor'] = rtmp[7]
                                    if rtmp[8][0].isalpha():
                                        files[filetmp]['lastmodified'] = " ".join(rtmp[8:11])
                                    else:
                                        files[filetmp]['lastmodified'] = " ".join(rtmp[8:10])
                        else:
                            if vstat:
                                files[filetmp] = {'message': line[5:].rstrip("\n\r"), 'inode': rtmp[0], 'blocksize': rtmp[1], 'permissions': rtmp[2], 'numberoflink': rtmp[3], 'owner': rtmp[4], 'group': rtmp[5], 'size': rtmp[6], 'device_major': rtmp[7], 'device_minor': rtmp[8],  'createdate': rtmp[9],  'lastaccess': rtmp[10],  'lastmodified': rtmp[11],  'lastchange': rtmp[12]}
                            else:
                                files[filetmp] = {'message': line.rstrip("\n\r"), 'inode': rtmp[0], 'blocksize': rtmp[1], 'permissions': rtmp[2], 'numberoflink': rtmp[3], 'owner': rtmp[4], 'group': rtmp[5]}
                                if not ',' in rtmp[6]:
                                    files[filetmp]['size'] = rtmp[6]
                                    if '-' in rtmp[7]:
                                        files[filetmp]['lastmodified'] = " ".join(rtmp[7:9])
                                    else:
                                        files[filetmp]['lastmodified'] = " ".join(rtmp[7:10])
                                else:
                                    files[filetmp]['device_major'] = rtmp[6]
                                    files[filetmp]['device_minor'] = rtmp[7]
                                    if rtmp[8][0].isalpha():
                                        files[filetmp]['lastmodified'] = " ".join(rtmp[8:11])
                                    else:
                                        files[filetmp]['lastmodified'] = " ".join(rtmp[8:10])
                                    #files[filetmp]['ext'] = extx #?? verif
                        if files[filetmp]['lastmodified'][0].isalpha() and not vstat:
                            if ':' in files[filetmp]['lastmodified']:
                                tmpdx=files[filetmp]['lastmodified'].split()
                                # j=01, f=02, mar=03 sinon ma=04, ju&l=07 sinon 06, a=08, s=09, o=10, n=11, d=12
                                if tmpdx[0].lower().startswith('j'):
                                    tmpd="01"
                                elif tmpdx[0].lower().startswith('f'):
                                    tmpd="02"
                                elif tmpdx[0].lower().startswith('mar'):
                                    tmpd="03"
                                elif tmpdx[0].lower().startswith('a'):
                                    if 'r' in tmpdx[0].lower():
                                        tmpd="04"
                                    else:
                                        tmpd="08"
                                elif tmpdx[0].lower().startswith('ma'):
                                    tmpd="05"
                                elif tmpdx[0].lower().startswith('ju'):
                                    if 'l' in tmpdx[0].lower():
                                        tmpd="07"
                                    else:
                                        tmpd="06"
                                elif tmpdx[0].lower().startswith('s'):
                                    tmpd="09"
                                elif tmpdx[0].lower().startswith('o'):
                                    tmpd="10"
                                elif tmpdx[0].lower().startswith('n'):
                                    tmpd="11"
                                elif tmpdx[0].lower().startswith('d'):
                                    tmpd="12"
                                files[filetmp]['lastmodified']=str(now.year)+"-"+tmpd+"-"+tmpdx[1]+" "+tmpdx[2]
                            else:
                                tmpdx=files[filetmp]['lastmodified'].split()
                                # j=01, f=02, mar=03 sinon ma=04, ju&l=07 sinon 06, a=08, s=09, o=10, n=11, d=12
                                if tmpdx[0].lower().startswith('j'):
                                    tmpd="01"
                                elif tmpdx[0].lower().startswith('f'):
                                    tmpd="02"
                                elif tmpdx[0].lower().startswith('mar'):
                                    tmpd="03"
                                elif tmpdx[0].lower().startswith('a'):
                                    if 'r' in tmpdx[0].lower():
                                        tmpd="04"
                                    else:
                                        tmpd="08"
                                elif tmpdx[0].lower().startswith('ma'):
                                    tmpd="05"
                                elif tmpdx[0].lower().startswith('ju'):
                                    if 'l' in tmpdx[0].lower():
                                        tmpd="07"
                                    else:
                                        tmpd="06"
                                elif tmpdx[0].lower().startswith('s'):
                                    tmpd="09"
                                elif tmpdx[0].lower().startswith('o'):
                                    tmpd="10"
                                elif tmpdx[0].lower().startswith('n'):
                                    tmpd="11"
                                elif tmpdx[0].lower().startswith('d'):
                                    tmpd="12"
                                print(str(files[filetmp]['message']))
                                files[filetmp]['lastmodified']=tmpdx[2]+"-"+tmpd+"-"+tmpdx[1]+" 00:00"
                        if files[filetmp]['permissions'].startswith('d'):
                            files[filetmp]['type_file'] = 'directory'
                        elif files[filetmp]['permissions'].startswith('-'):
                            files[filetmp]['type_file'] = 'file'
                            #get filename withotu path & ext
                            fnx=os.path.basename(filetmp)
                            pathx=os.path.dirname(filetmp)
                            fnxwe, extx = os.path.splitext(fnx)
                            if extx in stat_ext:
                                stat_ext[extx]=stat_ext[extx]+1
                            else:
                                stat_ext[extx]=1
                            if fnx in stat_filename:
                                stat_filename[fnx]=stat_filename[fnx]+1
                            else:
                                stat_filename[fnx]=1
                            if pathx in stat_path:
                                stat_path[pathx]=stat_path[pathx]+1
                            else:
                                stat_path[pathx]=1
                            if fnxwe in stat_filenamewithoutext:
                                stat_filenamewithoutext[fnxwe]=stat_filenamewithoutext[fnxwe]+1
                            else:
                                stat_filenamewithoutext[fnxwe]=1
                            files[filetmp]['ext'] = extx
                            files[filetmp]['file_name'] = fnx
                            files[filetmp]['file_path'] = pathx
                            files[filetmp]['file_name_withoutext'] = fnxwe
                        elif files[filetmp]['permissions'].startswith('c'):
                            files[filetmp]['type_file'] = 'device'
                        elif files[filetmp]['permissions'].startswith('b'):
                            files[filetmp]['type_file'] = 'device'
                        elif files[filetmp]['permissions'].startswith('s'):
                            files[filetmp]['type_file'] = 'socket'
                        elif files[filetmp]['permissions'].startswith('p'):
                            files[filetmp]['type_file'] = 'pipe'
                        elif files[filetmp]['permissions'].startswith('l'):
                            files[filetmp]['type_file'] = 'link'
                        if filelink:
                            files[filetmp]['link'] = True
                            files[filetmp]['filelink'] = filelink
                        #enrichissemnt
                        #important configuration file
                        if filetmp.startswith('/etc/'):
                            files[filetmp]['etc_file']=True
                        if filetmp.endswith('.hushlogin') or filetmp.endswith('.profile') or filetmp.endswith('.rhost') or filetmp.endswith('.cshrc') or filetmp.endswith('.login') or filetmp.endswith('.logout') or filetmp.endswith('.bashrc') or filetmp.endswith('.hosts') or filetmp.endswith('.bash_profile') or '/.ssh/' in filetmp or 'ftpusers' in filetmp:
                            files[filetmp]['configuration']=True
                        if filetmp.startswith('/etc/hosts.') or filetmp.startswith('/etc/sudoers') or filetmp.startswith('/etc/at.') or filetmp.startswith('/etc/grub.conf') or filetmp.startswith('/etc/default/') or filetmp.startswith('/etc/securetty') or filetmp.startswith('/etc/security/') or filetmp.startswith('/etc/motd') or filetmp.startswith('/etc/issue') or filetmp.startswith('/etc/exports') or filetmp.startswith('/etc/bashrc') or filetmp.startswith('/etc/shells') or filetmp.startswith('/etc/profile') or filetmp.startswith('/etc/pam.d/') or filetmp.startswith('/etc/passwd') or filetmp.startswith('/etc/group') or filetmp.startswith('/etc/group-') or filetmp.startswith('/etc/shadow') or filetmp.startswith('/etc/login.defs'):
                            files[filetmp]['configuration']=True
                        #docker file
                        if '/docker/containers/' in filetmp and (filetmp.endswith('.log') or filetmp.endswith('.json')):
                            files[filetmp]['docker_conf']=True
                        #history
                        if '.' in filetmp and 'history' in filetmp:
                            files[filetmp]['history']=True
                        #browser
                        if '.mozilla' in filetmp:
                            files[filetmp]['browser']=True
                        #browser
                        if '.mozilla' in filetmp or '/.cache/chromium/' in filetmp or '/.cache/google-chrome/' in filetmp:
                            files[filetmp]['browser']=True
                        #hidden
                        if '/.' in filetmp:
                            files[filetmp]['hidden']=True
                        #service
                        if filetmp.startswith('/etc/rc') or filetmp.startswith('/etc/systemd/') or filetmp.startswith('/etc/init.d/') or filetmp.startswith('/etc/xinet') or filetmp.startswith('/etc/rc.d/init.d/'):
                             files[filetmp]['service']=True
                        #executable file
                        if 'x' in files[filetmp]['permissions'] and not (filetmp.startswith('/usr/') or filetmp.startswith('/sbin/') or filetmp.startswith('/bin/') or filetmp.startswith('/opt/') or filetmp.startswith('/proc/')):
                            files[filetmp]['executable_nocommun_path'] = True
                        if 'x' in files[filetmp]['permissions']:
                            files[filetmp]['executable'] = True
                        #suid or sgid file
                        if 's' in files[filetmp]['permissions']:
                            files[filetmp]['suid_sgid'] = True
                        #device file
                        if 'b' in files[filetmp]['permissions']:
                            files[filetmp]['device'] = True
                        #writable file by all users
                        if len(files[filetmp]['permissions']) > 9 and 'w' == files[filetmp]['permissions'][-2] and not 'l' in files[filetmp]['permissions']:
                            files[filetmp]['writable'] = True
                        #unknown user or group
                        if files[filetmp]['owner'].isdigit() or files[filetmp]['group'].isdigit():
                            files[filetmp]['unknown_owner'] = True
                        #space at the end
                        if filetmp.endswith('\\') or filetmp.endswith(' '):
                            files[filetmp]['space_end'] = True    
                        #verify if in package
                        if filetmp in package_files_rpm:
                            files[filetmp]['rpm']=package_files_rpm[filetmp]
                            #use in service (autorun) & CVE
                            for package in package_files_rpm[filetmp]:
                                if package in package_files_rpm_service:
                                    files[filetmp]['service']=True
                                if package in package_cve_rpm:
                                    files[filetmp]['CVE']=True
                        if filetmp in package_files_deb:
                            files[filetmp]['deb']=package_files_deb[filetmp]
                            #use in service (autorun)
                            for package in package_files_deb[filetmp]:
                                if package in package_files_deb_service:
                                    files[filetmp]['service']=True
                                if package in package_cve_deb:
                                    files[filetmp]['CVE']=True
                        if filetmp in package_files_aix:
                            files[filetmp]['aix']=package_files_aix[filetmp]
                            #use in service (autorun)
                            for package in package_files_aix[filetmp]:
                                if package in package_files_aix_service:
                                    files[filetmp]['service']=True
                        #Package Integrity
                        if filetmp in package_files_deb_int:
                            files[filetmp]['debint']=True
                        if filetmp in package_files_rpm_int:
                            files[filetmp]['rpmint']=True
                        #loaded in kernel module
                        if filetmp in kernel_modules:
                            files[filetmp]['kernel_module_loaded']=True
                        #systemd
                        if filetmp in systemd:
                            files[filetmp]['service']=True
                        #initd
                        if filetmp in initd:
                            files[filetmp]['service']=True
                        #crontab
                        if filetmp in crontab:
                            files[filetmp]['crontab']=crontab[filetmp]
                        #env
                        if filetmp in envar:
                            files[filetmp]['env']=envar[filetmp]
                        #tmpfs
                        for fpat in tmpfs:
                            if filetmp.startswith(fpat):
                                files[filetmp]['tmpfs']=True
                        #process exe
                        if filetmp in procexe:
                            files[filetmp]['pid']=procexe[filetmp]
                            #network
                            for pid in procexe[filetmp]:
                                if pid in networks:
                                    files[filetmp]['net']=True
                        #process ldd
                        if filetmp in procldd:
                            files[filetmp]['ldd']=procldd[filetmp]
                            #network
                            for pid in procldd[filetmp]:
                                if pid in networks:
                                    files[filetmp]['net']=True
                                if pid in aixservices:
                                    files[filetmp]['service']=True
                        #process fd
                        if filetmp in procfd:
                            files[filetmp]['fd']=procfd[filetmp]
                            #network
                            for pid in procfd[filetmp]:
                                if pid in networks:
                                    files[filetmp]['net']=True
                                if pid in aixservices:
                                    files[filetmp]['service']=True
                        #process lsof
                        if filetmp in proclsof:
                            files[filetmp]['lsof']=proclsof[filetmp]
                            #network
                            for pid in proclsof[filetmp]:
                                if pid in networks:
                                    files[filetmp]['net']=True
                                if pid in aixservices:
                                    files[filetmp]['service']=True
                        #process ps
                        if filetmp in procps:
                            files[filetmp]['ps']=procps[filetmp]
                            #network
                            for pid in procps[filetmp]:
                                if pid in networks:
                                    files[filetmp]['net']=True
                                if pid in aixservices:
                                    files[filetmp]['service']=True
                elif line.startswith('Date:') and current_file in files:
                    #aix case  29-11-2019 15:30:24
                    tmp=line.rstrip("\n\r").split()
                    if len(tmp) == 3:
                        files[current_file]['lastmodified'] = tmp[1]+' '+tmp[2][0:-3] #remove second for have same iso linux
                #count line parsed
                cnt += 1
            print("Finish parse artefacts file. Number of line parsed: {}".format(cnt))
            if debug:
                with open('result.json', 'w') as fp:
                    json.dump(files, fp, indent=4, ensure_ascii=False)
                sorted(stat_type.items(), key=lambda item: item[1])
                with open('result-stat-file.json', 'w') as fp:
                    json.dump(stat_type, fp, indent=4, ensure_ascii=False, sort_keys=True)
                with open('result-stat-ext.json', 'w') as fp:
                    json.dump(stat_ext, fp, indent=4, ensure_ascii=False, sort_keys=True)
                with open('result-stat-filename.json', 'w') as fp:
                    json.dump(stat_filename, fp, indent=4, ensure_ascii=False, sort_keys=True)
                with open('result-stat-path.json', 'w') as fp:
                    json.dump(stat_path, fp, indent=4, ensure_ascii=False, sort_keys=True)
                with open('result-stat-filenamewithoutext.json', 'w') as fp:
                    json.dump(stat_filenamewithoutext, fp, indent=4, ensure_ascii=False, sort_keys=True)
            fx = open("timeline.jsonl", "a")
            #date
            #2019-12-11 15:20
            for k,v in files.items():
                if 'lastmodified' not in v:
                    print('Error to find file: '+str(k)+' ( '+str(v)+' )')
                    continue
                date = None
                if '+' in v['lastmodified']:
                    date=datetime.strptime(v['lastmodified'][0:-9]+v['lastmodified'][-6:], '%Y-%m-%d %H:%M:%S.%f %z')
                else:
                    date=datetime.strptime(v['lastmodified'], '%Y-%m-%d %H:%M')
                date2 = date.strftime('%Y-%m-%dT%H:%M:%S.%f')
                jsonl={"message": v['message'], "parser": 'find', "datetime": date2, "timestamp_desc": "Metadata Modification Time", "data_type": "fs:stat", "host": hostname, "file_entry_type": v['type_file'], "file_group": v['group'], "file_perm": v['permissions'], "file_owner": v['owner'], "inode": v['inode'], "filename": k, "blocksize": v['blocksize'], "tag": []}
                if 'ext' in v and v['ext']:
                    jsonl["file_ext"]=v['ext']
                    jsonl["file_statext"]=stat_ext[v['ext']]
                else:
                    jsonl["file_ext"]=None
                    jsonl["file_statext"]=0
                if 'file_name' in v and v['file_name']:
                    jsonl["file_name"]=v['file_name']
                    jsonl["file_statname"]=stat_filename[v['file_name']]
                else:
                    jsonl["file_name"]=None
                    jsonl["file_statname"]=0
                if 'file_path' in v and v['file_path']:
                    jsonl["file_path"]=v['file_path']
                    jsonl["file_statpath"]=stat_path[v['file_path']]
                    #add suspect name
                    if bool(re.match(r"[bcdfghjklmnpqrstvwxz]{4,}", v['file_path'], flags=re.IGNORECASE)) or bool(re.match(r"[aeuoiy]{4,}", v['file_path'], flags=re.IGNORECASE)):
                        jsonl['tag'].append('suspect_pathname')
                else:
                    jsonl["file_path"]=None
                    jsonl["file_statpath"]=0
                if 'file_name_withoutext' in v and v['file_name_withoutext']:
                    jsonl["file_name_withoutext"]=v['file_name_withoutext']
                    #add suspect name
                    if bool(re.match(r"[bcdfghjklmnpqrstvwxz]{4,}", v['file_name_withoutext'], flags=re.IGNORECASE)) or bool(re.match(r"[aeuoiy]{4,}", v['file_name_withoutext'], flags=re.IGNORECASE)):
                        jsonl['tag'].append('suspect_filename')
                else:
                    jsonl["file_name_withoutext"]=None
                if 'size' in v and v['size']:
                    jsonl["file_size"]=v['size']
                    jsonl["file_sizeint"]=int(v['size'])
                else:
                    jsonl["file_size"]=None
                    jsonl["file_sizeint"]=0
                if 'device_minor' in v and v['device_minor']:
                    jsonl["file_device_minor"]=v['device_minor']
                else:
                    jsonl["file_device_minor"]=None
                if 'device_major' in v and v['device_major']:
                    jsonl["file_device_major"]=v['device_major']
                else:
                    jsonl["file_device_major"]=None
                if 'type' in v and v['type']:
                    if 'statically linked' in v['type']:
                        jsonl['tag'].append('static_exe')
                    jsonl["file_type"]=v['type']
                    jsonl["file_stattype"]=stat_type[v['type']]
                else:
                    jsonl["file_type"]=None
                    jsonl["file_stattype"]=0
                if 'md5sum' in v and v['md5sum']:
                    jsonl["file_md5sum"]=v['md5sum']
                else:
                    jsonl["file_md5sum"]=None
                if 'entropy' in v and v['entropy']:
                    jsonl["file_entropy"]=v['entropy']
                else:
                    jsonl["file_entropy"]=None
                if 'filelink' in v and v['filelink']:
                    jsonl['tag'].append('file_link')
                    jsonl['filelink']=v['filelink']
                else:
                    jsonl['filelink']=None
                if 'etc_file' in v and v['etc_file']:
                    jsonl['file_etc']=True
                    jsonl['tag'].append('file_etc')
                else:
                    jsonl['file_etc']=False
                if 'configuration' in v and v['configuration']:
                    jsonl['file_cfg']=True
                    jsonl['tag'].append('file_cfg')
                else:
                    jsonl['file_cfg']=False
                if 'docker_conf' in v and v['docker_conf']:
                    #jsonl['file_docker']=True
                    jsonl['tag'].append('docker_conf')
                #else:
                    #jsonl['file_docker']=False
                if 'history' in v and v['history']:
                    #jsonl['file_history']=True
                    jsonl['tag'].append('file_history')
                #else:
                    #jsonl['file_history']=False
                if 'browser' in v and v['browser']:
                    #jsonl['file_browser']=True
                    jsonl['tag'].append('file_browser')
                #else:
                    #jsonl['file_browser']=False
                if 'hidden' in v and v['hidden']:
                    #jsonl['file_hidden']=True
                    jsonl['tag'].append('file_hidden')
                #else:
                    #jsonl['file_hidden']=False
                if 'service' in v and v['service']:
                    #jsonl['file_service']=True
                    jsonl['tag'].append('file_service')
                #else:
                    #jsonl['file_service']=False
                if 'executable' in v and v['executable'] and v['type_file'] == 'file':
                    #jsonl['file_executable']=True
                    jsonl['tag'].append('file_executable')
                #else:
                    #jsonl['file_executable']=False
                if 'executable_nocommun_path' in v and v['executable_nocommun_path'] and v['type_file'] == 'file':
                    #jsonl['file_executable_nocommonpath']=True
                    jsonl['tag'].append('file_executable_nocommonpath')
                #else:
                    #jsonl['file_executable_nocommonpath']=False
                if 'suid_sgid' in v and v['suid_sgid']:
                    jsonl['tag'].append('file_suid_guid')
                    #jsonl['file_suid_sgid']=True
                #else:
                    #jsonl['file_suid_sgid']=False
                if 'writable' in v and v['writable']:
                    jsonl['file_writable']=True
                    jsonl['tag'].append('file_writable')
                else:
                    jsonl['file_writable']=False
                if 'unknown_owner' in v and v['unknown_owner']:
                    jsonl['tag'].append('file_unknown_owner')
                    #jsonl['file_unknown_owner']=True
                #else:
                    #jsonl['file_unknown_owner']=False
                if 'space_end' in v and v['space_end']:
                    #jsonl['file_space_end']=True
                    #TODO fix pb with space ''.join(filename) << when multi spaces only replace one space
                    jsonl['tag'].append('file_space_end')
                #else:
                    #jsonl['file_space_end']=False
                if 'rpm' in v and v['rpm']:
                    jsonl['file_pkgrpm']=v['rpm']
                    jsonl['tag'].append('file_from_package')
                else:
                    jsonl['file_pkgrpm']=None
                if 'deb' in v and v['deb']:
                    jsonl['file_pkgdeb']=v['deb']
                    jsonl['tag'].append('file_from_package')
                else:
                    jsonl['file_pkgdeb']=None
                if 'aix' in v and v['aix']:
                    jsonl['file_pkgaix']=v['aix']
                    jsonl['tag'].append('file_from_package')
                else:
                    jsonl['file_pkgaix']=None
                if 'CVE' in v and v['CVE']:
                    #jsonl['file_cve']=True
                    jsonl['tag'].append('file_cve')
                #else:
                    #jsonl['file_cve']=False
                if 'debint' in v and v['debint']:
                    jsonl['file_pkg_integrity']=False
                    jsonl['tag'].append('file_pb_pkg_integrity')
                else:
                    jsonl['file_pkg_integrity']=True
                if 'rpmint' in v and v['rpmint']:
                    jsonl['file_pkg_integrity']=False
                    jsonl['tag'].append('file_pb_pkg_integrity')
                else:
                    jsonl['file_pkg_integrity']=True
                if 'kernel_module_loaded' in v and v['kernel_module_loaded']:
                    #jsonl['file_kernelmodule']=True
                    jsonl['tag'].append('file_kernelmodule')
                #else:
                    #jsonl['file_kernelmodule']=False
                if 'crontab' in v and v['crontab']:
                    #jsonl['file_crontab']=True
                    jsonl['tag'].append('file_crontab')
                #else:
                    #jsonl['file_crontab']=False
                if 'env' in v and v['env']:
                    #jsonl['file_env']=True
                    jsonl['tag'].append('file_env')
                #else:
                    #jsonl['file_env']=False
                if 'tmpfs' in v and v['tmpfs']:
                    #jsonl['file_tmpfs']=True
                    jsonl['tag'].append('file_tmpfs')
                #else:
                    #jsonl['file_tmpfs']=False
                if 'net' in v and v['net']:
                    #jsonl['file_network']=True
                    jsonl['tag'].append('file_network')
                #else:
                    #jsonl['file_network']=False
                if 'pid' in v and v['pid']:
                    jsonl['file_pid']=v['pid']
                    jsonl['tag'].append('file_pid')
                else:
                    jsonl['file_pid']=None
                if 'ldd' in v and v['ldd']:
                    jsonl['file_ldd']=v['ldd']
                    jsonl['tag'].append('file_ldd')
                else:
                    jsonl['file_ldd']=None
                if 'fd' in v and v['fd']:
                    jsonl['file_fd']=v['fd']
                    jsonl['tag'].append('file_fd')
                else:
                    jsonl['file_fd']=None
                if 'lsof' in v and v['lsof']:
                    jsonl['file_lsof']=v['lsof']
                    jsonl['tag'].append('file_lsof')
                else:
                    jsonl['file_lsof']=None
                if 'ps' in v and v['ps']:
                    jsonl['file_ps']=v['ps']
                    jsonl['tag'].append('file_ps')
                else:
                    jsonl['file_ps']=None
                if not jsonl['tag']:
                  del jsonl['tag']
                print("%s" % (json.dumps(jsonl)),file=fx)
                if 'lastchange' in v and v['lastchange'] != '-':
                    try:
                        date=datetime.strptime(v['lastchange'][0:-9]+v['lastchange'][-6:], '%Y-%m-%d %H:%M:%S.%f %z')
                    except:
                        print("Error parse date :"+v['lastchange'][0:-9]+v['lastchange'][-6:]+" --on file: " + str(jsonl))
                    #jsonl['timestamp']=str(int(datetime.timestamp(date)))
                    try:
                        jsonl['datetime']=date.strftime('%Y-%m-%dT%H:%M:%S.%f')
                        jsonl['timestamp_desc']="Metadata Change Time"
                        print("%s" % (json.dumps(jsonl)),file=fx)
                    except Exception as e:
                        print("Errorwrite jsonl: " + str(jsonl)+" -- error:"+str(e))
                if 'lastaccess' in v and v['lastaccess'] != '-':
                    try:
                        date=datetime.strptime(v['lastaccess'][0:-9]+v['lastaccess'][-6:], '%Y-%m-%d %H:%M:%S.%f %z')
                    except:
                        print("Error parse date :"+v['lastaccess'][0:-9]+v['lastaccess'][-6:]+" --on file: " + str(jsonl))
                    #jsonl['timestamp']=str(int(datetime.timestamp(date)))
                    try:
                        jsonl['datetime']=date.strftime('%Y-%m-%dT%H:%M:%S.%f')
                        jsonl['timestamp_desc']="Metadata Access Time"
                        print("%s" % (json.dumps(jsonl)),file=fx)
                    except Exception as e:
                        print("Errorwrite jsonl: " + str(jsonl)+" -- error:"+str(e))
                if 'createdate' in v and v['createdate'] != '-':
                    try:
                        date=datetime.strptime(v['createdate'][0:-9]+v['createdate'][-6:], '%Y-%m-%d %H:%M:%S.%f %z')
                    except:
                        print("Error parse date :"+v['createdate'][0:-9]+v['createdate'][-6:]+" --on file: " + str(jsonl))
                    #jsonl['timestamp']=str(int(datetime.timestamp(date)))
                    try:
                        jsonl['datetime']=date.strftime('%Y-%m-%dT%H:%M:%S.%f')
                        jsonl['timestamp_desc']="Metadata Create Time"
                        print("%s" % (json.dumps(jsonl)),file=fx)
                    except Exception as e:
                        print("Errorwrite jsonl: " + str(jsonl)+" -- error:"+str(e))
            fx.close()    

if __name__ == '__main__':
   main()
