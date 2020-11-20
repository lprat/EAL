import "elf"

private rule b64
{
    strings:
        $user_agent = "SFRUUF9VU0VSX0FHRU5UCg"
        $eval = "ZXZhbCg"
        $system = "c3lzdGVt"
        $preg_replace = "cHJlZ19yZXBsYWNl"
        $exec = "ZXhlYyg"
        $base64_decode = "YmFzZTY0X2RlY29kZ"
        $perl_shebang = "IyEvdXNyL2Jpbi9wZXJsCg"
        $cmd_exe = "Y21kLmV4ZQ"
        $powershell = "cG93ZXJzaGVsbC5leGU"
        $create_function = "Y3JlYXRlX2Z1bmN0aW9u"

    condition:
        any of them
}

private rule hex
{
    strings:
        $globals = "\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53" nocase
        $eval = "\\x65\\x76\\x61\\x6C\\x28" nocase
        $exec = "\\x65\\x78\\x65\\x63" nocase
        $system = "\\x73\\x79\\x73\\x74\\x65\\x6d" nocase
        $preg_replace = "\\x70\\x72\\x65\\x67\\x5f\\x72\\x65\\x70\\x6c\\x61\\x63\\x65" nocase
        $http_user_agent = "\\x48\\124\\x54\\120\\x5f\\125\\x53\\105\\x52\\137\\x41\\107\\x45\\116\\x54" nocase
        $base64_decode = "\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65\\x28\\x67\\x7a\\x69\\x6e\\x66\\x6c\\x61\\x74\\x65\\x28" nocase
        $create_function = "\\x63\\x72\\x65\\x61\\x74\\x65\\x5f\\x66\\x75\\x6e\\x63\\x74\\x69\\x6f\\x6e" nocase
        
    condition:
        any of them
}

private rule Hpack
{
    strings:
        $globals = "474c4f42414c53" nocase
        $eval = "6576616C28" nocase
        $exec = "65786563" nocase
        $system = "73797374656d" nocase
        $preg_replace = "707265675f7265706c616365" nocase
        $base64_decode = "61736536345f6465636f646528677a696e666c61746528" nocase
    
    condition:
        any of them
}

private rule strrev
{
    strings:
        $globals = "slabolg" nocase fullword
        $preg_replace = "ecalper_gerp" nocase fullword
        $base64_decode = "edoced_46esab" nocase fullword
        $gzinflate = "etalfnizg" nocase fullword
         $create_function = "noitcnuf_etaerc" nocase fullword
    condition:
        any of them
}

private rule filejs {
    meta:
        author = "Lionel PRAT"
        description = "File javascript"

    strings:
        $js0 = "function " nocase
        $js1 = "return" nocase
        $js2 = "var " nocase
        $k0 = "if " nocase
        $k1 = "else " nocase
        $k2 = "do " nocase
        $k3 = "while " nocase
        $k4 = "for " nocase
        $var = /(^|\s+)var\s+\S+\s*=[^;]+;/ nocase
        $func = /(^|\s+)function\s+\S+\([^\)]+\)\s*{/ nocase
    condition:
        (2 of ($js*) and 2 of ($k*) and $func and $var)
}

private rule strsuspectfile
{
    meta:
        description = "Suspect string in file"
        author = "Lionel PRAT"
        filetype = "ALL"
        
    strings:
        $ = "pwndns.pw" nocase ascii wide  /* malware miner */
        $ = "ipify.org" nocase ascii wide /* get my ip */
        $ = "45.9.148." nocase ascii wide /* monero ip */
        $ = "PRIVMSG " nocase ascii wide /* Potential command IRC*/
        $ = "</cfexecute>" nocase ascii wide /* coldfusion */
        $ = "User-Agent" nocase ascii wide /* Potential make header HTTP */
        $ = "already connected" nocase ascii wide
        $ = "connection closed" nocase ascii wide
        $ = "error on socket" nocase ascii wide
        $ = "AF_INET" nocase ascii wide
        $ = "SOCK_STREAM" nocase ascii wide
        $ = "popen(" nocase ascii wide
        $ = "system(" nocase ascii wide
        $ = "backdoor" nocase ascii wide
        $ = "webshell" nocase ascii wide
        $ = "web shell" nocase ascii wide
        $ = "xmrig" nocase ascii wide /* malware miner */
        $ = "monero" nocase ascii wide /* malware miner */
        $ = "bitcoin" nocase ascii wide /* malware miner */
        $ = "miner" nocase ascii wide /* malware miner */
        $ = "coinhive" nocase ascii wide /* malware miner */
        $ = "authorized_keys" nocase ascii wide /* ssh backdoor */
        $ = "/dev/cpu" nocase ascii wide /* malware miner */
        $ = "ujL;d$" nocase ascii wide /*libcurl */ 
        $ = "tls: failed to parse configured certificate chain" nocase ascii wide /* use network */
        $ = "server port" nocase ascii wide  /* use network */ 
        $ = "keepalive timeout" nocase ascii wide /* use network */
        $ = ".onion" nocase ascii wide /* use TOR */
        $ = "Accept: application/" nocase ascii wide  /* Potential make header HTTP */
        $ = "d$8[]A\\A]" nocase ascii wide /* busybox */
        $ = "@(A98u" nocase ascii wide /* metasploit */
        $ = "C88E8u" nocase ascii wide /* metasploit */
        $ = "/bin/chown" nocase ascii wide /* suspect command use */
        $ = "socket:[%d]" nocase ascii wide /* use network */
        $ = "history -c" nocase ascii wide /* clean history */
        $ = "Cookie: " nocase ascii wide  /* Potential make header HTTP */
        $ = "/useradd" nocase ascii wide /* suspect command use */
        $ = "/adduser" nocase ascii wide /* suspect command use */
        $ = "chmod +x" nocase ascii wide /* suspect command use */
        $ = "curl" nocase ascii wide /* suspect command use */
        $ = "/bin/sh" nocase ascii wide /* suspect command use */
        $ = "wget" nocase ascii wide /* suspect command use */
        $ = "masscan" nocase ascii wide /* suspect command use */
        $ = "nmap(%s): unsupported" nocase ascii wide /* suspect command use */
        $ = "NBT-NS" nocase ascii wide /* suspect command use responder */
        $ = "LLMNR" nocase ascii wide /* suspect command use responder */
        $ = "LD_PRELOAD" nocase ascii wide /* hijack proc */
        $ = "_ZNSaIcEaSERKS_" nocase ascii wide /* metasploit */
        //$ = "content-type: " nocase ascii wide /* Potential make header HTTP  - more false positive */ 
        $ = "smbexec" nocase ascii wide /* suspect command use */
        $ = /\!ENTITY [^>]{1,64} SYSTEM/ nocase ascii wide /* potential XXE */
        $ = /GCC: \([\^)]{1,32}\) [0-9\.]{3,6}/ nocase ascii wide /* bash to elf */
        $ = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase ascii wide /* url with ip */
        $ = "pastebin" nocase ascii wide /* pastebin */
        $ = /https:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase ascii wide /* url suspect port */
        $ = /https?:\/\/[\w\.-]{4,255}:[0-9]{1,5}/ nocase ascii wide /* url specify port */
        $ = "meterpreter" nocase ascii wide /* from https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 */
        $ = "Nir Sofer" nocase ascii wide /* from https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 */
        $ = /\[[\+\-!E]\] (exploit|target|vulnerab|shell|inject|dump)/ nocase /* from https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 */
        $ = "stratum+tcp://"    /* from https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 */
    condition:
        any of them
}

rule single_load_rwe
{
    meta:
        description = "Flags binaries with a single LOAD segment marked as RWE."
        author = "https://github.com/tenable/yara-rules/blob/master/generic/elf_format.yar"
        family = "Stager"
        filetype = "ELF"
        hash = "711a06265c71a7157ef1732c56e02a992e56e9d9383ca0f6d98cd96a30e37299"

    condition:
        elf.number_of_segments == 1 and
        elf.segments[0].type == elf.PT_LOAD and
        elf.segments[0].flags == elf.PF_R | elf.PF_W | elf.PF_X
}

rule fake_section_headers_conflicting_entry_point_address
{
    meta:
        description = "A fake sections header has been added to the binary."
        author = "https://github.com/tenable/yara-rules/blob/master/generic/elf_format.yar"
        family = "Obfuscation"
        filetype = "ELF"
        hash = "a2301180df014f216d34cec8a6a6549638925ae21995779c2d7d2827256a8447"

    condition:
        elf.type == elf.ET_EXEC and
        elf.entry_point < filesize and // file scanning only
        elf.number_of_segments > 0 and
        elf.number_of_sections > 0 and
        not
        (
            for any i in (0..elf.number_of_segments):
            (
                (elf.segments[i].offset <= elf.entry_point) and
                ((elf.segments[i].offset + elf.segments[i].file_size) >= elf.entry_point) and
                for any j in (0..elf.number_of_sections):
                (
                    elf.sections[j].offset <= elf.entry_point and
                    ((elf.sections[j].offset + elf.sections[j].size) >= elf.entry_point) and
                    (elf.segments[i].virtual_address + (elf.entry_point - elf.segments[i].offset)) ==
                    (elf.sections[j].address + (elf.entry_point - elf.sections[j].offset))
                )
            )
        )
}

rule fake_dynamic_symbols
{
    meta:
        description = "A fake dynamic symbol table has been added to the binary"
        author = "https://github.com/tenable/yara-rules/blob/master/generic/elf_format.yar"
        family = "Obfuscation"
        filetype = "ELF"
        hash = "51676ae7e151a0b906c3a8ad34f474cb5b65eaa3bf40bb09b00c624747bcb241"

    condition:
        elf.type == elf.ET_EXEC and
        elf.entry_point < filesize and // file scanning only
        elf.number_of_sections > 0 and
        elf.dynamic_section_entries > 0 and
        for any i in (0..elf.dynamic_section_entries):
        (
            elf.dynamic[i].type == elf.DT_SYMTAB and
            not
            (
                for any j in (0..elf.number_of_sections):
                (
                    elf.sections[j].type == elf.SHT_DYNSYM and
                    for any k in (0..elf.number_of_segments):
                    (
                        (elf.segments[k].virtual_address <= elf.dynamic[i].val) and
                        ((elf.segments[k].virtual_address + elf.segments[k].file_size) >= elf.dynamic[i].val) and
                        (elf.segments[k].offset + (elf.dynamic[i].val - elf.segments[k].virtual_address)) == elf.sections[j].offset
                    )
                )
            )
        )
}

rule static_elf
{
    meta:
        description = "ELF Suspect no ldd"
        author = "Lionel PRAT"
        filetype = "ELF"

    condition:
        elf.dynamic_section_entries > 0 and not
        for any i in (0..elf.dynamic_section_entries):
        (
            elf.dynamic[i].type == elf.DT_NEEDED
         )
        and not
        for any i in (0..elf.symtab_entries): //work with patch https://github.com/VirusTotal/yara/pull/1395
        (
            elf.symtab[i].bind == elf.STB_GLOBAL
        )
}

rule SuspectElf
{
    meta:
        description = "ELF Suspect no ldd"
        author = "Lionel PRAT"
        filetype = "ELF"
        
    strings:
        $elf = {7f 45 4c 46}
        $ss0 = "pwndns.pw" nocase ascii wide  /* malware miner */
        $ss1 = "ipify.org" nocase ascii wide /* get my ip */
        $ss2 = "45.9.148." nocase ascii wide /* monero ip */
        $ss3 = "PRIVMSG " nocase ascii wide /* Potential command IRC*/
        $ss4 = "</cfexecute>" nocase ascii wide /* coldfusion */
        $ss5 = "User-Agent" nocase ascii wide /* Potential make header HTTP */
        //$ss6 = "already connected" nocase ascii wide
        $ss7 = "connection closed" nocase ascii wide
        $ss8 = "error on socket" nocase ascii wide
        $ss9 = "AF_INET" nocase ascii wide
        $ss10 = "SOCK_STREAM" nocase ascii wide
        $ss11 = "popen(" nocase ascii wide
        $ss12 = "system(" nocase ascii wide
        $ss13 = "backdoor" nocase ascii wide
        $ss14 = "webshell" nocase ascii wide
        $ss15 = "web shell" nocase ascii wide
        $ss16 = "xmrig" nocase ascii wide /* malware miner */
        $ss17 = "monero" nocase ascii wide /* malware miner */
        $ss18 = "bitcoin" nocase ascii wide /* malware miner */
        $ss19 = "miner" nocase ascii wide /* malware miner */
        $ss20 = "coinhive" nocase ascii wide /* malware miner */
        $ss21 = "authorized_keys" nocase ascii wide /* ssh backdoor */
        $ss22 = "/dev/cpu" nocase ascii wide /* malware miner */
        $ss23 = "ujL;d$ss" nocase ascii wide /*libcurl */ 
        $ss24 = "tls: failed to parse configured certificate chain" nocase ascii wide /* use network */
        $ss25 = "server port" nocase ascii wide  /* use network */ 
        $ss26 = "keepalive timeout" nocase ascii wide /* use network */
        $ss27 = ".onion" nocase ascii wide /* use TOR */
        $ss28 = "Accept: application/" nocase ascii wide  /* Potential make header HTTP */
        $ss29 = "d$ss8[]A\\A]" nocase ascii wide /* busybox */
        $ss30 = "@(A98u" nocase ascii wide /* metasploit */
        $ss31 = "C88E8u" nocase ascii wide /* metasploit */
        $ss32 = "/bin/chown" nocase ascii wide /* suspect command use */
        $ss33 = "socket:[%d]" nocase ascii wide /* use network */
        $ss34 = "history -c" nocase ascii wide /* clean history */
        $ss35 = "Cookie: " nocase ascii wide  /* Potential make header HTTP */
        $ss36 = "/useradd" nocase ascii wide /* suspect command use */
        $ss37 = "/adduser" nocase ascii wide /* suspect command use */
        $ss38 = "chmod +x" nocase ascii wide /* suspect command use */
        $ss39 = "curl" nocase ascii wide /* suspect command use */
        $ss40 = "/bin/sh" nocase ascii wide /* suspect command use */
        $ss41 = "wget" nocase ascii wide /* suspect command use */
        $ss42 = "masscan" nocase ascii wide /* suspect command use */
        $ss43 = "nmap(%s): unsupported" nocase ascii wide /* suspect command use */
        $ss44 = "NBT-NS" nocase ascii wide /* suspect command use responder */
        $ss45 = "LLMNR" nocase ascii wide /* suspect command use responder */
        $ss46 = "LD_PRELOAD" nocase ascii wide /* hijack proc */
        $ss47 = "_ZNSaIcEaSERKS_" nocase ascii wide /* metasploit */
        //$ss = "content-type: " nocase ascii wide /* Potential make header HTTP  - more false positive */ 
        $ss48 = "smbexec" nocase ascii wide /* suspect command use */
        $ss49 = /\!ENTITY [^>]{1,64} SYSTEM/ nocase ascii wide /* potential XXE */
        $ss50 = /GCC: \([\^)]{1,32}\) [0-9\.]{3,6}/ nocase ascii wide /* bash to elf */
        $ss51 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase ascii wide /* url with ip */
        $ss52 = "pastebin" nocase ascii wide /* pastebin */
        $ss53 = /https:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase ascii wide /* url suspect port */
        $ss54 = /https?:\/\/[\w\.-]{4,255}:[0-9]{1,5}/ nocase ascii wide /* url specify port */
        $ss55 = "meterpreter" nocase ascii wide /* from https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 */
        $ss56 = "Nir Sofer" nocase ascii wide /* from https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 */
        $ss57 = /\[[\+\-!E]\] (exploit|target|vulnerab|shell|inject|dump)/ nocase /* from https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 */
        $ss58 = "stratum+tcp://"    /* from https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 */
    condition:
        $elf in (0..4) and 1 of ($ss*)
}

rule SuspectPhp
{
    meta:
        description = "Suspect php code" /* used like webshell/web backdoor */
        author = "Lionel PRAT - modified from https://raw.githubusercontent.com/jvoisin/php-malware-finder/master/php-malware-finder/php.yar"
        filetype = "PHP"
        
    strings:
        $php = "<?php" fullword nocase
        $system = "system" fullword nocase  // localroot bruteforcers have a lot of this
        $param1 = "_GET" fullword nocase
        $param2 = "_POST" fullword nocase
        $param3 = "_REQUEST" fullword nocase
        $param4 = "_COOKIE" fullword nocase
        $param5 = "_SERVER" fullword nocase
        $param6 = "_FILENAME" fullword nocase
        $obf0 = /([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^"]*";|([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^"]*",|([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^"]*"\)/ nocase // strings obfuscated
        $obf1 = /([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^']*';|([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^']*',|([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^']*'\)/ nocase // strings obfuscated
        $obf2 = "eval(" nocase
        $obf3 = /\$[a-z0-9_-]{1,160}\{[0-9]{1,3}\}\./ nocase // varname obfuscated
        $fobf0 = "CURLOPT" nocase
        $fobf1 = "substr" nocase
        $fobf2 = "header(" nocase 
        $fobf3 = "base64_decode" nocase 
        $fobf4 = "create_function" nocase 
        $fobf5 = "GLOBALS"
        $func1 = "array_filter" fullword nocase
        $func2 = "assert" fullword nocase
        $func3 = "backticks" fullword nocase
        $func4 = "call_user_func" fullword nocase
        $func5 = "eval" fullword nocase
        $func6 = "exec" fullword nocase
        $func7 = "fpassthru" fullword nocase
        $func8 = "fsockopen" fullword nocase
        $func9 = "fsockopen" fullword nocase
        $func10 = "function_exists" fullword nocase
        $func11 = "getmygid" fullword nocase
        $func12 = "shmop_open" fullword nocase
        $func13 = "mb_ereg_replace_callback" fullword nocase
        $func14 = "passthru" fullword nocase
        $func15 = /pcntl_(exec|fork)/ fullword nocase
        $func16 = "php_uname" fullword nocase
        $func17 = "phpinfo" fullword nocase
        $func18 = "posix_geteuid" fullword nocase
        $func19 = "posix_getgid" fullword nocase
        $func20 = "posix_getpgid" fullword nocase
        $func21 = "posix_getppid" fullword nocase
        $func22 = "posix_getpwnam" fullword nocase
        $func23 = "posix_getpwuid" fullword nocase
        $func24 = "posix_getsid" fullword nocase
        $func25 = "posix_getuid" fullword nocase
        $func26 = "posix_kill" fullword nocase
        $func27 = "posix_setegid" fullword nocase
        $func28 = "posix_seteuid" fullword nocase
        $func29 = "posix_setgid" fullword nocase
        $func30 = "posix_setpgid" fullword nocase
        $func31 = "posix_setsid" fullword nocase
        $func32 = "posix_setsid" fullword nocase
        $func33 = "posix_setuid" fullword nocase
        $func34 = "preg_replace" fullword
        $func35 = "proc_open" fullword nocase
        $func36 = "proc_close" fullword nocase
        $func37 = "popen" fullword nocase
        $func38 = "register_shutdown_function" fullword nocase
        $func39 = "register_tick_function" fullword nocase
        $func40 = "shell_exec" fullword nocase
        $func41 = "shm_open" fullword nocase
        $func42 = "show_source" fullword nocase
        $func43 = "socket_create(AF_INET, SOCK_STREAM, SOL_TCP)" nocase
        $func44 = "stream_socket_pair" nocase
        $func45 = "suhosin.executor.func.blacklist" nocase
        $func46 = "unregister_tick_function" fullword nocase
        $func47 = "win32_create_service" fullword nocase
        $func48 = "xmlrpc_decode" fullword nocase
        $func49 = "base64_decode" fullword nocase
        $whitelist = /escapeshellcmd|escapeshellarg/ nocase
    condition:
        $php and (((any of ($param*)) and  ((not $whitelist and (3 of ($func*) or #system > 250)) or b64 or hex or strrev or Hpack or strsuspectfile)) or (3 of ($obf*) and any of  ($fobf*)))
}

rule SuspectJS {
    meta:
        description = "Suspect javascript code" /* can be used in website to apply on client */
        author = "Lionel PRAT"
        filetype = "JS"
        
    strings:
        $obf0 = /([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^"]*";|([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^"]*",|([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^"]*"\)/ nocase // strings obfuscated
        $obf1 = /([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^']*';|([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^']*',|([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^']*'\)/ nocase // strings obfuscated
        $obf2 = "eval(" nocase
        $obf3 = /(function\s+.*){3}/ nocase // base 64
        $obf4 = /var\s+[^\s]*[a-z_\$]([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{5}){1}/ nocase // name var obfuscated
        $obf5 = /var\s+[^\s]*[a-z_\$]([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{5}){1}/ nocase // name var obfuscated
        $obf6 = /\.toString\([0-9]+\)/ nocase
    condition:
        filejs and (3 of ($obf*) or strsuspectfile)
}

rule SuspectScript
{
    meta:
        description = "Suspect script"
        author = "Lionel PRAT"
        filetype = "Script"
        
    strings:
        $script = {23 21 2f}
        $ss0 = "pwndns.pw" nocase ascii wide  /* malware miner */
        $ss1 = "ipify.org" nocase ascii wide /* get my ip */
        $ss2 = "45.9.148." nocase ascii wide /* monero ip */
        $ss3 = "PRIVMSG " nocase ascii wide /* Potential command IRC*/
        $ss4 = "</cfexecute>" nocase ascii wide /* coldfusion */
        $ss5 = "User-Agent" nocase ascii wide /* Potential make header HTTP */
        $ss6 = "already connected" nocase ascii wide
        $ss7 = "connection closed" nocase ascii wide
        $ss8 = "error on socket" nocase ascii wide
        $ss9 = "AF_INET" nocase ascii wide
        $ss10 = "SOCK_STREAM" nocase ascii wide
        $ss11 = "popen(" nocase ascii wide
        $ss12 = "system(" nocase ascii wide
        $ss13 = "backdoor" nocase ascii wide
        $ss14 = "webshell" nocase ascii wide
        $ss15 = "web shell" nocase ascii wide
        $ss16 = "xmrig" nocase ascii wide /* malware miner */
        $ss17 = "monero" nocase ascii wide /* malware miner */
        $ss18 = "bitcoin" nocase ascii wide /* malware miner */
        $ss19 = "miner" nocase ascii wide /* malware miner */
        $ss20 = "coinhive" nocase ascii wide /* malware miner */
        $ss21 = "authorized_keys" nocase ascii wide /* ssh backdoor */
        $ss22 = "/dev/cpu" nocase ascii wide /* malware miner */
        $ss23 = "ujL;d$ss" nocase ascii wide /*libcurl */ 
        $ss24 = "tls: failed to parse configured certificate chain" nocase ascii wide /* use network */
        $ss25 = "server port" nocase ascii wide  /* use network */ 
        $ss26 = "keepalive timeout" nocase ascii wide /* use network */
        $ss27 = ".onion" nocase ascii wide /* use TOR */
        $ss28 = "Accept: application/" nocase ascii wide  /* Potential make header HTTP */
        $ss29 = "d$ss8[]A\\A]" nocase ascii wide /* busybox */
        $ss30 = "@(A98u" nocase ascii wide /* metasploit */
        $ss31 = "C88E8u" nocase ascii wide /* metasploit */
        $ss32 = "/bin/chown" nocase ascii wide /* suspect command use */
        $ss33 = "socket:[%d]" nocase ascii wide /* use network */
        $ss34 = "history -c" nocase ascii wide /* clean history */
        $ss35 = "Cookie: " nocase ascii wide  /* Potential make header HTTP */
        $ss36 = "/useradd" nocase ascii wide /* suspect command use */
        $ss37 = "/adduser" nocase ascii wide /* suspect command use */
        $ss38 = "chmod +x" nocase ascii wide /* suspect command use */
        $ss39 = "curl" nocase ascii wide /* suspect command use */
        $ss40 = /\/bin\/sh('|"| -)/ nocase ascii wide /* suspect command use */
        $ss41 = "wget" nocase ascii wide /* suspect command use */
        $ss42 = "masscan" nocase ascii wide /* suspect command use */
        $ss43 = "nmap(%s): unsupported" nocase ascii wide /* suspect command use */
        $ss44 = "NBT-NS" nocase ascii wide /* suspect command use responder */
        $ss45 = "LLMNR" nocase ascii wide /* suspect command use responder */
        $ss46 = "LD_PRELOAD" nocase ascii wide /* hijack proc */
        $ss47 = "_ZNSaIcEaSERKS_" nocase ascii wide /* metasploit */
        //$ss = "content-type: " nocase ascii wide /* Potential make header HTTP  - more false positive */ 
        $ss48 = "smbexec" nocase ascii wide /* suspect command use */
        $ss49 = /\!ENTITY [^>]{1,64} SYSTEM/ nocase ascii wide /* potential XXE */
        $ss50 = /GCC: \([\^)]{1,32}\) [0-9\.]{3,6}/ nocase ascii wide /* bash to elf */
        $ss51 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase ascii wide /* url with ip */
        $ss52 = "pastebin" nocase ascii wide /* pastebin */
        $ss53 = /https:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase ascii wide /* url suspect port */
        $ss54 = /https?:\/\/[\w\.-]{4,255}:[0-9]{1,5}/ nocase ascii wide /* url specify port */
        $ss55 = "meterpreter" nocase ascii wide /* from https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 */
        $ss56 = "Nir Sofer" nocase ascii wide /* from https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 */
        $ss57 = /\[[\+\-!E]\] (exploit|target|vulnerab|shell|inject|dump)/ nocase /* from https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 */
        $ss58 = "stratum+tcp://"    /* from https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 */
    condition:
        $script in (0..3) and 1 of ($ss*)
}

rule SuspectXXE {
    meta:
        description = "File contains suspect XXE"
        author = "Lionel PRAT"
        filetype = "XML"
        
    strings:
        $xml = "<?xml" nocase
        $soap = "<soap"
        $xxe = /<\!entity [^>]{1,64} SYSTEM / nocase ascii wide
    condition:
        ($soap or $xml) and $xxe
}

rule SuspectJSP
{
    meta:
        description = "Suspect JSP code"
        author = "Lionel PRAT"
        filetype = "JSP"
        source = "https://github.com/fa1c0n1/MyJSPWebshell/"
        
    strings:
        $jsp0 = "<%@page" nocase
        $jsp1 = "import=" nocase
        $jsp2 = "%>"
        $req = "request."
        $obf0 = /([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^"]*";|([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^"]*",|([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^"]*"\)/ nocase // strings obfuscated
        $obf1 = /([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^']*';|([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^']*',|([aeuoiy]{4}|[bcdfghjklmnpqrstvwxz]{6}|[0-9a-f]{8}|(\\x[0-9a-f]){8}|[a-z0-9+\/]{2}==){1}[^']*'\)/ nocase // strings obfuscated
        $obf2 = /(\\u00[0-9][0-9]){4}/ nocase
        $obf3 = /(\\x[a-f0-9][a-f0-9]){4}/ nocase
        $obf4 = /(\&\#x[a-f0-9][a-f0-9];){4}/ nocase
        $obf5 = "<![CDATA[" nocase
        $obf6 = "eval(" nocase
        $d1 = "Runtime.getRuntime().exec" nocase
        $d2 = /Expression\(\s{0,64}Runtime.getRuntime\(\)/ nocase
        $d3 = "URLClassLoader" nocase
        $d4 = "javax.xml.transform.stream." nocase
        $d5 = "com.sun.jndi.ldap.object.trustURLCodebase" nocase
        $d6 = "com.anbai.sec.cmd.CommandExecution" nocase
        $d7 = "(Process)'" nocase
        $d8 = "eval('" nocase
        $d9 = ".execute(" nocase
        $d10 = "ProcessBuilder(" nocase
        $d11 = "java.net.URL" nocase
        $d12 = "$$BCEL$$" nocase
    condition:
        all of ($jsp*) and (($req and (strsuspectfile or any of ($d*))) or 3 of ($obf*))
}

rule SuspectPY
{
    meta:
        description = "Suspect Python code"
        author = "Lionel PRAT"
        filetype = "PY"
        
    strings:
        $py1 = "import socket" nocase
        $py2 = "import subprocess" nocase
        $py3 = "import paramiko" nocase
        $pc = "import os" nocase
        $cc = "system(" nocase
        $cmd1 = "check_output(" nocase
        $cmd2 = "popen" nocase
        $cmd3 = "run(" nocase
        
    condition:
        any of ($py*) and (strsuspectfile or any of ($cmd*)) or ($pc and $cc)
}
