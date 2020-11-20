rule suspect_proc
{
    meta:
        description = "Suspect string in memory"
        author = "Lionel PRAT"
        filetype = "ALL"
        
    strings:
        $ = "pwndns.pw" nocase ascii wide  /* malware miner */
        $ = "ipify.org" nocase ascii wide /* get my ip */
        $ = "45.9.148." nocase ascii wide /* monero ip */
        $ = "PRIVMSG " nocase ascii wide /* Potential command IRC*/
        $ = "</cfexecute>" nocase ascii wide /* coldfusion */
        $ = "User-Agent:" nocase ascii wide /* Potential make header HTTP */
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
        $ = "content-type: " nocase ascii wide /* Potential make header HTTP  - more false positive */ 
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
