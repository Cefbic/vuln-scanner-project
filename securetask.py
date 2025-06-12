#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author     : Monsif Bichara
# Tool       : Securetask
# Usage      : python3 Securetask example.com
# Description: Securetask is a versatile web vulnerability scanner that integrates multiple tools to identify vulnerabilities.

# Importing required libraries
import sys
import argparse
import subprocess
import os
import time
import random
import threading
import re
import random
from urllib.parse import urlsplit


CURSOR_UP_ONE = '\x1b[1A' 
ERASE_LINE = '\x1b[2K'

# Function to calculate elapsed time in a readable format
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )
def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])


# Function to determine the size of the terminal
def terminal_size():
    try:
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        return int(columns)
    except subprocess.CalledProcessError as e:
        return int(20)
    


# Function to process and normalize a URL
def url_maker(url):
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host

# Function to verify internet connectivity
def check_internet():
    os.system('ping -c1 github.com > rs_net 2>&1')
    if "0% packet loss" in open('rs_net').read():
        val = 1
    else:
        val = 0
    os.system('rm rs_net > /dev/null 2>&1')
    return val


# Class to define color codes for terminal output
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT  = '\033[41m' # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END   = '\x1b[0m'


# Function to categorize the severity of vulnerabilities
def vul_info(val):
    result =''
    if val == 'c':
        result = bcolors.BG_CRIT_TXT+" critical "+bcolors.ENDC
    elif val == 'h':
        result = bcolors.BG_HIGH_TXT+" high "+bcolors.ENDC
    elif val == 'm':
        result = bcolors.BG_MED_TXT+" medium "+bcolors.ENDC
    elif val == 'l':
        result = bcolors.BG_LOW_TXT+" low "+bcolors.ENDC
    else:
        result = bcolors.BG_INFO_TXT+" info "+bcolors.ENDC
    return result

# Symbols to represent the severity of processes
proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med  = bcolors.WARNING + "●" + bcolors.ENDC
proc_low  = bcolors.OKGREEN + "●" + bcolors.ENDC

# Function to link vulnerabilities with their severity and remediation details
def vul_remed_info(v1,v2,v3):
    print(bcolors.BOLD+"Vulnerability Threat Level"+bcolors.ENDC)
    print("\t"+vul_info(v2)+" "+bcolors.WARNING+str(tool_resp[v1][0])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Definition"+bcolors.ENDC)
    print("\t"+bcolors.BADFAIL+str(tools_fix[v3-1][1])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Remediation"+bcolors.ENDC)
    print("\t"+bcolors.OKGREEN+str(tools_fix[v3-1][2])+bcolors.ENDC)


# Function to display help and usage instructions
def helper():
        print(bcolors.OKBLUE+"Information:"+bcolors.ENDC)
        print("------------")
        print("\t./securetask.py example.com: Scans the domain example.com.")
        print("\t./securetask.py example.com --skip dmitry --skip theHarvester: Skip the 'dmitry' and 'theHarvester' tests.")
        print("\t./securetask.py example.com --nospinner: Disable the idle loader/spinner.")
        print("\t./securetask.py --update   : Updates the scanner to the latest version.")
        print("\t./securetask.py --help     : Displays this help context.")
        print(bcolors.OKBLUE+"Interactive:"+bcolors.ENDC)
        print("------------")
        print("\tCtrl+C: Skips current test.")
        print("\tCtrl+Z: Quits securetask.")
        print(bcolors.OKBLUE+"Legends:"+bcolors.ENDC)
        print("--------")
        print("\t["+proc_high+"]: Scan process may take longer times (not predictable).")
        print("\t["+proc_med+"]: Scan process may take less than 10 minutes.")
        print("\t["+proc_low+"]: Scan process may take less than a minute or two.")
        print(bcolors.OKBLUE+"Vulnerability Information:"+bcolors.ENDC)
        print("--------------------------")
        print("\t"+vul_info('c')+": Requires immediate attention as it may lead to compromise or service unavailability.")
        print("\t"+vul_info('h')+"    : May not lead to an immediate compromise, but there are considerable chances for probability.")
        print("\t"+vul_info('m')+"  : Attacker may correlate multiple vulnerabilities of this type to launch a sophisticated attack.")
        print("\t"+vul_info('l')+"     : Not a serious issue, but it is recommended to tend to the finding.")
        print("\t"+vul_info('i')+"    : Not classified as a vulnerability, simply an useful informational alert to be considered.\n")


# Function to clear the terminal line
def clear():
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K") # Clears until the end of the line

# Function to display the SecureTask logo
def logo():
    print(bcolors.WARNING)
    logo_ascii = """
                     """+bcolors.ENDC+"""(The Multi-Tool Web Vulnerability Scanner)

                     New tool, """+bcolors.BG_LOW_TXT+"""SecureTask"""+bcolors.ENDC+""" for detecting vulnerabilities
    """
    print(logo_ascii)
    print(bcolors.ENDC)


# Class to handle the spinner/loader animation
class Spinner:
    busy = False
    delay = 0.005 # 0.05

    @staticmethod
    def spinning_cursor():
        while 1:
            #for cursor in '|/-\\/': yield cursor #←↑↓→
            #for cursor in '←↑↓→': yield cursor
            #for cursor in '....scanning...please..wait....': yield cursor
            for cursor in ' ': yield cursor
    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay
        self.disabled = False

    def spinner_task(self):
        inc = 0
        try:
            while self.busy:
                if not self.disabled:
                    x = bcolors.BG_SCAN_TXT_START+next(self.spinner_generator)+bcolors.BG_SCAN_TXT_END
                    inc = inc + 1
                    print(x,end='')
                    if inc>random.uniform(0,terminal_size()): #30 init
                        print(end="\r")
                        bcolors.BG_SCAN_TXT_START = '\x1b[6;30;'+str(round(random.uniform(40,47)))+'m'
                        inc = 0
                    sys.stdout.flush()
                time.sleep(self.delay)
                if not self.disabled:
                    sys.stdout.flush()

        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"securetask received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

    def start(self):
        self.busy = True
        try:
            threading.Thread(target=self.spinner_task).start()
        except Exception as e:
            print("\n")
        
    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"securetask received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

# End of loader/spinner class

# Instantiating the spinner/loader class
spinner = Spinner()



# Scanners that will be used and filename rotation (default: enabled (1))
tool_names = [
                #1
                ["host","Host - Verifies the presence of an IPv6 address.","host",1],

                #2
                ["aspnet_config_err","ASP.Net Misconfiguration - Identifies ASP.Net setup issues.","wget",1],

                #3
                ["wp_check","WordPress Detector - Confirms WordPress installation.","wget",1],

                #4
                ["drp_check", "Drupal Detector - Confirms Drupal installation.","wget",1],

                #5
                ["joom_check", "Joomla Detector - Confirms Joomla installation.","wget",1],

                #6
                ["uniscan","Uniscan - Scans for robots.txt and sitemap.xml files.","uniscan",1],

                #7
                ["wafw00f","Wafw00f - Detects the presence of web application firewalls.","wafw00f",1],

                #8
                ["nmap","Nmap - Quick scan for a limited set of ports.","nmap",1],

                #9
                ["theHarvester","The Harvester - Gathers email addresses using passive search.","theHarvester",1],

                #10
                ["dnsrecon","DNSRecon - Attempts zone transfers on DNS servers.","dnsrecon",1],

                #11
                #["fierce","Fierce - Tries zone transfers without brute-forcing.","fierce",1],

                #12
                ["dnswalk","DNSWalk - Performs zone transfer attempts.","dnswalk",1],

                #13
                ["whois","WHOis - Retrieves administrator contact details.","whois",1],

                #14
                ["nmap_header","Nmap [XSS Header Check] - Verifies XSS protection headers.","nmap",1],

                #15
                ["nmap_sloris","Nmap [Slowloris Test] - Checks for Slowloris DoS vulnerability.","nmap",1],

                #16
                ["sslyze_hbleed","SSLyze - Scans for Heartbleed vulnerability.","sslyze",1],

                #17
                ["nmap_hbleed","Nmap [Heartbleed Test] - Scans for Heartbleed vulnerability.","nmap",1],

                #18
                ["nmap_poodle","Nmap [POODLE Test] - Checks for POODLE vulnerability.","nmap",1],

                #19
                ["nmap_ccs","Nmap [CCS Injection Test] - Scans for OpenSSL CCS Injection.","nmap",1],

                #20
                ["nmap_freak","Nmap [FREAK Test] - Checks for FREAK vulnerability.","nmap",1],

                #21
                ["nmap_logjam","Nmap [LOGJAM Test] - Scans for LOGJAM vulnerability.","nmap",1],

                #22
                ["sslyze_ocsp","SSLyze - Verifies OCSP stapling.","sslyze",1],

                #23
                ["sslyze_zlib","SSLyze - Checks for ZLib compression support.","sslyze",1],

                #24
                ["sslyze_reneg","SSLyze - Tests secure renegotiation support.","sslyze",1],

                #25
                ["sslyze_resum","SSLyze - Checks session resumption with IDs or TLS tickets.","sslyze",1],

                #26
                ["lbd","LBD - Detects DNS/HTTP load balancers.","lbd",1],

                #27
                ["golismero_dns_malware","Golismero - Scans for domain spoofing or hijacking.","golismero",1],

                #28
                ["golismero_heartbleed","Golismero - Scans for Heartbleed vulnerability.","golismero",1],

                #29
                ["golismero_brute_url_predictables","Golismero - Brute-forces predictable URLs.","golismero",1],

                #30
                ["golismero_brute_directories","Golismero - Brute-forces directory paths.","golismero",1],

                #31
                ["golismero_sqlmap","Golismero - Uses SQLMap to retrieve database banners.","golismero",1],

                #32
                ["dirb","DirB - Brute-forces open directories on the target.","dirb",1],

                #33
                ["xsser","XSSer - Detects cross-site scripting vulnerabilities.","xsser",1],

                #34
                ["golismero_ssl_scan","Golismero - Performs SSL-related scans.","golismero",1],

                #35
                ["golismero_zone_transfer","Golismero - Attempts DNS zone transfers.","golismero",1],

                #36
                ["golismero_nikto","Golismero - Uses Nikto plugin to find vulnerabilities.","golismero",1],

                #37
                ["golismero_brute_subdomains","Golismero - Brute-forces subdomain discovery.","golismero",1],

                #38
                ["dnsenum_zone_transfer","DNSEnum - Attempts DNS zone transfers.","dnsenum",1],

                #39
                ["fierce_brute_subdomains","Fierce - Brute-forces subdomain discovery.","fierce",1],

                #40
                ["dmitry_email","DMitry - Passively collects email addresses.","dmitry",1],

                #41
                ["dmitry_subdomains","DMitry - Passively collects subdomains.","dmitry",1],

                #42
                ["nmap_telnet","Nmap [TELNET Test] - Checks for TELNET service.","nmap",1],

                #43
                ["nmap_ftp","Nmap [FTP Test] - Checks for FTP service.","nmap",1],

                #44
                ["nmap_stuxnet","Nmap [STUXNET Test] - Detects STUXNET worm.","nmap",1],

                #45
                ["webdav","WebDAV - Checks if WebDAV is enabled.","davtest",1],

                #46
                ["golismero_finger","Golismero - Performs domain fingerprinting.","golismero",1],

                #47
                ["uniscan_filebrute","Uniscan - Brute-forces filenames on the domain.","uniscan",1],

                #48
                ["uniscan_dirbrute", "Uniscan - Brute-forces directories on the domain.","uniscan",1],

                #49
                ["uniscan_ministresser", "Uniscan - Stress-tests the domain.","uniscan",1],

                #50
                ["uniscan_rfi","Uniscan - Checks for LFI, RFI, and RCE vulnerabilities.","uniscan",1],

                #51
                ["uniscan_xss","Uniscan - Scans for XSS, SQLi, and other vulnerabilities.","uniscan",1],

                #52
                ["nikto_xss","Nikto - Checks for Apache XSS headers.","nikto",1],

                #53
                ["nikto_subrute","Nikto - Brute-forces subdomains.","nikto",1],

                #54
                ["nikto_shellshock","Nikto - Detects Shellshock vulnerability.","nikto",1],

                #55
                ["nikto_internalip","Nikto - Checks for internal IP leaks.","nikto",1],

                #56
                ["nikto_putdel","Nikto - Checks for HTTP PUT and DELETE methods.","nikto",1],

                #57
                ["nikto_headers","Nikto - Analyzes domain headers.","nikto",1],

                #58
                ["nikto_ms01070","Nikto - Detects MS10-070 vulnerability.","nikto",1],

                #59
                ["nikto_servermsgs","Nikto - Checks for server issues.","nikto",1],

                #60
                ["nikto_outdated","Nikto - Detects outdated servers.","nikto",1],

                #61
                ["nikto_httpoptions","Nikto - Checks HTTP options on the domain.","nikto",1],

                #62
                ["nikto_cgi","Nikto - Enumerates CGI directories.","nikto",1],

                #63
                ["nikto_ssl","Nikto - Performs SSL checks.","nikto",1],

                #64
                ["nikto_sitefiles","Nikto - Searches for interesting files on the domain.","nikto",1],

                #65
                ["nikto_paths","Nikto - Detects injectable paths.","nikto",1],

                #66
                ["dnsmap_brute","DNSMap - Brute-forces subdomains.","dnsmap",1],

                #67
                ["nmap_sqlserver","Nmap - Scans for MS-SQL Server database.","nmap",1],

                #68
                ["nmap_mysql", "Nmap - Scans for MySQL database.","nmap",1],

                #69
                ["nmap_oracle", "Nmap - Scans for Oracle database.","nmap",1],

                #70
                ["nmap_rdp_udp","Nmap - Checks for RDP over UDP.","nmap",1],

                #71
                ["nmap_rdp_tcp","Nmap - Checks for RDP over TCP.","nmap",1],

                #72
                ["nmap_full_ps_tcp","Nmap - Performs a full TCP port scan.","nmap",1],

                #73
                ["nmap_full_ps_udp","Nmap - Performs a full UDP port scan.","nmap",1],

                #74
                ["nmap_snmp","Nmap - Scans for SNMP service.","nmap",1],

                #75
                ["aspnet_elmah_axd","Checks for ASP.Net Elmah logger.","wget",1],

                #76
                ["nmap_tcp_smb","Checks for SMB service over TCP.","nmap",1],

                #77
                ["nmap_udp_smb","Checks for SMB service over UDP.","nmap",1],

                #78
                ["wapiti","Wapiti - Scans for SQLi, RCE, XSS, and other vulnerabilities.","wapiti",1],

                #79
                ["nmap_iis","Nmap - Checks for IIS WebDAV.","nmap",1],

                #80
                ["whatweb","WhatWeb - Analyzes X-XSS protection headers.","whatweb",1],

                #81
                ["amass","AMass - Discovers subdomains through brute-forcing.","amass",1]
            ]


# Command that is used to initiate the tool (with parameters and extra params)
tool_cmd   = [
                #1
                ["host ", ""],

                #2
                ["wget -O /tmp/securetask_temp_aspnet_config_err --tries=1 ", "/%7C~.aspx"],

                #3
                ["wget -O /tmp/securetask_temp_wp_check --tries=1 ", "/wp-admin"],

                #4
                ["wget -O /tmp/securetask_temp_drp_check --tries=1 ", "/user"],

                #5
                ["wget -O /tmp/securetask_temp_joom_check --tries=1 ", "/administrator"],

                #6
                ["uniscan -e -u ", ""],

                #7
                ["wafw00f ", ""],

                #8
                ["nmap -F --open -Pn ", ""],

                #9
                ["theHarvester -l 50 -b censys -d ", ""],

                #10
                ["dnsrecon -d ", ""],

                #11
                #["fierce -wordlist xxx -dns ", ""],

                #12
                ["dnswalk -d ", "."],

                #13
                ["whois ", ""],

                #14
                ["nmap -p80 --script http-security-headers -Pn ", ""],

                #15
                ["nmap -p80,443 --script http-slowloris --max-parallelism 500 -Pn ", ""],

                #16
                ["sslyze --heartbleed ", ""],

                #17
                ["nmap -p443 --script ssl-heartbleed -Pn ", ""],

                #18
                ["nmap -p443 --script ssl-poodle -Pn ", ""],

                #19
                ["nmap -p443 --script ssl-ccs-injection -Pn ", ""],

                #20
                ["nmap -p443 --script ssl-enum-ciphers -Pn ", ""],

                #21
                ["nmap -p443 --script ssl-dh-params -Pn ", ""],

                #22
                ["sslyze --certinfo=basic ", ""],

                #23
                ["sslyze --compression ", ""],

                #24
                ["sslyze --reneg ", ""],

                #25
                ["sslyze --resum ", ""],

                #26
                ["lbd ", ""],

                #27
                ["golismero -e dns_malware scan ", ""],

                #28
                ["golismero -e heartbleed scan ", ""],

                #29
                ["golismero -e brute_url_predictables scan ", ""],

                #30
                ["golismero -e brute_directories scan ", ""],

                #31
                ["golismero -e sqlmap scan ", ""],

                #32
                ["dirb http://", " -fi"],

                #33
                ["xsser --all=http://", ""],

                #34
                ["golismero -e sslscan scan ", ""],

                #35
                ["golismero -e zone_transfer scan ", ""],

                #36
                ["golismero -e nikto scan ", ""],

                #37
                ["golismero -e brute_dns scan ", ""],

                #38
                ["dnsenum ", ""],

                #39
                ["fierce --domain ", ""],

                #40
                ["dmitry -e ", ""],

                #41
                ["dmitry -s ", ""],

                #42
                ["nmap -p23 --open -Pn ", ""],

                #43
                ["nmap -p21 --open -Pn ", ""],

                #44
                ["nmap --script stuxnet-detect -p445 -Pn ", ""],

                #45
                ["davtest -url http://", ""],

                #46
                ["golismero -e fingerprint_web scan ", ""],

                #47
                ["uniscan -w -u ", ""],

                #48
                ["uniscan -q -u ", ""],

                #49
                ["uniscan -r -u ", ""],

                #50
                ["uniscan -s -u ", ""],

                #51
                ["uniscan -d -u ", ""],

                #52
                ["nikto -Plugins 'apache_expect_xss' -host ", ""],

                #53
                ["nikto -Plugins 'subdomain' -host ", ""],

                #54
                ["nikto -Plugins 'shellshock' -host ", ""],

                #55
                ["nikto -Plugins 'cookies' -host ", ""],

                #56
                ["nikto -Plugins 'put_del_test' -host ", ""],

                #57
                ["nikto -Plugins 'headers' -host ", ""],

                #58
                ["nikto -Plugins 'ms10-070' -host ", ""],

                #59
                ["nikto -Plugins 'msgs' -host ", ""],

                #60
                ["nikto -Plugins 'outdated' -host ", ""],

                #61
                ["nikto -Plugins 'httpoptions' -host ", ""],

                #62
                ["nikto -Plugins 'cgi' -host ", ""],

                #63
                ["nikto -Plugins 'ssl' -host ", ""],

                #64
                ["nikto -Plugins 'sitefiles' -host ", ""],

                #65
                ["nikto -Plugins 'paths' -host ", ""],

                #66
                ["dnsmap ", ""],

                #67
                ["nmap -p1433 --open -Pn ", ""],

                #68
                ["nmap -p3306 --open -Pn ", ""],

                #69
                ["nmap -p1521 --open -Pn ", ""],

                #70
                ["nmap -p3389 --open -sU -Pn ", ""],

                #71
                ["nmap -p3389 --open -sT -Pn ", ""],

                #72
                ["nmap -p1-65535 --open -Pn ", ""],

                #73
                ["nmap -p1-65535 -sU --open -Pn ", ""],

                #74
                ["nmap -p161 -sU --open -Pn ", ""],

                #75
                ["wget -O /tmp/securetask_temp_aspnet_elmah_axd --tries=1 ", "/elmah.axd"],

                #76
                ["nmap -p445,137-139 --open -Pn ", ""],

                #77
                ["nmap -p137,138 --open -Pn ", ""],

                #78
                ["wapiti ", " -f txt -o securetask_temp_wapiti"],

                #79
                ["nmap -p80 --script=http-iis-webdav-vuln -Pn ", ""],

                #80
                ["whatweb ", " -a 1"],

                #81
                ["amass enum -d ", ""]
            ]


# Tool Responses (Begins) [Responses + Severity (c - critical | h - high | m - medium | l - low | i - informational) + Reference for Vuln Definition and Remediation]
tool_resp = [
                #1
                ["IPv6 address not detected. It is beneficial to have one for enhanced security.","i",1],

                #2
                ["ASP.Net is configured to display server stack errors, which may expose sensitive information.","m",2],

                #3
                ["WordPress installation identified. Verify vulnerabilities associated with the detected version.","i",3],

                #4
                ["Drupal installation identified. Verify vulnerabilities associated with the detected version.","i",4],

                #5
                ["Joomla installation identified. Verify vulnerabilities associated with the detected version.","i",5],

                #6
                ["robots.txt or sitemap.xml found. Review these files for any sensitive information.","i",6],

                #7
                ["No Web Application Firewall (WAF) detected, which may leave the application exposed.","m",7],

                #8
                ["Open ports detected. Consider performing a comprehensive scan manually.","l",8],

                #9
                ["Email addresses discovered. These could be used for further reconnaissance.","l",9],

                #10
                ["DNS zone transfer succeeded using DNSRecon. Immediate reconfiguration is advised.","h",10],

                #11
                #["DNS zone transfer succeeded using fierce. Immediate reconfiguration is advised.","h",10],

                #12
                ["DNS zone transfer succeeded using dnswalk. Immediate reconfiguration is advised.","h",10],

                #13
                ["Whois information is publicly accessible. This may aid attackers in reconnaissance.","i",11],

                #14
                ["XSS protection headers are missing, leaving the application vulnerable to reflected XSS attacks.","m",12],

                #15
                ["Vulnerable to Slowloris Denial of Service (DoS) attacks.","c",13],

                #16
                ["Heartbleed vulnerability detected using SSLyze.","h",14],

                #17
                ["Heartbleed vulnerability detected using Nmap.","h",14],

                #18
                ["POODLE vulnerability identified, which affects SSL 3.0 protocol.","h",15],

                #19
                ["OpenSSL CCS injection vulnerability detected, allowing potential data compromise.","h",16],

                #20
                ["FREAK vulnerability identified, which weakens encryption strength.","h",17],

                #21
                ["LOGJAM vulnerability detected, which allows attackers to downgrade encryption.","h",18],

                #22
                ["OCSP response is unsuccessful, indicating potential issues with certificate validation.","m",19],

                #23
                ["Server supports Deflate compression, which may lead to BREACH attacks.","m",20],

                #24
                ["Secure renegotiation is supported, which may allow plaintext injection attacks.","m",21],

                #25
                ["Session resumption is not supported, which may weaken TLS security.","m",22],

                #26
                ["No DNS or HTTP load balancers detected, which may increase the risk of DoS attacks.","l",23],

                #27
                ["Domain appears to be spoofed or hijacked, posing a significant security risk.","h",24],

                #28
                ["Heartbleed vulnerability detected using Golismero.","h",14],

                #29
                ["Sensitive files identified using Golismero brute force.","m",25],

                #30
                ["Open directories identified using Golismero brute force.","m",26],

                #31
                ["Database banner retrieved using SQLMap, which may reveal sensitive information.","l",27],

                #32
                ["Open directories identified using DirB.","m",26],

                #33
                ["Cross-site scripting (XSS) vulnerabilities detected using XSSer.","c",28],

                #34
                ["SSL-related vulnerabilities identified using Golismero.","m",29],

                #35
                ["DNS zone transfer succeeded using Golismero. Immediate reconfiguration is advised.","h",10],

                #36
                ["Vulnerabilities identified using Golismero Nikto plugin.","m",30],

                #37
                ["Subdomains discovered using Golismero, which may expand the attack surface.","m",31],

                #38
                ["DNS zone transfer succeeded using DNSEnum. Immediate reconfiguration is advised.","h",10],

                #39
                ["Subdomains discovered using Fierce, which may expand the attack surface.","m",31],

                #40
                ["Email addresses discovered using DMitry, which may aid in reconnaissance.","l",9],

                #41
                ["Subdomains discovered using DMitry, which may expand the attack surface.","m",31],

                #42
                ["Telnet service detected, which is outdated and insecure.","h",32],

                #43
                ["FTP service detected, which lacks secure communication.","c",33],

                #44
                ["System appears vulnerable to Stuxnet worm.","c",34],

                #45
                ["WebDAV is enabled, which may expose the system to vulnerabilities.","m",35],

                #46
                ["Fingerprinting revealed information about the target system.","l",36],

                #47
                ["Sensitive files identified using Uniscan.","m",25],

                #48
                ["Open directories identified using Uniscan.","m",26],

                #49
                ["System is vulnerable to stress tests, which may lead to DoS attacks.","h",37],

                #50
                ["Uniscan detected potential LFI, RFI, or RCE vulnerabilities.","h",38],

                #51
                ["Uniscan detected potential XSS, SQLi, or BSQLi vulnerabilities.","h",39],

                #52
                ["Apache XSS protection headers are missing.","m",12],

                #53
                ["Subdomains discovered using Nikto, which may expand the attack surface.","m",31],

                #54
                ["Web server is vulnerable to the Shellshock bug.","c",40],

                #55
                ["Internal IP addresses are exposed, which may aid attackers.","l",41],

                #56
                ["HTTP PUT and DELETE methods are enabled, which may allow file manipulation.","m",42],

                #57
                ["Vulnerable headers are exposed, which may reveal sensitive information.","m",43],

                #58
                ["Web server is vulnerable to MS10-070, which may allow data tampering.","h",44],

                #59
                ["Issues detected on the web server, which may require further investigation.","m",30],

                #60
                ["Web server is outdated, which may contain unpatched vulnerabilities.","h",45],

                #61
                ["Issues detected with HTTP options, which may expose the system to risks.","l",42],

                #62
                ["CGI directories enumerated, which may reveal sensitive information.","l",26],

                #63
                ["SSL vulnerabilities identified, which may compromise secure communication.","m",29],

                #64
                ["Interesting files detected, which may contain sensitive information.","m",25],

                #65
                ["Injectable paths detected, which may allow SQL injection attacks.","l",46],

                #66
                ["Subdomains discovered using DNSMap, which may expand the attack surface.","m",31],

                #67
                ["MS-SQL database service detected, which may reveal sensitive information.","l",47],

                #68
                ["MySQL database service detected, which may reveal sensitive information.","l",47],

                #69
                ["Oracle database service detected, which may reveal sensitive information.","l",47],

                #70
                ["RDP service detected over UDP, which may expose the system to attacks.","h",48],

                #71
                ["RDP service detected over TCP, which may expose the system to attacks.","h",48],

                #72
                ["Open TCP ports detected, which may require further investigation.","l",8],

                #73
                ["Open UDP ports detected, which may require further investigation.","l",8],

                #74
                ["SNMP service detected, which may expose sensitive information.","m",49],

                #75
                ["Elmah logger is configured, which may expose sensitive logs.","m",50],

                #76
                ["SMB ports are open over TCP, which may expose the system to attacks.","m",51],

                #77
                ["SMB ports are open over UDP, which may expose the system to attacks.","m",51],

                #78
                ["Wapiti identified multiple vulnerabilities, which may require further investigation.","h",30],

                #79
                ["IIS WebDAV is enabled, which may expose the system to vulnerabilities.","m",35],

                #80
                ["X-XSS protection headers are missing, which may leave the application vulnerable.","m",12],

                #81
                ["Subdomains discovered using AMass, which may expand the attack surface.","m",31]
            ]

# Tool Responses (Ends)



# Tool Status (Response Data + Response Code (if status check fails and you still got to push it + Legends + Approx Time + Tool Identification + Bad Responses)
tool_status = [
                #1
                ["IPv6 support detected", 1, proc_low, " < 15s", "ipv6", ["not found", "has IPv6"]],

                #2
                ["Server error encountered", 0, proc_low, " < 30s", "asp.netmisconf", ["unable to resolve host address", "Connection timed out"]],

                #3
                ["WordPress login page identified", 0, proc_low, " < 30s", "wpcheck", ["unable to resolve host address", "Connection timed out"]],

                #4
                ["Drupal installation detected", 0, proc_low, " < 30s", "drupalcheck", ["unable to resolve host address", "Connection timed out"]],

                #5
                ["Joomla installation detected", 0, proc_low, " < 30s", "joomlacheck", ["unable to resolve host address", "Connection timed out"]],

                #6
                ["robots.txt or sitemap.xml found", 0, proc_low, " < 40s", "robotscheck", ["Use of uninitialized value in unpack at"]],

                #7
                ["No Web Application Firewall (WAF) detected", 0, proc_low, " < 45s", "wafcheck", ["appears to be down"]],

                #8
                ["Open TCP ports detected", 0, proc_med, " <  2m", "nmapopen", ["Failed to resolve"]],

                #9
                ["No email addresses discovered", 1, proc_med, " <  3m", "harvester", ["No hosts found", "No emails found"]],

                #10
                ["DNS zone transfer succeeded", 0, proc_low, " < 20s", "dnsreconzt", ["Could not resolve domain"]],

                #11
                ["No errors detected in DNS zone transfer", 0, proc_low, " < 35s", "dnswalkzt", ["!!!0 failures, 0 warnings, 3 errors."]],

                #12
                ["Administrator email found", 0, proc_low, " < 25s", "whois", ["No match for domain"]],

                #13
                ["XSS filter disabled", 0, proc_low, " < 20s", "nmapxssh", ["Failed to resolve"]],

                #14
                ["Denial of Service vulnerability detected", 0, proc_high, " < 45m", "nmapdos", ["Failed to resolve"]],

                #15
                ["Heartbleed vulnerability detected", 0, proc_low, " < 40s", "sslyzehb", ["Could not resolve hostname"]],

                #16
                ["Vulnerability identified", 0, proc_low, " < 30s", "nmap1", ["Failed to resolve"]],

                #17
                ["Vulnerability identified", 0, proc_low, " < 35s", "nmap2", ["Failed to resolve"]],

                #18
                ["Vulnerability identified", 0, proc_low, " < 35s", "nmap3", ["Failed to resolve"]],

                #19
                ["Vulnerability identified", 0, proc_low, " < 30s", "nmap4", ["Failed to resolve"]],

                #20
                ["Vulnerability identified", 0, proc_low, " < 35s", "nmap5", ["Failed to resolve"]],

                #21
                ["OCSP response unsuccessful", 0, proc_low, " < 25s", "sslyze1", ["Could not resolve hostname"]],

                #22
                ["Vulnerability identified", 0, proc_low, " < 30s", "sslyze2", ["Could not resolve hostname"]],

                #23
                ["Vulnerability identified", 0, proc_low, " < 25s", "sslyze3", ["Could not resolve hostname"]],

                #24
                ["Vulnerability identified", 0, proc_low, " < 30s", "sslyze4", ["Could not resolve hostname"]],

                #25
                ["Load balancing not detected", 0, proc_med, " <  4m", "lbd", ["NOT FOUND"]],

                #26
                ["No vulnerabilities found", 1, proc_low, " < 45s", "golism1", ["Cannot resolve domain name", "No vulnerabilities found"]],

                #27
                ["No vulnerabilities found", 1, proc_low, " < 40s", "golism2", ["Cannot resolve domain name", "No vulnerabilities found"]],

                #28
                ["No vulnerabilities found", 1, proc_low, " < 45s", "golism3", ["Cannot resolve domain name", "No vulnerabilities found"]],

                #29
                ["No vulnerabilities found", 1, proc_low, " < 40s", "golism4", ["Cannot resolve domain name", "No vulnerabilities found"]],

                #30
                ["No vulnerabilities found", 1, proc_low, " < 45s", "golism5", ["Cannot resolve domain name", "No vulnerabilities found"]],

                #31
                ["No directories found", 1, proc_high, " < 35m", "dirb", ["COULDNT RESOLVE HOST", "FOUND: 0"]],

                #32
                ["No vulnerabilities detected", 1, proc_med, " <  4m", "xsser", ["XSSer is not working properly!", "Could not find any vulnerability!"]],

                #33
                ["No subdomains found", 0, proc_low, " < 45s", "golism6", ["Cannot resolve domain name"]],

                #34
                ["DNS zone transfer successful", 0, proc_low, " < 30s", "golism7", ["Cannot resolve domain name"]],

                #35
                ["No vulnerabilities found using Nikto", 1, proc_med, " <  4m", "golism8", ["Cannot resolve domain name", "Nikto found 0 vulnerabilities"]],

                #36
                ["Possible subdomain leak detected", 0, proc_high, " < 30m", "golism9", ["Cannot resolve domain name"]],

                #37
                ["AXFR record query failed", 1, proc_low, " < 45s", "dnsenumzt", ["NS record query failed:", "AXFR record query failed", "no NS record for"]],

                #38
                ["No entries found", 1, proc_high, " < 75m", "fierce2", ["Found 0 entries", "is gimp"]],

                #39
                ["No email addresses found", 1, proc_low, " < 30s", "dmitry1", ["Unable to locate Host IP addr", "Found 0 E-Mail(s)"]],

                #40
                ["No subdomains found", 1, proc_low, " < 35s", "dmitry2", ["Unable to locate Host IP addr", "Found 0 possible subdomain(s)"]],

                #41
                ["Telnet service detected", 0, proc_low, " < 15s", "nmaptelnet", ["Failed to resolve"]],

                #42
                ["FTP service detected", 0, proc_low, " < 15s", "nmapftp", ["Failed to resolve"]],

                #43
                ["Stuxnet vulnerability detected", 0, proc_low, " < 20s", "nmapstux", ["Failed to resolve"]],

                #44
                ["WebDAV enabled", 0, proc_low, " < 30s", "webdav", ["is not DAV enabled or not accessible."]],

                #45
                ["No vulnerabilities found", 1, proc_low, " < 15s", "golism10", ["Cannot resolve domain name", "No vulnerabilities found"]],

                #46
                ["Uniscan detected potential issues", 0, proc_med, " <  2m", "uniscan2", ["Use of uninitialized value in unpack at"]],

                #47
                ["Uniscan detected potential issues", 0, proc_med, " <  5m", "uniscan3", ["Use of uninitialized value in unpack at"]],

                #48
                ["Uniscan detected potential issues", 0, proc_med, " <  9m", "uniscan4", ["Use of uninitialized value in unpack at"]],

                #49
                ["Uniscan detected potential issues", 0, proc_med, " <  8m", "uniscan5", ["Use of uninitialized value in unpack at"]],

                #50
                ["Uniscan detected potential issues", 0, proc_med, " <  9m", "uniscan6", ["Use of uninitialized value in unpack at"]],

                #51
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto1", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #52
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto2", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #53
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto3", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #54
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto4", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #55
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto5", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #56
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto6", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #57
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto7", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #58
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto8", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #59
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto9", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #60
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto10", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #61
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto11", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #62
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto12", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #63
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto13", ["ERROR: Cannot resolve hostname", "0 item(s) reported", "No web server found", "0 host(s) tested"]],

                #64
                ["No vulnerabilities reported", 1, proc_low, " < 35s", "nikto14", ["ERROR: Cannot resolve hostname", "0 item(s) reported"]],

                #65
                ["No subdomains or IPs found", 0, proc_high, " < 30m", "dnsmap_brute", ["[+] 0 (sub)domains and 0 IP address(es) found"]],

                #66
                ["SQL Server detected", 0, proc_low, " < 15s", "nmapmssql", ["Failed to resolve"]],

                #67
                ["MySQL service detected", 0, proc_low, " < 15s", "nmapmysql", ["Failed to resolve"]],

                #68
                ["Oracle database detected", 0, proc_low, " < 15s", "nmaporacle", ["Failed to resolve"]],

                #69
                ["RDP over UDP detected", 0, proc_low, " < 15s", "nmapudprdp", ["Failed to resolve"]],

                #70
                ["RDP over TCP detected", 0, proc_low, " < 15s", "nmaptcprdp", ["Failed to resolve"]],

                #71
                ["Full TCP port scan completed", 0, proc_high, " > 50m", "nmapfulltcp", ["Failed to resolve"]],

                #72
                ["Full UDP port scan completed", 0, proc_high, " > 75m", "nmapfulludp", ["Failed to resolve"]],

                #73
                ["SNMP service detected", 0, proc_low, " < 30s", "nmapsnmp", ["Failed to resolve"]],

                #74
                ["Elmah logger detected", 0, proc_low, " < 30s", "elmahxd", ["unable to resolve host address", "Connection timed out"]],

                #75
                ["SMB service over TCP detected", 0, proc_low, " < 20s", "nmaptcpsmb", ["Failed to resolve"]],

                #76
                ["SMB service over UDP detected", 0, proc_low, " < 20s", "nmapudpsmb", ["Failed to resolve"]],

                #77
                ["Wapiti scan completed", 0, proc_med, " < 5m", "wapiti", ["none"]],

                #78
                ["WebDAV enabled on IIS", 0, proc_low, " < 40s", "nmapwebdaviis", ["Failed to resolve"]],

                #79
                ["X-XSS protection headers missing", 1, proc_med, " < 3m", "whatweb", ["Timed out", "Socket error", "X-XSS-Protection[1"]],

                #80
                ["No subdomains discovered", 1, proc_med, " < 15m", "amass", ["The system was unable to build the pool of resolvers"]]
            ]

# Vulnerabilities and Remediation
tools_fix = [
                    [1, "This is an informational alert indicating the absence of IPv6 support. IPv6 enhances security by integrating IPSec, which ensures confidentiality, integrity, and availability.",
                            "Consider implementing IPv6 for better security. Refer to this guide for implementation details: https://www.cisco.com/c/en/us/solutions/collateral/enterprise/cisco-on-cisco/IPv6-Implementation_CS.html"],
                    [2, "Sensitive information leakage detected. The ASP.Net application does not sanitize illegal characters in the URL, allowing attackers to extract server stack details using special characters like '%7C~.aspx'.",
                            "Filter special characters in URLs and configure custom error pages to avoid exposing sensitive information. Learn more here: https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs"],
                    [3, "Having WordPress as a CMS is not inherently risky, but vulnerabilities may exist in the version or third-party plugins.",
                            "Conceal the WordPress version and follow security best practices. Refer to this guide: https://codex.wordpress.org/Hardening_WordPress"],
                    [4, "Using Drupal as a CMS is not inherently risky, but vulnerabilities may exist in the version or third-party plugins.",
                            "Conceal the Drupal version and follow security best practices. Refer to this guide: https://www.drupal.org/docs/7/site-building-best-practices/ensure-that-your-site-is-secure"],
                    [5, "Using Joomla as a CMS is not inherently risky, but vulnerabilities may exist in the version or third-party plugins.",
                            "Conceal the Joomla version and follow security best practices. Refer to this guide: https://www.incapsula.com/blog/10-tips-to-improve-your-joomla-website-security.html"],
                    [6, "robots.txt or sitemap.xml files may expose sensitive links that attackers can access directly, bypassing search engine restrictions.",
                            "Avoid including sensitive links in robots.txt or sitemap.xml files."],
                    [7, "Without a Web Application Firewall (WAF), attackers can exploit vulnerabilities or launch automated attacks, potentially causing a Denial of Service (DoS).",
                            "Implement a WAF to protect against common web attacks like XSS and SQL injection. Learn more here: https://www.gartner.com/reviews/market/web-application-firewall"],
                    [8, "Open ports provide attackers with information about running services, which can be exploited.",
                            "Close unused ports and use a firewall to filter traffic. Refer to this guide: https://security.stackexchange.com/a/145781/6137"],
                    [9, "Email addresses can aid attackers in brute-force attacks or reconnaissance, though the risk is minimal.",
                            "Use unique usernames for different services to reduce the risk of exploitation."],
                    [10, "DNS zone transfers expose critical information about the target's topology, giving attackers a complete view of the host.",
                            "Restrict zone transfers to specific IPs. Learn more here: https://www.sans.org/reading-room/whitepapers/dns/securing-dns-zone-transfer-868"],
                    [11, "Publicly available administrator contact details can aid attackers in reconnaissance.",
                            "Mask sensitive information if not intentionally made public. Learn more here: http://www.name.com/blog/how-tos/tutorial-2/2013/06/protect-your-personal-information-with-whois-privacy/"],
                    [12, "Missing X-XSS protection headers leave older browsers vulnerable to reflected XSS attacks.",
                            "Upgrade older browsers to modern versions to mitigate this issue."],
                    [13, "Slowloris attacks keep multiple connections open to exhaust server resources, leading to a Denial of Service (DoS).",
                            "Use Apache's `mod_antiloris` or similar tools to mitigate this attack. Learn more here: https://www.acunetix.com/blog/articles/slow-http-dos-attacks-mitigate-apache-http-server/"],
                    [14, "The Heartbleed vulnerability allows attackers to extract sensitive data from memory during a TLS session.",
                            "Implement Perfect Forward Secrecy (PFS) and upgrade OpenSSL. Learn more here: http://heartbleed.com/"],
                    [15, "The POODLE vulnerability allows attackers to decrypt sensitive data in SSL 3.0 sessions.",
                            "Disable SSL 3.0 protocol. Learn more here: https://www.us-cert.gov/ncas/alerts/TA14-290A"],
                    [16, "The CCS Injection vulnerability allows attackers to intercept and decrypt SSL/TLS traffic during the handshake process.",
                            "Upgrade OpenSSL to the latest version. Learn more here: http://ccsinjection.lepidum.co.jp/"],
                    [17, "The FREAK vulnerability weakens encryption, enabling attackers to perform Man-in-the-Middle (MiTM) attacks.",
                            "Upgrade OpenSSL to the latest version. Learn more here: https://bobcares.com/blog/how-to-fix-sweet32-birthday-attacks-vulnerability-cve-2016-2183/"],
                    [18, "The LogJam attack downgrades TLS connections, allowing attackers to intercept and modify data.",
                            "Use 2048-bit or larger Diffie-Hellman primes and update TLS libraries. Learn more here: https://weakdh.org/"],
                    [19, "Malformed ClientHello handshake messages can cause OpenSSL to crash or leak sensitive information.",
                            "Upgrade OpenSSL to a secure version. Learn more here: https://www.openssl.org/news/secadv/20110208.txt"],
                    [20, "The BREACH attack exploits HTTP compression to extract sensitive data like session tokens.",
                            "Disable Zlib compression and follow additional mitigation steps. Learn more here: http://breachattack.com/"],
                    [21, "Plain-text injection attacks exploit SSL renegotiation to insert data into HTTPS sessions.",
                            "Disable SSL renegotiation or follow secure configuration practices. Learn more here: https://securingtomorrow.mcafee.com/technical-how-to/tips-securing-ssl-renegotiation/"],
                    [22, "Session resumption vulnerabilities allow attackers to hijack existing TLS sessions.",
                            "Disable session resumption or harden its configuration. Learn more here: https://wiki.crashtest-security.com/display/KB/Harden+TLS+Session+Resumption"],
                    [23, "The absence of load balancers increases the risk of DoS attacks and affects performance during outages.",
                            "Implement load balancers to improve availability and performance. Learn more here: https://www.digitalocean.com/community/tutorials/what-is-load-balancing"],
                    [24, "DNS spoofing or hijacking can redirect users to malicious sites.",
                            "Deploy DNSSEC to ensure secure DNS resolution. Learn more here: https://www.cloudflare.com/dns/dnssec/how-dnssec-works/"],
                    [25, "Sensitive files may expose critical information to attackers.",
                            "Restrict access to sensitive files unless necessary."],
                    [26, "Open directories may expose critical information to attackers.",
                            "Restrict access to directories unless necessary."],
                    [27, "Banner information may reveal backend details, aiding attackers in targeted exploits.",
                            "Restrict banner information and minimize service exposure."],
                    [28, "XSS vulnerabilities allow attackers to steal cookies, deface websites, or redirect users to malicious sites.",
                            "Implement input validation and output sanitization. Learn more here: https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet"],
                    [29, "SSL vulnerabilities compromise confidentiality, enabling attackers to intercept communication.",
                            "Use updated SSL/TLS libraries and secure configurations."],
                    [30, "Multiple vulnerabilities detected by the scanner may expose the target to attacks.",
                            "Refer to the vulnerability report for detailed remediation steps."],
                    [31, "Subdomains may reveal additional services or vulnerabilities, expanding the attack surface.",
                            "Restrict access to sensitive subdomains and use complex naming conventions."],
                    [32, "The outdated Telnet protocol is vulnerable to MiTM and other attacks.",
                            "Replace Telnet with SSH for secure communication. Learn more here: https://www.ssh.com/ssh/telnet"],
                    [33, "FTP lacks secure communication, making it vulnerable to eavesdropping and exploits.",
                            "Use SSH instead of FTP for secure file transfers."],
                    [34, "The Stuxnet worm targets critical infrastructure and exposes sensitive information.",
                            "Perform a rootkit scan and follow remediation steps. Learn more here: https://www.symantec.com/security_response/writeup.jsp?docid=2010-071400-3123-99&tabid=3"],
                    [35, "WebDAV may allow attackers to upload malicious files or execute code.",
                            "Disable WebDAV unless necessary. Learn more here: https://www.networkworld.com/article/2202909/network-security/-webdav-is-bad---says-security-researcher.html"],
                    [36, "Server fingerprinting reveals information about the target's tech stack, aiding attackers.",
                            "Obfuscate server information to make attacks more difficult."],
                    [37, "DoS attacks flood the target with traffic, rendering services unavailable.",
                            "Use load balancers, rate limiting, and connection restrictions to mitigate DoS attacks."],
                    [38, "LFI, RFI, and RCE vulnerabilities allow attackers to execute malicious code or access sensitive files.",
                            "Follow secure coding practices to prevent these vulnerabilities. Learn more here: https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [39, "SQLi, XSS, and BSQLi vulnerabilities allow attackers to steal data or compromise the backend.",
                            "Implement input validation and secure coding practices. Learn more here: https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [40, "The Shellshock vulnerability allows attackers to execute remote code via BASH.",
                            "Patch BASH to the latest version. Learn more here: https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability"],
                    [41, "Exposed internal IP addresses provide attackers with information about the network.",
                            "Restrict banner information to prevent disclosure. Learn more here: https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed"],
                    [42, "HTTP PUT and DELETE methods may allow attackers to manipulate files on the server.",
                            "Disable these methods unless required. Learn more here: http://www.techstacks.com/howto/disable-http-methods-in-tomcat.html"],
                    [43, "Exposed headers reveal information about the tech stack, aiding attackers.",
                            "Restrict header information and minimize service exposure."],
                    [44, "The MS10-070 vulnerability allows attackers to tamper with encrypted data.",
                            "Apply Microsoft's security patches. Learn more here: https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070"],
                    [45, "Outdated web servers may contain unpatched vulnerabilities.",
                            "Upgrade the web server to the latest version."],
                    [46, "Injectable paths allow attackers to manipulate URLs and execute malicious code.",
                            "Sanitize input and follow secure coding practices. Learn more here: https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [47, "Exposed backend details allow attackers to launch targeted exploits.",
                            "Apply security patches and restrict banner information. Learn more here: http://kb.bodhost.com/secure-database-server/"],
                    [48, "RDP vulnerabilities allow attackers to launch remote exploits or brute-force attacks.",
                            "Restrict RDP access to specific IPs. Learn more here: https://www.perspectiverisk.com/remote-desktop-service-vulnerabilities/"],
                    [49, "SNMP vulnerabilities allow attackers to extract sensitive information or execute remote code.",
                            "Block SNMP ports and secure the service. Learn more here: https://www.techrepublic.com/article/lock-it-down-dont-allow-snmp-to-compromise-network-security/"],
                    [50, "Exposed logs reveal sensitive information that attackers can use to exploit the system.",
                            "Restrict access to logs from external sources."],
                    [51, "Exposed SMB services are vulnerable to remote exploits like WannaCry.",
                            "Secure SMB services and apply the latest patches. Learn more here: https://kb.iweb.com/hc/en-us/articles/115000274491-Securing-Windows-SMB-and-NetBios-NetBT-Services"]
            ]

# Tool Set
tools_precheck = [
                    ["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"], ["davtest"], ["theHarvester"], ["xsser"], ["dnsrecon"],["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"], ["golismero"], ["dnsenum"],["dmitry"], ["davtest"], ["nikto"], ["dnsmap"], ["amass"]
                 ]

def get_parser():

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true', 
                        help='Show help message and exit.')
    parser.add_argument('-u', '--update', action='store_true', 
                        help='Update securetask.')
    parser.add_argument('-s', '--skip', action='append', default=[],
                        help='Skip some tools', choices=[t[0] for t in tools_precheck])
    parser.add_argument('-n', '--nospinner', action='store_true', 
                        help='Disable the idle loader/spinner.')
    parser.add_argument('target', nargs='?', metavar='URL', help='URL to scan.', default='', type=str)
    return parser


# Shuffling Scan Order (starts)
scan_shuffle = list(zip(tool_names, tool_cmd, tool_resp, tool_status))
random.shuffle(scan_shuffle)
tool_names, tool_cmd, tool_resp, tool_status = zip(*scan_shuffle)
tool_checks = (len(tool_names) + len(tool_resp) + len(tool_status)) / 3 # Cross verification incase, breaks.
tool_checks = round(tool_checks)
# Shuffling Scan Order (ends)

# Tool Head Pointer: (can be increased but certain tools will be skipped)
tool = 0

# Run Test
runTest = 1

# For accessing list/dictionary elements
arg1 = 0
arg2 = 1
arg3 = 2
arg4 = 3
arg5 = 4
arg6 = 5

# Detected Vulnerabilities [will be dynamically populated]
rs_vul_list = list()
rs_vul_num = 0
rs_vul = 0

# Total Time Elapsed
rs_total_elapsed = 0

# Tool Pre Checker
rs_avail_tools = 0

# Checks Skipped
rs_skipped_checks = 0

if len(sys.argv) == 1:
    logo()
    helper()
    sys.exit(1)

args_namespace = get_parser().parse_args()

if args_namespace.nospinner:
    spinner.disabled = True

if args_namespace.help or (not args_namespace.update \
    and not args_namespace.target):
    logo()
    helper()
elif args_namespace.update:
    logo()
    print("securetask is updating....Please wait.\n")
    spinner.start()
    # Checking internet connectivity first...
    rs_internet_availability = check_internet()
    if rs_internet_availability == 0:
        print("\t"+ bcolors.BG_ERR_TXT + "There seems to be some problem connecting to the internet. Please try again or later." +bcolors.ENDC)
        spinner.stop()
        sys.exit(1)
    cmd = 'sha1sum securetask.py | grep .... | cut -c 1-40'
    oldversion_hash = subprocess.check_output(cmd, shell=True)
    oldversion_hash = oldversion_hash.strip()
    os.system('wget -N https://raw.githubusercontent.com/securetask/master/securetask.py -O securetask.py > /dev/null 2>&1')
    newversion_hash = subprocess.check_output(cmd, shell=True)
    newversion_hash = newversion_hash.strip()
    if oldversion_hash == newversion_hash :
        clear()
        print("\t"+ bcolors.OKBLUE +"You already have the latest version of securetask." + bcolors.ENDC)
    else:
        clear()
        print("\t"+ bcolors.OKGREEN +"securetask successfully updated to the latest version." +bcolors.ENDC)
    spinner.stop()
    sys.exit(1)

elif args_namespace.target:

    target = url_maker(args_namespace.target)
    #target = args_namespace.target
    os.system('rm /tmp/securetask* > /dev/null 2>&1') # Clearing previous scan files
    os.system('clear')
    os.system('setterm -cursor off')
    logo()
    print(bcolors.BG_HEAD_TXT+"[ Checking Available Security Scanning Tools Phase... Initiated. ]"+bcolors.ENDC)

    unavail_tools_names = list()

    while (rs_avail_tools < len(tools_precheck)):
        precmd = str(tools_precheck[rs_avail_tools][arg1])
        try:
            p = subprocess.Popen([precmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
            output, err = p.communicate()
            val = output + err
        except:
            print("\t"+bcolors.BG_ERR_TXT+"securetask was terminated abruptly..."+bcolors.ENDC)
            sys.exit(1)
        
        # If the tool is not found or it's part of the --skip argument(s), disabling it
        if b"not found" in val or tools_precheck[rs_avail_tools][arg1] in args_namespace.skip :
            if b"not found" in val:
                print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...unavailable."+bcolors.ENDC)
            elif tools_precheck[rs_avail_tools][arg1] in args_namespace.skip :
                print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...skipped."+bcolors.ENDC)
            
            for scanner_index, scanner_val in enumerate(tool_names):
                if scanner_val[2] == tools_precheck[rs_avail_tools][arg1]:
                    scanner_val[3] = 0 # disabling scanner as it's not available.
                    unavail_tools_names.append(tools_precheck[rs_avail_tools][arg1])

        else:
            print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.OKGREEN+"...available."+bcolors.ENDC)
        rs_avail_tools = rs_avail_tools + 1
        clear()
    unavail_tools_names = list(set(unavail_tools_names))
    if len(unavail_tools_names) == 0:
        print("\t"+bcolors.OKGREEN+"All Scanning Tools are available. Complete vulnerability checks will be performed by securetask."+bcolors.ENDC)
    else:
        print("\t"+bcolors.WARNING+"Some of these tools "+bcolors.BADFAIL+str(unavail_tools_names)+bcolors.ENDC+bcolors.WARNING+" are unavailable or will be skipped. securetask will still perform the rest of the tests. Install these tools to fully utilize the functionality of securetask."+bcolors.ENDC)
    print(bcolors.BG_ENDL_TXT+"[ Checking Available Security Scanning Tools Phase... Completed. ]"+bcolors.ENDC)
    print("\n")
    print(bcolors.BG_HEAD_TXT+"[ Preliminary Scan Phase Initiated... Loaded "+str(tool_checks)+" vulnerability checks. ]"+bcolors.ENDC)
    #while (tool < 1):
    while(tool < len(tool_names)):
        print("["+tool_status[tool][arg3]+tool_status[tool][arg4]+"] Deploying "+str(tool+1)+"/"+str(tool_checks)+" | "+bcolors.OKBLUE+tool_names[tool][arg2]+bcolors.ENDC,)
        if tool_names[tool][arg4] == 0:
            print(bcolors.WARNING+"\nScanning Tool Unavailable. Skipping Test...\n"+bcolors.ENDC)
            rs_skipped_checks = rs_skipped_checks + 1
            tool = tool + 1
            continue
        try:
            spinner.start()
        except Exception as e:
            print("\n")
        scan_start = time.time()
        temp_file = "/tmp/securetask_temp_"+tool_names[tool][arg1]
        cmd = tool_cmd[tool][arg1]+target+tool_cmd[tool][arg2]+" > "+temp_file+" 2>&1"

        try:
            subprocess.check_output(cmd, shell=True)
        except KeyboardInterrupt:
            runTest = 0
        except:
            runTest = 1

        if runTest == 1:
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                rs_total_elapsed = rs_total_elapsed + elapsed
                #print(bcolors.OKBLUE+"\b...Completed in "+display_time(int(elapsed))+bcolors.ENDC+"\n")
                sys.stdout.write(ERASE_LINE)
                print(bcolors.OKBLUE+"\nScan Completed in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n")
                #clear()
                rs_tool_output_file = open(temp_file).read()
                if tool_status[tool][arg2] == 0:
                    if tool_status[tool][arg1].lower() in rs_tool_output_file.lower():
                        #print "\t"+ vul_info(tool_resp[tool][arg2]) + bcolors.BADFAIL +" "+ tool_resp[tool][arg1] + bcolors.ENDC
                        vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
                else:
                    if any(i in rs_tool_output_file for i in tool_status[tool][arg6]):
                        m = 1 # This does nothing.
                    else:
                        #print "\t"+ vul_info(tool_resp[tool][arg2]) + bcolors.BADFAIL +" "+ tool_resp[tool][arg1] + bcolors.ENDC
                        vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
        else:
                runTest = 1
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                rs_total_elapsed = rs_total_elapsed + elapsed
                #sys.stdout.write(CURSOR_UP_ONE) 
                sys.stdout.write(ERASE_LINE)
                #print("-" * terminal_size(), end='\r', flush=True)
                print(bcolors.OKBLUE+"\nScan Interrupted in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n"+bcolors.WARNING + "\tTest Skipped. Performing Next. Press Ctrl+Z to Quit securetask.\n" + bcolors.ENDC)
                rs_skipped_checks = rs_skipped_checks + 1

        tool=tool+1

    print(bcolors.BG_ENDL_TXT+"[ Preliminary Scan Phase Completed. ]"+bcolors.ENDC)
    print("\n")

    #################### Report & Documentation Phase ###########################
    date = subprocess.Popen(["date", "+%Y-%m-%d"],stdout=subprocess.PIPE).stdout.read()[:-1].decode("utf-8")
    debuglog = "rs.dbg.%s.%s" % (target, date) 
    vulreport = "rs.vul.%s.%s" % (target, date)
    print(bcolors.BG_HEAD_TXT+"[ Report Generation Phase Initiated. ]"+bcolors.ENDC)
    if len(rs_vul_list)==0:
        print("\t"+bcolors.OKGREEN+"No Vulnerabilities Detected."+bcolors.ENDC)
    else:
        with open(vulreport, "a") as report:
            while(rs_vul < len(rs_vul_list)):
                vuln_info = rs_vul_list[rs_vul].split('*')
                report.write(vuln_info[arg2])
                report.write("\n------------------------\n\n")
                temp_report_name = "/tmp/securetask_temp_"+vuln_info[arg1]
                with open(temp_report_name, 'r') as temp_report:
                    data = temp_report.read()
                    report.write(data)
                    report.write("\n\n")
                temp_report.close()
                rs_vul = rs_vul + 1

            print("\tComplete Vulnerability Report for "+bcolors.OKBLUE+target+bcolors.ENDC+" named "+bcolors.OKGREEN+vulreport+bcolors.ENDC+" is available under the same directory securetask resides.")

        report.close()
    # Writing all scan files output into RS-Debug-ScanLog for debugging purposes.
    for file_index, file_name in enumerate(tool_names):
        with open(debuglog, "a") as report:
            try:
                with open("/tmp/securetask_temp_"+file_name[arg1], 'r') as temp_report:
                        data = temp_report.read()
                        report.write(file_name[arg2])
                        report.write("\n------------------------\n\n")
                        report.write(data)
                        report.write("\n\n")
                temp_report.close()
            except:
                break
        report.close()

    print("\tTotal Number of Vulnerability Checks        : "+bcolors.BOLD+bcolors.OKGREEN+str(len(tool_names))+bcolors.ENDC)
    print("\tTotal Number of Vulnerability Checks Skipped: "+bcolors.BOLD+bcolors.WARNING+str(rs_skipped_checks)+bcolors.ENDC)
    print("\tTotal Number of Vulnerabilities Detected    : "+bcolors.BOLD+bcolors.BADFAIL+str(len(rs_vul_list))+bcolors.ENDC)
    print("\tTotal Time Elapsed for the Scan             : "+bcolors.BOLD+bcolors.OKBLUE+display_time(int(rs_total_elapsed))+bcolors.ENDC)
    print("\n")
    print("\tFor Debugging Purposes, You can view the complete output generated by all the tools named "+bcolors.OKBLUE+debuglog+bcolors.ENDC+" under the same directory.")
    print(bcolors.BG_ENDL_TXT+"[ Report Generation Phase Completed. ]"+bcolors.ENDC)

    os.system('setterm -cursor on')
    os.system('rm /tmp/securetask_te* > /dev/null 2>&1') # Clearing previous scan files
