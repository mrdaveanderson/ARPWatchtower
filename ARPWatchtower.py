# Author: Dave Anderson, released under Apache 2.0 License

import datetime, os, subprocess, sys, time

def print_to_stderr(msg):
    sys.stderr.write(msg+'\n')
    sys.stderr.flush()

cache_timeout_seconds=6000
interface=''
try: interface=sys.argv[1]
except: interface='en0'

try: cache_timeout_seconds=float(sys.argv[2])
except: cache_timeout_seconds=6000

cmd = ['tcpdump', '-nnlte', '-s', '64', '-i', interface, 'arp' ]
print_to_stderr('Starting tcpdump with options: '+str(cmd))
proc = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
cache={}
last_cache_full_vacuum=time.time()

while True:
    try:
        line=proc.stdout.readline().decode('utf-8').rstrip().replace(',','')
        if len(line) < 1: break
        seconds=time.time()
        mac=''
        ip=''
        vlan=''
        segments=[]
        origline=line
        if 'Request' in line or 'Reply' in line:
            if 'Request' in line:
                segments=line.split('Request')
                try: ip=segments[1].split('tell')[1].split()[0].rstrip()
                except (IndexError): ip=''
            elif 'Reply' in line:
                segments=line.split('Reply')
                try: ip=segments[1].split()[0].rstrip()
                except (IndexError): ip=''
            try: mac=segments[0].split()[0].rstrip()
            except (IndexError): mac=''
            try: vlan=segments[0].split('vlan')[1].split()[0].rstrip()
            except (IndexError): vlan=''
        else:
            print_to_stderr(line.rstrip())
        
        if len(ip)>=7 and len(mac)==17: #minimal validation of IP and mac addr. It's ok if vlan is empty.
            key=ip+'@'+mac+'@'+vlan
            if key in cache:
                value=cache[key]
                if value[0] < seconds-cache_timeout_seconds: # If it's older than cache_timeout_seconds in the past, evict from cache
                    cache.pop(key)
            if not (key in cache):
                cache[key]=(seconds,origline)
                print(str(datetime.datetime.now())+'  IP='+'{:16}'.format(ip)+'VLAN='+'{:4}'.format(vlan)+'  MAC='+mac)
                #TODO: this is the location where graylog/ELK integration would happen (send same string as above)
        
        if (seconds-last_cache_full_vacuum > 30*cache_timeout_seconds): # Occasoinally evict everything we have not seen in a long time from the cache
            last_cache_full_vacuum=seconds
            keys_to_evict=[]
            for key in cache:
                value=cache[key]
                if value[0] < seconds-cache_timeout_seconds:
                    keys_to_evict.append(key)   #add to list of items to be evicted
            for key in keys_to_evict:           #actually evict keys
                cache.pop(key)
            print_to_stderr(str(datetime.datetime.now())+' '+'Info: Cache Vacuum: Evicting '+str(len(keys_to_evict))+', Remaining: '+str(len(cache)))
    except KeyboardInterrupt: # print the summary from tcpdump when we shut it down, then exit 
        print_to_stderr('\nShutting Down.')
        proc.kill()
        proc.wait()
        for i in range(5):
            print_to_stderr(proc.stdout.readline().decode('utf-8').rstrip())
        print_to_stderr('Exiting')
        exit()
