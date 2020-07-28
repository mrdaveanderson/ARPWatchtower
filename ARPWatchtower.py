# Author: Dave Anderson, released under Apache 2.0 License

import datetime, graypy, logging, os, signal, subprocess, sys, time

def print_to_stderr(msg):
    sys.stderr.write(msg+'\n')
    sys.stderr.flush()

cache_timeout_seconds=28800 #8hrs
interface=''
try: interface=sys.argv[1]
except: interface='en0'

try: cache_timeout_seconds=float(sys.argv[2])
except: cache_timeout_seconds=28800 #8hrs

cmd = ['tcpdump', '-B', '10240', '-nnlte', '-s', '128', '-i', interface, 'arp' ]
print_to_stderr('Starting tcpdump with options: '+str(cmd))
proc = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
cache={}
last_cache_full_vacuum=time.time()

# TODO: figure out how to make it so installing graypy is optional
# TODO: improve arg parsing so that getting graylog host/port is a reasonable addition
graylog_hostname=''
graylog_port=0
graylogger=None
try:
    if graylog_hostname:
        graylogger=logging.getLogger('ARPWatchtower')
        graylogger.setLevel(logging.INFO)
        graylogger.addHandler(graypy.GELFUDPHandler(graylog_hostname, graylog_port))
    else: print_to_stderr('No graylog host defined, skipping')
except: 
    print_to_stderr(str(datetime.datetime.now())+'  Failed to configure graylog.')
    graylogger=None

while True:
    try:
        line=proc.stdout.readline().decode('utf-8').rstrip().replace(',','')
        if len(line) < 1: break
        seconds=time.time()
        mac=''
        ip=''
        vlan=''
        segments=[]
        if 'Request' in line or 'Reply' in line or 'Probe' in line or 'Announcement' in line:
            if 'Request' in line:
                segments=line.split('Request')
                try: ip=segments[1].split('tell')[1].split()[0].rstrip()
                except (IndexError): ip=''
            else:
                if   'Reply'        in line: segments=line.split('Reply')
                elif 'Announcement' in line: segments=line.split('Announcement')
                elif 'Probe'        in line: segments=line.split('Probe')
                try: ip=segments[1].split()[0].rstrip()
                except (IndexError): ip=''
            try: mac=segments[0].split()[0].rstrip()
            except (IndexError): mac=''
            try: vlan=segments[0].split('vlan')[1].split()[0].rstrip()
            except (IndexError): vlan=''
        else:
            print_to_stderr(str(datetime.datetime.now())+'  '+line.rstrip())
        

        if len(ip)>=7 and len(mac)==17: #minimal validation of IP and mac addr. It's ok if vlan is empty.
            key=ip+'@'+mac+'@'+vlan
            if key in cache:
                value=cache[key]
                if value[0] < seconds-cache_timeout_seconds: # If it's older than cache_timeout_seconds in the past, evict from cache
                    cache.pop(key)
            if not (key in cache):
                cache[key]=(seconds,line)
                msg=(str(datetime.datetime.now())+'  IP='+'{:16}'.format(ip)+'VLAN='+'{:4}'.format(vlan)+'  MAC='+mac)
                if not (ip=='0.0.0.0'): print(msg)
                #TODO: this is the location where graylog/ELK integration would happen (send same string as above)
                try: 
                    if graylogger and not (ip=='0.0.0.0'): graylogger.info(msg+"\n"+line)
                except Exception as e:
                    graylogger=None
                    print_to_stderr('failed to log to graylog: e='+str(e)+"\ntraceback:"+e.__traceback__)

        
        if (seconds-last_cache_full_vacuum > 86400 ): # Every 24hrs evict everything we have not seen lately
            last_cache_full_vacuum=seconds
            keys_to_evict=[]
            for key in cache:
                value=cache[key]
                if value[0] < seconds-cache_timeout_seconds:
                    keys_to_evict.append(key)   #add to list of items to be evicted
            for key in keys_to_evict:           #actually evict keys
                cache.pop(key)
            print_to_stderr(str(datetime.datetime.now())+'  '+'Info: Cache Vacuum: Evicting '+str(len(keys_to_evict))+', Remaining: '+str(len(cache)))
    except KeyboardInterrupt: # print the summary from tcpdump when we shut it down, then exit 
        print_to_stderr('\nShutting Down.')
        os.kill(proc.pid, signal.SIGINT) #send a control-c
        lines_printed=0
        for i in range(50): #there may be various pending amount of crap in the buffer, iterate through, print anything that seems printable, then exit
            final_output=proc.stdout.readline().decode('utf-8').rstrip()
            if len(final_output) > 5:
                print_to_stderr(str(datetime.datetime.now())+'  '+final_output)
                lines_printed+=1
            else:
                if lines_printed > 2: break
                time.sleep(0.1)
                if i > 30: proc.kill()        #somehow it still might be alive, start sending kills
                elif i > 47: proc.terminate() #still alive? send terminates.   
        print_to_stderr('Exiting')
        exit()
