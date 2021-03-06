# Author: Dave Anderson, released under Apache 2.0 License

import datetime, importlib, logging, os, signal, subprocess, sys, time

def print_to_stderr(msg):
    sys.stderr.write(msg+'\n')
    sys.stderr.flush()

cache_timeout_seconds=28800 #8hrs
interfaces='en0'
graylog_hostname=''
graylog_port=12201
cache={}
last_cache_full_vacuum=time.time()
graylogger=None

for option in sys.argv:
    try:
        segments=option.split('=')
        if 'interfaces' in segments[0]:
            interfaces=segments[1]
        elif 'grayloghost' in segments[0]:
            subsegments=segments[1].split(':')
            graylog_hostname=subsegments[0]
            graylog_port=int(subsegments[1])
        elif 'cacheseconds' in segments[0]:
            cache_timeout_seconds=int(segments[1])
        elif 'help' in segments[0] or '?' in segments[0]:
            print_to_stderr('Optional arguments: \ninterfaces=<comma separated list of tcpdumpable interfaces>\ncacheseconds=<seconds to cache entries for>\ngrayloghost=example.host:1234\n\nexample: python3 ARPWatchtower.py interfaces=eth0 cacheseconds=600 grayloghost=example.com:12201')        
    except Exception as e:
        print_to_stderr('Failed to parse arg: '+option+" reason: "+str(e))

print('ARPWatchtower.py starting with args: interfaces:',interfaces,'cacheseconds:',cache_timeout_seconds,'grayloghost:',graylog_hostname,'graylogport',graylog_port)
cmd = ['tcpdump', '-B', '10240', '-nnlte', '-s', '128', '-i', interfaces, 'arp' ]
print_to_stderr('Starting tcpdump with options: '+str(cmd))
proc = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

try:
    if graylog_hostname:
        graypy=importlib.import_module('graypy') #import graypy
        graylogger=logging.getLogger('ARPWatchtower')
        graylogger.setLevel(logging.INFO)
        graylogger.addHandler(graypy.GELFUDPHandler(graylog_hostname, graylog_port))
    else: print_to_stderr('No graylog host defined, skipping')
except Exception as e: 
    print_to_stderr(str(datetime.datetime.now())+'  Failed to configure graylog. Error: '+str(e))
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
        
        if len(ip)>=7 and len(mac)==17 and ip!='0.0.0.0': #minimal validation of IP and mac addr. It's ok if vlan is empty.
            key=ip+'@'+mac+'@'+vlan
            if key in cache:
                value=cache[key]
                if value[0] < seconds-cache_timeout_seconds: # If it's older than cache_timeout_seconds in the past, evict from cache
                    cache.pop(key)
            if not (key in cache):
                cache[key]=(seconds,line)
                msg=(str(datetime.datetime.now())+'  IP='+'{:16}'.format(ip)+'VLAN='+'{:4}'.format(vlan)+'  MAC='+mac)
                print(msg)   #Print the output to stdout to enable file redirection, etc
                try:         #Try to log the same message to graylog
                    if graylogger: graylogger.info(msg+"\n"+line)
                except Exception as e:
                    graylogger=None
                    print_to_stderr('failed to log to graylog: e='+str(e)+"\ntraceback:"+e.__traceback__)

        if (seconds-last_cache_full_vacuum > 86400 ): # Every 24hrs evict everything we have not seen lately
            last_cache_full_vacuum=seconds
            keys_to_evict=[]
            for key in cache:
                value=cache[key]
                if value[0] < seconds-(cache_timeout_seconds*3):
                    keys_to_evict.append(key)   #add to list of items to be evicted
            for key in keys_to_evict:           #actually evict keys
                cache.pop(key)
            print_to_stderr(str(datetime.datetime.now())+'  '+'Info: Cache Vacuum: Evicting '+str(len(keys_to_evict))+', Remaining: '+str(len(cache)))
    except KeyboardInterrupt: # print the summary from tcpdump when we shut it down, then exit (TODO: is there a nother kind of interrupt if we get SIGINT from another proc?)
        print_to_stderr('\n'+str(datetime.datetime.now())+'  shutdown requested, cleaning up.')
        os.kill(proc.pid, signal.SIGINT) #send a control-c
        time.sleep(0.1)
        print_to_stderr(str(datetime.datetime.now())+'  -- tcpdump stats --')
        seconds=time.time()
        while True: #there may be various pending amount of crap in the buffer, iterate through, print anything that seems printable, then exit
            final_output=proc.stdout.readline().decode('utf-8').rstrip()
            if len(final_output) > 5:
                print_to_stderr(str(datetime.datetime.now())+'  '+final_output)
                seconds-=0.1
            else:
                if time.time()-0.5 > seconds: break
                time.sleep(0.02)
        print_to_stderr(str(datetime.datetime.now())+'  -- clean exit --')
        exit()
