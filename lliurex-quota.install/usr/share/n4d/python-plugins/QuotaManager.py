import os,sys,time
import re
import subprocess
import json
import xmlrpclib
import getpass
import socket
import time

from functools import wraps
import inspect

#
# TODO:
# -Allow use rquotad with parameter -S allowing set remote quotas from nfs share edquota -Frpc -u <user>
# -Check run inside master|slave|independent server(maybe detecting mount with nfs type), maybe repquota (not support -Frpc) is not valid and we've to fallback to setquota|getquota
# -If it's a client must be n4d call to check quotas (not necesary to set quotas)
#

DEBUG = False

class QuotaManager:
    def __init__(self):
        self.fake_client = False
        self.type_client = None
        self.client = None
        self.n4d_server = None
        self.auth = None
        self.system_groups = None
        self.system_users = None
        self.get_client()

    def set_credentials(self,user,pwd):
        self.auth=(user,pwd)

    def get_client(self):
        if type(self.client) == type(None):
            self.client = self.init_client()
            #self.n4d_key = self.get_n4d_key()
        return self.client

    def ask_auth(self):
        user = raw_input('Network user? (netadmin) ')
        if user.strip() == '':
            user = 'netadmin'
        pwd = getpass.getpass('Password? ')
        return (user,pwd)

    def get_auth(self,namefunc):
        methods = self.client.get_methods('QuotaManager').strip().split('\n')
        n4dinfo = { line.strip().split(' ')[1] : line.strip().split(' ')[3:] for line in methods if len(line.strip().split(' ')) > 3 }
        if namefunc not in n4dinfo:
            return None
        if 'anonymous' in n4dinfo[namefunc]:
            return ''
        else:
            return self.ask_auth()

    def proxy(func,*args,**kwargs):
        if DEBUG:
            print 'into call {} {} {}'.format(func,args,kwargs)
        def decorator(self,*args,**kwargs):
            if DEBUG:
                print 'into decorator {} {} {}'.format(self,args,kwargs)

            @wraps(func)
            def wrapper(*args,**kwargs):
                if DEBUG:
                    print('into wrapper({}) {} {}'.format(func.__name__,args,kwargs))
                if self.fake_client:
                    if DEBUG:
                        print('running fake mode')
                    return func(self,*args,**kwargs)
                else:
                    self.client = self.get_client()
                    try:
                        self.client.listMethods()
                        #
                        # TODO: check and emit warning if method used it's not configured as xmlrpc call
                        # missing into n4d conf file
                        #
                    except ResponseNotReady as e:
                        print('Couldn\'t create N4D client, aborting call ({}), {}'.format(func.__name__,e))
                    except Exception as e:
                        print('Couldn\'t create N4D client, aborting call ({}),{}'.format(func.__name__,r))
                    if DEBUG:
                        print('running n4d mode with server {}'.format(self.n4d_server))
                    cparams=None
                    for frameinfo in inspect.stack():
                        if frameinfo[3] == '_dispatch':
                            try:
                                cparams=tuple(frameinfo[0].f_locals['params'][1])
                            except:
                                pass
                    if type(self.auth) == type(None):
                        if cparams and len(cparams) == 2 and type(cparams[0]) == type(str()) and type(cparams[1]) == type(str()):
                                self.auth = cparams
                    if type(self.auth) == type(None):
                        self.auth = self.get_auth(func.__name__)
                    params = []
                    params.append(self.auth)
                    params.append('QuotaManager')
                    params.extend(args)
                    if DEBUG:
                        print('calling {} with params {}'.format(func.__name__,params))
                    ret = getattr(self.client,func.__name__)(*params)
                    if DEBUG:
                        print('returning {}'.format(ret))
                    return ret
            if DEBUG:
                print 'created wrapper {} {}'.format(args,kwargs)
            return wrapper(*args,**kwargs)
        return decorator

    def check_ping(self,host):
        ret = False
        try:
            subprocess.check_call(['ping','-c','1',host],stderr=open(os.devnull,'w'),stdout=open(os.devnull,'w'))
            ret = True
        except:
            pass
        return ret

    def detect_nfs_mount(self,mount='/net/server-sync'):
        try:
            nfsmounts = subprocess.check_output(['findmnt','-J','-t','nfs'])
            if nfsmounts == '':
                return False
            nfsmounts_obj = json.loads(nfsmounts)
            parsed_nfsmounts = [ x.get('target') for x in nfsmounts_obj.get('filesystems',[]) ]
            if mount and mount in parsed_nfsmounts:
                return True
            else:
                return False
        except Exception as e:
            raise Exception('Error detecting nfs mount {}, {}'.format(mount,e))

    def any_slave(self,ips=[]):
        truncated = [ '.'.join(ip.split('.')[0:2]) for ip in ips ]
        if '10.3' in truncated:
            return True
        else:
            return False

    def detect_running_system(self):
        if self.type_client:
            return self.type_client
        ips = self.get_local_ips()
        try:
            srv_ip = socket.gethostbyname('server')
        except:
            srv_ip = None

        #var_value = self.read_vars('SRV_IP')
        #if 'value' in var_value:
        #    var_value = var_value['value']

        iplist = [ ip.split('/')[0] for ip in ips ]
        type_client = None

        if '10.3.0.254' in iplist: # it has a reserved master server address
            self.fake_client = True
            type_client = 'master'
        elif srv_ip in iplist: # is something like a server, dns 'server' is assigned to me
            if self.any_slave(iplist): # classroom range 10.3.X.X
                if self.detect_nfs_mount(): # nfs mounted or not
                    type_client = 'slave'
                    self.fake_client = False
                    #Moved to caller functions
                    #if self.check_ping('10.3.0.254'): # available
                    #    type_client = 'slave'
                    #    self.fake_client = False
                    #else: # not available
                    #    raise Exception('Nfs master server is not reachable!')
                else:
                    self.fake_client = True
                    type_client = 'independent'
            else: 
                self.fake_client = True
                type_client = 'independent'
        elif srv_ip is not None: # dns 'server' is known but is not assigned to me, maybe i am a client
            type_client = 'client'
            self.fake_client = False
        else: # 'server' dns is unknown
            type_client = 'other'
            self.fake_client = True

        self.type_client = type_client
        return type_client

    def init_client(self):
        try:
            type = self.detect_running_system()
        except Exception as e:
            if DEBUG:
                print('Exception initiating client, {}'.format(e))
        url = ''
        reachable = True
        if type == 'master':
            url = 'fake'
        elif type == 'independent':
            url = 'fake'
        elif type == 'slave':
            url = 'https://10.3.0.254:9779'
            if not self.check_ping('10.3.0.254'):
                print('Nfs master server is not reachable!')
                reachable = False
        else:
            try:
                srv_ip = socket.gethostbyname('server')
                if not self.check_ping(srv_ip):
                    print('server {} is not reachable!'.format(srv_ip))
                    reachable = False
            except:
                srv_ip = None
            url = 'https://'+str(srv_ip)+':9779'
        self.n4d_server = url
        client = None
        if (url == 'fake'):
            return client
        try:
            client = xmlrpclib.ServerProxy(url,allow_none=True)
            client.get_methods()
        except Exception as e:
            #raise Exception('Can\'t create xml client, {}, {}'.format(url,e))
            client = None
        return client

    #def read_vars(self,name=None):
    #    var_dir='/var/lib/n4d/variables-dir'
    #    filevar=var_dir+'/'+name
    #    if not name or not os.path.exists(filevar):
    #        raise Exception('{} not found in {}'.format(name,var_dir))
    #    content = None
    #    with open(filevar,'r') as fp:
    #        content = json.load(fp)
    #    if name in content:
    #        content = content[name]
    #    else:
    #        content = None
    #    return content

    def get_local_ips(self):
        try:
            ips = subprocess.check_output(['ip','-o','a','s'])
        except subprocess.CalledProcessError as e:
            if hasattr(e,'output'):
                ips = e.output.strip()
            else:
                raise Exception('Error trying to get local ips, {}'.format(e))
        except Exception as e:
            raise Exception('Error trying to get local ips, {}'.format(e))
        iplist = []
        for line in ips.split('\n'):
            m = re.search('inet\s+([0-9]{1,3}(?:[.][0-9]{1,3}){3}/[0-9]{1,2})\s+',line)
            if m:
                iplist.append(m.group(1))
        return iplist

    def detect_mount_from_path(self,ipath):
        if not os.path.exists(ipath):
            raise Exception('Path not found')
        mounts = self.get_fstab_mounts()
        out = None
        try:
            out = json.loads(subprocess.check_output(['findmnt','-J','-T',str(ipath)]))
            targetfs = out['filesystems'][0]['source']
            targetmnt = out['filesystems'][0]['target']
        except Exception as e:
            print e
        if targetfs in [ x['fs'] for x in mounts ]:
            return targetfs, targetmnt
        else:
            raise Exception('Filesystem {} not matched from readed fstab'.format(ipath))
            return None

    def get_comments(self, filename):
        if not os.path.isfile(filename):
            raise Exception('Not valid filename to get comments, {}'.format(filename))
        out = []
        with open(filename,'r') as fp:
            for line in fp.readlines():
                m = re.findall(r'^\s*(#.*)$',line)
                if m:
                    out.extend(m)
        return '\n'.join(out) if out else ''

    def get_idx_mapping_blkid(self):
        out = []
        try:
            ids = subprocess.check_output(['blkid','-o','list'])
        except subprocess.CalledProcessError as e:
            if hasattr(e,'output'):
                ids = e.output.strip()
            else:
                raise Exception('Error trying to get block id\'s'.format(e))
        except Exception as e:
            raise Exception('Error trying to get block id\'s'.format(e))
        ids = ids.strip().split('\n')
        blklist = []
        for line in ids:
            m = re.match(r'^(?P<fs>/\S+)\s+(?P<type>\S+)\s+(?P<mountpoint>\S+)\s+(?P<uuid>\S+)$',line)
            if m:
                blklist.append(m.groupdict())
        if not blklist:
            raise Exception('Couldn\'t get block list uuids, maybe need run as superuser')
        return blklist

    def get_idx_mapping_lsblk(self):
        out = []
        try:
            # each version of lsblk outputs distinct information, this is the safest method
            ids = subprocess.check_output(['lsblk','-P','-o','KNAME,FSTYPE,MOUNTPOINT,UUID'])
        except subprocess.CalledProcessError as e:
            if hasattr(e,'output'):
                ids = e.output.strip()
            else:
                raise Exception('Error trying to get block id\'s'.format(e))
        except Exception as e:
            raise Exception('Error trying to get block id\'s'.format(e))

        ids = ids.strip().split('\n')
        blklist = []
        for line in ids:
            m = re.match(r'^KNAME="(?P<fs>[^"]*)"\s+FSTYPE="(?P<type>[^"]*)"\s+MOUNTPOINT="(?P<mountpoint>[^"]*)"\s+UUID="(?P<uuid>[^"]*)"$',line)
            if m:
                dout = m.groupdict()
                if 'uuid' in dout and dout['uuid'] != '':
                    if dout['fs'][0:4] != '/dev':
                        dout['fs'] = '/dev/' + dout['fs']
                    blklist.append(dout)
        if not blklist:
            raise Exception('Couldn\'t get block list uuids, maybe the output format of lsblk ... has changed !!')
        return blklist

    def get_realname(self,devicelink):
        out = []
        try:
            # each version of lsblk outputs distinct information, this is the safest method
            realname = subprocess.check_output(['readlink','-f',str(devicelink)])
        except subprocess.CalledProcessError as e:
            if hasattr(e,'output'):
                realname = e.output.strip()
            else:
                raise Exception('Error trying to get realname from {}, {}\'s'.format(devicelink,e))
        except Exception as e:
            raise Exception('Error trying to get realname from {}, {}'.format(devicelink,e))
        try:
            realname = realname.strip()
        except:
            pass
        return realname

    def get_fstab_mounts(self):
        out = []
        other = []
        with open('/etc/fstab','r') as fp:
            for line in fp.readlines():
                m = re.match(r'^\s*(?P<fs>[^#]\S+)\s+(?P<mountpoint>\S+)\s+(?P<type>\S+)\s+(?P<options>(?:[\S]+,)*[\S]+)\s+(?P<dump>\d)\s+(?P<pass>\d)\s*#?.*$',line.strip())
                if m:
                    out.append(m.groupdict())
        if not out:
            return None
        try:
            blklist = self.get_idx_mapping_lsblk()
        except Exception as e:
            try:
                blklist = self.get_idx_mapping_blkid()
            except Exception as e2:
                raise Exception('Couldn\'t get block id\'s !!\nlsblk says: {}\nblkid says: {}\n'.format(e,e2))

        for linefstab in out:
            if linefstab['fs'].lower()[0:4] == 'uuid':
                for blk in blklist:
                    if linefstab['fs'].lower() == 'uuid='+blk['uuid']:
                        linefstab['fs'] = blk['fs']
                        linefstab['uuid'] = blk['uuid']
                        break

                # check realname, lvm uses symlinks pointing to real kernel name
                realnamefs = self.get_realname(linefstab['fs'])
                if realnamefs == linefstab['fs']:
                    linefstab['alias']=linefstab['fs']
                else:
                    linefstab['alias']=linefstab['fs']
                    linefstab['fs']=realnamefs
            else:
                # check realname, lvm uses symlinks pointing to real kernel name
                realnamefs = self.get_realname(linefstab['fs'])
                if realnamefs == linefstab['fs']:
                    linefstab['alias']=linefstab['fs']
                else:
                    linefstab['alias']=linefstab['fs']
                    linefstab['fs']=realnamefs
                found = False
                for blk in blklist:
                    if linefstab['fs'] == blk['fs']:
                        linefstab['uuid'] = blk['uuid']
                        found = True
                        break
                if not found:
                    linefstab['uuid'] = ''
        return out

    def get_mounts_with_quota(self):
        mounts = self.get_fstab_mounts()
        out = []
        options = ['usrquota','usrjquota','grpquota','grpjquota','jqfmt']
        for mount in mounts:
            quota = {'user': False, 'group': False}
            for option in options:
                if option in mount['options']:
                    if 'usr' in option:
                        quota['user'] = True
                    if 'grp' in option:
                        quota['group'] = True
            mount.setdefault('quota',quota)
            if quota['user'] or quota['group']:
                out.append(mount)
        return out if out else []

    def trim_quotas(self, string):
        parts = string.split(',')
        out = []
        for part in parts:
            contains = False
            for token in ['usrquota','usrjquota','grpquota','grpjquota','jqfmt']:
                if token in part:
                    contains = True
            if not contains:
                out.append(part.strip())
        return ','.join(out)

    def get_quota_files(self,string):
        parts = string.split(',')
        out = []
        for part in parts:
            for token in ['usrquota','usrjquota','grpquota','grpjquota']:
                if token in part:
                    subpart = part.split('=')
                    if len(subpart) != 2:
                        raise Exception('Malformed option'.fomat(part))
                    out.append(subpart[1])
        return out

    def unset_mount_with_quota(self, mount = 'all'):
        quota_mounts = self.get_mounts_with_quota()
        all_mounts = self.get_fstab_mounts()
        found = False
        targets = []
        nontargets = []
        if mount == 'all':
            targets = all_mounts
        else:
            if mount[0:5].lower() == 'uuid=':
                mount = mount[5:]
            for mountitem in all_mounts:
                if mountitem['fs'] == os.path.normpath(mount) or mountitem['uuid'] == mount or mountitem['mountpoint'] == os.path.normpath(mount) or mountitem['alias'] == os.path.normpath(mount):
                    found = False
                    for qmount in quota_mounts:
                        if qmount['fs'] == mountitem['fs']:
                            found = True
                            break
                        if qmount['fs'] == mountitem['alias']:
                            found = True
                            break
                    if found:
                        targets.append(mountitem)
                    else:
                        nontargets.append(mountitem)
                else:
                    nontargets.append(mountitem)
        if not targets:
            raise Exception('No target filesystems to remove quotas')
        with open('/etc/fstab','r') as fpr:
            ts = str(int(time.time()))
            with open('/etc/fstab_bkp_'+ts,'w') as fpw:
                fpw.write(fpr.read())
        comments = self.get_comments('/etc/fstab')
        quotafiles = []
        with open('/etc/fstab','w') as fp:
            fp.write(comments+'\n')
            for target in nontargets:
                if target['uuid']:
                    fp.write('UUID={uuid}\t{mountpoint}\t{type}\t{options}\t{dump}\t{pass}\t # {fs} {alias}\n'.format(**target))
                else:
                    fp.write('{alias}\t{mountpoint}\t{type}\t{options}\t{dump}\t{pass}\t # {uuid} {fs}\n'.format(**target))
            for target in targets:
                newoptions = self.trim_quotas(target['options'])
                for file in self.get_quota_files(target['options']):
                    quotafiles.append(target['mountpoint']+'/'+file)
                if not newoptions:
                    Exception('Error timming options from {}'.format(target['options']))
                else:
                    target['options'] = newoptions
                if target['uuid']:
                    fp.write('UUID={uuid}\t{mountpoint}\t{type}\t{options}\t{dump}\t{pass}\t # {fs} {alias}\n'.format(**target))
                else:
                    fp.write('{alias}\t{mountpoint}\t{type}\t{options}\t{dump}\t{pass}\t # {uuid} {fs}\n'.format(**target))
        ts = str(int(time.time()))
        for file in quotafiles:
            with open(file,'rb') as fpr:
                with open(file+'_bkp_'+ts,'wb') as fpw:
                    fpw.write(fpr.read())
        self.activate('quotaoff')
        for target in targets:
            try:
                self.remount(target['mountpoint'],forceumount=False)
            except:
                if target['mountpoint'] == "/":
                    print "WARNING: Forced umount not allowed on / need to restart"
                else:
                    print "Forced remount for path {}".format(target['mointpoint'])
                    self.remount(target['mountpoint'],forceumount=True)
        for file in quotafiles:
            os.unlink(file)
        quota_mounts = self.get_mounts_with_quota()
        if quota_mounts:
            self.activate('quotaon')
        return True

    def remount(self,mount='all',forceumount=False):
        if not mount:
            raise Exception('Need mount when call remount')
        cmd_append=[]
        if mount != 'all':
            all_mounts = self.get_fstab_mounts()
            targets = []
            if mount[0:5].lower() == 'uuid=':
                mount = mount[5:]
            for mountitem in all_mounts:
                if mountitem['fs'] == os.path.normpath(mount) or mountitem['uuid'] == mount or mountitem['mountpoint'] == os.path.normpath(mount) or mountitem['alias'] == os.path.normpath(mount):
                    targets.append(mountitem)
                    break
            if not targets:
                raise Exception('No target filesystems to remove quotas')
        else:
            cmd_append.append('-a')
        cmd = ['mount','-o','remount']
        if mount == 'all':
            try:
                cmd.extend(cmd_append)
                out = subprocess.check_output(cmd)
            except subprocess.CalledProcessError as e:
                if hasattr(e,'output'):
                    out = e.output
                    return False
                else:
                    raise Exception('Error trying to remount ({}) {}, {}'.format(cmd,mount,e))
            except Exception as e:
                    raise Exception('Error trying to remount ({}) {}, {}'.format(cmd,mount,e))
        else:
            for target in targets:
                if forceumount:
                    cmdtmp = ['umount','-l',target['mountpoint']]
                    try:
                        out = subprocess.check_output(cmdtmp)
                    except subprocess.CalledProcessError as e:
                        if hasattr(e,'output'):
                            out = e.output
                            return False
                        else:
                            raise Exception('Error trying to remount ({}),{}, {}'.format(cmdtmp,mount,e))
                    except Exception as e:
                        raise Exception('Error trying to remount ({}) {}, {}'.format(cmdtmp,mount,e))

                    cmdtmp = ['mount','-o',target['options'],target['mountpoint']]
                    try:
                        out = subprocess.check_output(cmdtmp)
                    except subprocess.CalledProcessError as e:
                        if hasattr(e,'output'):
                            out = e.output
                            return False
                        else:
                            raise Exception('Error trying to remount ({}),{}, {}'.format(cmdtmp,mount,e))
                    except Exception as e:
                        raise Exception('Error trying to remount ({}) {}, {}'.format(cmdtmp,mount,e))
                else:
                    cmdtmp = cmd + ['-o',target['options'],target['mountpoint']]
                    try:
                        out = subprocess.check_output(cmdtmp)
                    except subprocess.CalledProcessError as e:
                        if hasattr(e,'output'):
                            out = e.output
                            return False
                        else:
                            raise Exception('Error trying to remount ({}),{}, {}'.format(cmdtmp,mount,e))
                    except Exception as e:
                        raise Exception('Error trying to remount ({}) {}, {}'.format(cmdtmp,mount,e))
        return True

    def set_mount_with_quota(self, mount=None):
        if mount == None:
            raise Exception('Mandatory mountpoint when setting quotas')
        quota_mounts = self.get_mounts_with_quota()
        all_mounts = self.get_fstab_mounts()
        found = False
        targets = []
        nontargets = []

        if mount[0:5].lower() == 'uuid=':
            mount = mount[5:]
        for mountitem in all_mounts:
            if mountitem['fs'] == os.path.normpath(mount) or mountitem['uuid'] == mount or mountitem['mountpoint'] == os.path.normpath(mount) or mountitem['alias'] == os.path.normpath(mount):
                found = False
                if quota_mounts:
                    for qmount in quota_mounts:
                        if qmount['fs'] == mountitem['fs']:
                            found = True
                            break
                        if qmount['alias'] == mountitem['fs']:
                            found = True
                            break
                if found:
                    raise Exception('Mount {} already with quota'.format(mountitem['mountpoint']))
                else:
                    if mountitem['type'] not in ['ext3','ext4','xfs','reiserfs']:
                        raise Exception('Type {type} for filesystem {fs} not suitable for quotas'.format(**mountitem))
                    targets.append(mountitem)
            else:
                nontargets.append(mountitem)
        if not targets:
            raise Exception('No target filesystems to add quotas')
        with open('/etc/fstab','r') as fpr:
            ts = str(int(time.time()))
            with open('/etc/fstab_bkp_'+ts,'w') as fpw:
                fpw.write(fpr.read())
        comments = self.get_comments('/etc/fstab')
        with open('/etc/fstab','w') as fp:
            fp.write(comments+'\n')
            for target in nontargets:
                if target['uuid']:
                    fp.write('UUID={uuid}\t{mountpoint}\t{type}\t{options}\t{dump}\t{pass}\t # {fs}\n'.format(**target))
                else:
                    fp.write('{alias}\t{mountpoint}\t{type}\t{options}\t{dump}\t{pass}\n'.format(**target))
            for target in targets:
                target['options'] += ',usrjquota=aquota.user,grpjquota=aquota.group,jqfmt=vfsv0'
                if target['uuid']:
                    fp.write('UUID={uuid}\t{mountpoint}\t{type}\t{options}\t{dump}\t{pass}\t # {fs}\n'.format(**target))
                else:
                    fp.write('{alias}\t{mountpoint}\t{type}\t{options}\t{dump}\t{pass}\n'.format(**target))
        for target in targets:
            self.remount(target['mountpoint'])
        self.activate('quotaoff')
        for target in targets:
            try:
                out=subprocess.check_output(['quotacheck','-vguma'],stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                if hasattr(e,'output'):
                    raise Exception('Error trying to check initial quotas on {}, {}, {}'.format(target['fs'],e,e.output.strip()))
                else:
                    raise Exception('Error trying to check initial quotas on {}, {}'.format(target['fs'],e))
            except Exception as e:
                raise Exception('Error trying to check initial quotas on {}, {}'.format(target['fs'],e))
        self.activate('quotaon')
        self.activate('quotarpc')
        return True

    def get_system_users(self):
        if self.system_users:
            return self.system_users
        try:
            pwdlist = subprocess.check_output(['getent','passwd'])
        except subprocess.CalledProcessError as e:
            if hasattr(e,'output'):
                pwdlist = e.output.strip()
            else:
                raise Exception('Error getting userlist, {}'.format(e))
        except Exception as e:
            raise Exception('Error getting userlist, {}'.format(e))
            pass
        pwdlist = pwdlist.strip().split('\n')
        userlist = []
        for line in pwdlist:
            user = re.findall('^([^:]+):(?:[^:]+:){5}[^:]+$',line)
            if user:
                userlist.append(user[0])
        self.system_users = userlist
        return userlist

    def get_quotas_file(self):
        folder = '/etc/lliurex-quota'
        file = 'quotas'
        filepath = folder + '/' + file
        if not os.path.isfile(filepath):
            raise Exception('Missing quotas file {}'.format(filepath))
        try:
            with open(filepath,'r') as fp:
                qinfo = json.load(fp)
        except Exception as e:
            raise Exception('Error reading file quotas {}, {}'.format(filepath,e))
        if type(qinfo) != type(dict()):
            raise Exception('Error reading file quotas {}, expected dictionary'.format(filepath))
        return qinfo

    def set_quotas_file(self,quotasdict={}):
        folder = '/etc/lliurex-quota'
        file = 'quotas'
        filepath = folder + '/' + file
        if type(quotasdict) != type(dict()):
            raise Exception('Invalid dictionary quotas passed to set_quotas_file')
        if not os.path.isdir(folder):
            try:
                os.mkdir(folder)
            except Exception as e:
                raise Exception('Error creating quotas dir {}, {}'.format(folder,e))
        try:
            with open(filepath,'w') as fp:
                json.dump(quotasdict,fp,sort_keys=True)
        except Exception as e:
            raise Exception('Error writting file quotas {}, {}'.format(filepath,e))
        return True

    def get_moving_directories(self):
        try:
            import net.Lliurex.Classroom.MovingProfiles as moving
            mp = moving.MovingProfiles('')
            return mp.cfg['include'].values()
        except:
            raise Exception('Unable to get moving directories')

    def get_moving_dir(self,user=None):
        basepath = '/net/server-sync/home'
        dirpath = basepath+'/students/'+str(user)
        if not os.path.isdir(dirpath):
            #print '{} is not dir'.format(dirpath)
            dirpath = basepath+'/teachers/'+str(user)
            if not os.path.isdir(dirpath):
                #print '{} is2 not dir'.format(dirpath)
                dirpath = None
        #print 'final dirpath {}'.format(dirpath)
        if dirpath and os.path.isdir(dirpath+'/Documents/.moving_profiles'):
            dirpath = dirpath+'/Documents/.moving_profiles'
        else:
            return None
        #print 'dirpath returned {}'.format(dirpath)
        return dirpath

    def normalize_quotas(self):
        #print 'init normalize'
        quotas = self.get_quotas(humanunits=False)
        #print 'quotas get {}'.format(quotas)
        qdict = {}
        for quotauser in quotas:
            hard = self.normalize_units(quotas[quotauser]['spacehardlimit'])
            soft = self.normalize_units(quotas[quotauser]['spacesoftlimit'])
            if hard - soft < 0:
                soft = hard
            margin = hard - soft
            qstruct={'quota': soft,'margin':margin}
            qdict.setdefault(quotauser,qstruct)
        try:
            qfile = self.get_quotas_file()
            if qfile == {}:
                self.set_quotas_file(qdict)
                qfile = qdict
        except:
            self.set_quotas_file(qdict)
            qfile = qdict
        users = self.get_system_users()
        for user in users:
            if user not in qfile:
                qfile[user] = {'quota':0,'margin':0}
        #print 'init qfile {}'.format(qfile['alus01'])
        userinfo = {}
        for user in qfile:
            #print 'using user --> {} {}'.format(user,type({'quota':qfile[user]}))
            userinfo.setdefault(user,{'quota':qfile[user],'normquota':{'hard':0,'soft':0}})
            #print 'first userinfo {}'.format(userinfo)
            #print 'Getting moving for user --> {}'.format(user)
            dpath = self.get_moving_dir(user)
            #print 'dpath {}'.format(dpath)
            try:
                if dpath:
                    userinfo[user]['moving_quota'] = self.get_user_space(folder=dpath,user=user)[user]
                    #print 'moving quota {}'.format(userinfo[user]['moving_quota'])
                    userinfo[user]['normquota']['hard'] = userinfo[user]['quota']['quota'] + userinfo[user]['quota']['margin'] + (userinfo[user]['moving_quota'] * 2)
                    userinfo[user]['normquota']['soft'] = userinfo[user]['quota']['quota'] + (userinfo[user]['moving_quota'] * 2) 
                else:
                    userinfo[user]['normquota']['hard'] = userinfo[user]['quota']['quota'] + userinfo[user]['quota']['margin']
                    userinfo[user]['normquota']['soft'] = userinfo[user]['quota']['quota']
            except Exception as e:
                import traceback
                return "{} {} {}".format(str(e),traceback.format_exc(),user)
        #print 'calculated userinfo {}'.format(userinfo['alus01'])
        qdict2 = {}
        utmp=''
        try:
            for user in userinfo:
                utmp=user
                if userinfo[user]['quota']['quota'] == 0:
                    if user in qdict and qdict[user]['quota'] != userinfo[user]['quota']['quota']:
                        qdict2.setdefault(user,{'quota':0,'margin':0})
                else:
                    if user in qdict and qdict[user]['quota'] != (userinfo[user]['normquota']['hard'] - userinfo[user]['normquota']['soft']):
                        qdict2.setdefault(user,{'quota':userinfo[user]['normquota']['soft'],'margin':userinfo[user]['normquota']['hard']-userinfo[user]['normquota']['soft']})
        except Exception as e:
            import traceback
            return "{} {} {}".format(str(e),traceback.format_exc(),qdict[utmp])
        #print 'setting quotas file {}'.format(qdict2)
        self.set_quotas_file(qfile)
        self.apply_quotasdict(qdict2)
        return True

    def get_user_space(self,folder=None,user=None):
        if user == None or folder == None:
            raise Exception('Need user and folder getting user space')
        if not os.path.isdir(folder):
            raise Exception('Invalid folder to get userspace')
        us = self.get_system_users()
        uparam = ''
        if user not in us:
            if str(user).lower() != 'all':
                raise Exception('Invalid user to get userspace')
        else:
            uparam = '-user {}'.format(user)
        try:
            sizes = subprocess.check_output(['find {} {} -printf "%u %s\n"'.format(folder,uparam) + "| awk '{user[$1]+=$2}; END{ for( i in user) print i \" \" user[i]}'"],shell=True)
        except subprocess.CalledProcessError as e:
            if hasattr(e,'output'):
                pwdlist = e.output.strip()
            else:
                raise Exception('Error getting consumed space by user {}, {}'.format(user,e))
        except Exception as e:
            raise Exception('Error getting consumed space by user {}, {}'.format(user,e))
        #print 'sizes --> {}'.format(sizes)
        if str(user).lower() == 'all':
            sizes = sizes.split('\n')
        else:
            sizes = [sizes]
        sizedict = {}
        for sizeuser in sizes:
            username,size = sizeuser.split(' ')
            sizedict.setdefault(username,int(size)/1000)
        return sizedict

    def get_system_groups(self):
        if self.system_groups:
            return self.system_groups
        try:
            grplist = subprocess.check_output(['getent','group'])
        except subprocess.CalledProcessError as e:
            if hasattr(e,'output'):
                grplist = e.output.strip()
            else:
                raise Exception('Error getting grouplist, {}'.format(e))
        except Exception as e:
            raise Exception('Error getting grouplist, {}'.format(e))
            pass
        grplist = grplist.strip().split('\n')
        grpdict = {'bygroup':{},'byuser':{}}
        for line in grplist:
            grpinfo = re.findall('^([^:]+):[^:]:\d+:([^:]*)$',line)
            if grpinfo and grpinfo[0][1]:
                usrlist = grpinfo[0][1].split(',')
                grpdict['bygroup'].setdefault(grpinfo[0][0],usrlist)
                for user in usrlist:
                    grpdict['byuser'].setdefault(user,[])
                    grpdict['byuser'][user].append(grpinfo[0][0])
        self.system_groups = grpdict
        return grpdict

    def get_quotas2(self, format='vfsv0', humanunits=True):
        users = self.get_system_users()
        quotadict = {}
        for user in users:
            quotadict.setdefault(user,self.get_quota_user2(user=user,extended_info=True,format=format,humanunits=humanunits))
        return quotadict

    def get_quota_user2(self, user='all', extended_info=False, format='vfsv0', humanunits=True):
        if user == 'all':
            return self.get_quotas2()
        users = self.get_system_users()
        if user not in users:
            raise Exception('No such user')
        if humanunits == True:
            uparam = '-s'
        else:
            uparam = ''
        try:
            out = subprocess.check_output(['quota','-v',uparam,'-w','-p','-F',format,'-u',user])
        except subprocess.CalledProcessError as e:
            if hasattr(e,'output'):
                out = e.output.strip()
            else:
                raise Exception('Error getting quota for user {} , {}'.format(user,e))
        except:
            raise Exception('Error getting quota for user {}, {}'.format(user,e))

        quotainfo={}
        out = out.split('\n')[2]
        out = out.split()
        if not extended_info:
            quotainfo = out[3]
        else:
            quotainfo['fs']=out[0]
            if out[1][-1] == '*':
                if out[4] != '0':
                    quotainfo['spacestatus']='soft'
                else:
                    quotainfo['spacestatus']='hard'
                quotainfo['spaceused']=out[1][0:-1]
            else:
                quotainfo['spacestatus']='ok'
                quotainfo['spaceused']=out[1]
            quotainfo['spacesoftlimit']=out[2]
            quotainfo['spacehardlimit']=out[3]
            quotainfo['spacegrace']=out[4]
            if out[5][-1] == '*':
                if out[8] != '0':
                    quotainfo['filestatus']='soft'
                else:
                    quotainfo['filestatus']='hard'
                quotainfo['fileused']=out[5][0:-1]
            else:
                quotainfo['filestatus']='ok'
                quotainfo['fileused']=out[5]
            quotainfo['fileused']=out[5]
            quotainfo['filesoftlimit']=out[6]
            quotainfo['filehardlimit']=out[7]
            quotainfo['filegrace']=out[8]

        return quotainfo

    def get_quota_user(self, user='all', extended_info=False):
        quotas = self.get_quotas()
        if user != 'all':
            if not extended_info:
                out = quotas[user]['spacehardlimit'] if user in quotas else None
            else:
                out = quotas[user] if user in quotas else None
        else:
            out = []
            if not extended_info:
                for userquota in quotas:
                    out.append('{}=({})'.format(userquota,quotas[userquota]['spacehardlimit']))
            else:
                for userquota in quotas:
                    tmp=[]
                    for key in quotas[userquota].keys():
                        tmp.append('{}:{}'.format(key,quotas[userquota][key]))
                    out.append('{}=({})'.format(userquota,','.join(tmp)))
            out = ';'.join(out)
        return out

    def set_quota_user(self, user='all', quota='0M', margin='0M', mount='all', filterbygroup=['teachers', 'students'], persistent=True):
        userlist = self.get_system_users()
        groups = self.get_system_groups()
        #print 'set_quota user user = {} quota = {}'.format(user,quota)
        targetuser = []
        if user != 'all':
            if user not in userlist:
                raise Exception('Invalid user, {}'.format(user))
            if filterbygroup:
                for grp_filtered in filterbygroup:
                    if user in groups['bygroup'][grp_filtered]:
                        targetuser.append(user)
            else:
                targetuser.append(user)
        else:
            if filterbygroup:
                for grp_filtered in filterbygroup:
                    for user_in_group in groups['bygroup'][grp_filtered]:
                        if user in userlist:
                            targetuser.append(user)
            else:
                targetuser = userlist
        if not targetuser:
            raise Exception('No users available to apply quota, called user={}'.format(user))
        if not re.findall(r'\d+[KMG]?',str(quota)):
            raise Exception('Invalid quota value, {}'.format(quota))
        quota = self.normalize_units(quota)
        margin = self.normalize_units(margin)
        append_command = []
        devicelist = []
        if mount == 'all':
            append_command.append('-a')
        else:
            devices = self.get_fstab_mounts()
            valid = False
            for dev in devices:
                if os.path.normpath(mount) == dev['fs'] or os.path.normpath(mount) == dev['mountpoint']:
                    valid = True
                    devicelist.append(dev['fs'])
            if not valid:
                raise Exception('mountpoint not valid, {}'.format(mount))
        if persistent:
            qfile = self.get_quotas_file()
        for useritem in targetuser:
            cmd = ['setquota','-u',useritem,str(quota),str(quota+margin),'0','0']
            if devicelist:
                for dev in devicelist:
                    cmd.extend([dev])
                    try:
                        out = subprocess.check_output(cmd)
                    except subprocess.CalledProcessError as e:
                        if hasattr(e,'output'):
                            out = e.output.strip()
                        else:
                            raise Exception('Error setting quota on {} = margin({}) quota({}) for user {}, {}'.format(mount,margin,quota,user,e))
                    except Exception as e:
                        raise Exception('Error setting quota on {} = margin({}) quota({}) for user {}, {}'.format(mount,margin,quota,user,e))
            else:
                cmd.extend(append_command)
                try:
                    out = subprocess.check_output(cmd)
                except subprocess.CalledProcessError as e:
                    if hasattr(e,'output'):
                        out = e.output.strip()
                    else:
                        raise Exception('Error setting quota on {} = margin({}) quota({}) for user {}, {}'.format(mount,margin,quota,user,e))
                except Exception as e:
                    raise Exception('Error setting quota on {} = margin({}) quota({}) for user {}, {}'.format(mount,margin,quota,user,e))
            if persistent and useritem in qfile:
                qfile[useritem] = {'quota':quota,'margin':margin}
        if persistent:
            self.set_quotas_file(qfile)
        return True

    def normalize_units(self,quotavalue):
        value = None
        if type(quotavalue) == type(int()):
            return quotavalue
        if type(quotavalue) == type(str()):
            try:
                value = int(quotavalue)
            except Exception as e:
                try:
                    if quotavalue[-1].lower() == 'g':
                        value = int(quotavalue[:-1])*1024*1024
                    if quotavalue[-1].lower() == 'm':
                        value = int(quotavalue[:-1])*1024
                    if quotavalue[-1].lower() == 'k':
                        value = int(quotavalue[:-1])
                    if not value:
                        try:
                            value = int(quotavalue[:-1])
                        except:
                            pass
                except:
                    pass
        if value == None:
            raise Exception('Unknown unit when normalize')
        return value

    @proxy
    def check_active_quotas(self,mount):
        return self.check_quotas_status(status={'user':'on','group':'on','project':'off'},device=mount,quotatype=['user','group'])

    def check_quotas_status(self, status=None, device='all', quotatype='all'):
        valid_types = ['user','group','project']
        if not status:
            raise Exception('Need valid status when check quotas, {}'.format(status))
        for status_key in status:
            if str(status[status_key]).lower() not in ['on','off']:
                raise Exception('Need valid status when check {} quotas, {}'.format(status_key,status[status_key]))
        if quotatype == 'all':
            typelist = valid_types
        else:
            if isinstance(quotatype,str):
                if str(quotatype).lower() not in valid_types:
                    Exception('Not valid type to check quota on device')
            else:
                if not isinstance(quotatype,list):
                    raise Exception("Type '{}' not valid".format(quotatype))
                typelist = [ str(t).lower() for t in quotatype if str(t).lower() in valid_types ]
                if not typelist:
                    raise Exception("Type '{}' not valid".format(quotatype))

        status_quotaon = self.check_quotaon()
        if not status_quotaon: # empty, not configured quotas
            if status == 'off':
                return True
            else:
                raise Exception('No devices with quota found')
        check = {}
        for key in typelist:
            if device == 'all':
                for mount_path in status_quotaon[key]['mount']:
                        if status_quotaon[key]['mount'][mount_path] != str(status[key]).lower():
                            return False
            else:
                for typedev in status_quotaon[key]:
                    if str(os.path.normpath(device)) in status_quotaon[key][typedev].keys():
                            check.setdefault(key,status_quotaon[key][typedev][str(os.path.normpath(device))])
                if not check:
                    raise Exception('Device not found when trying to check quota status, {}'.format(device))
        if device != 'all':
            if len(check) != len(typelist):
                return False
            for check_item in check:
                if check[check_item] != str(status[check_item]).lower():
                    return False
        return True

    def get_status_file(self):
        try:
            if not os.path.isfile('/etc/lliurex-quota/status'):
                return False
            with open('/etc/lliurex-quota/status','r') as fp:
                status = fp.read().strip()
                if not status:
                    return False
                if status == '1' or str(status).lower() == 'on' or str(status).lower() == 'true':
                    return True
                return False
        except:
            return False

    def set_status_file(self,status=False):
        st = False
        if not status or status == False:
            st = False
        if str(status) == '1' or str(status).lower() == 'on' or str(status).lower() == 'true':
            st = True
        else:
            st = False
        if not os.path.isdir('/etc/lliurex-quota'):
            os.mkdir('/etc/lliurex-quota')
        with open('/etc/lliurex-quota/status','w') as fp:
            fp.write(str(st))
        return st


    def check_quotaon(self):
        try:
            out = subprocess.check_output(['quotaon','-pa'])
            out = out.strip()
        except subprocess.CalledProcessError as e:
            if hasattr(e,'output'):
                out = e.output.strip()
            else:
                raise Exception('Error unexpected output from quotaon, {}'.format(e))
        except Exception as e:
            raise Exception('Error checking quotaon {}'.format(e))
        tmp = re.findall(r'(user|group|project) quota on (\S+) \((\S+)\) is (on|off)',out,re.IGNORECASE)
        out = {}
        for line in tmp:
            out.setdefault(line[0],{'mount':{},'device':{}})
            out[line[0]]['mount'].setdefault(line[1],line[3])
            out[line[0]]['device'].setdefault(line[2],line[3])
        return out if out else None

    def check_rquota_active(self):
        try:
            rpcinfo = subprocess.check_output(['rpcinfo','-p'])
        except Exception as e:
            raise Exception('Error checking rpcinfo, {}'.format(e))
        return True if 'rquotad' in rpcinfo else False

    def activate(self, type):
        scripts_path = '/usr/share/quota/'
        types = {
                'quotaon': {'script': scripts_path + 'quotaon.sh', 'checker': self.check_quotas_status, 'args': {'status':{'user':'on','group':'on','project':'off'},'device':'all','quotatype':['user','group']} },     # todo: check/handle project quotas
                'quotaoff': {'script': scripts_path + 'quotaoff.sh', 'checker': self.check_quotas_status, 'args': {'status':{'user':'off','group':'off','project':'off'},'device':'all','quotatype':['user','group']} }, # todo: check/handle project quotas 
                'quotarpc': {'script': scripts_path + 'quotarpc.sh', 'checker': self.check_rquota_active }
                }
        if type not in types.keys():
            raise Exception('{} not valid type for activation'.format(type))
        try:
            self.activate_script(types[type])
        except Exception as e:
            max_errors = 3
            while max_errors > 0:
                try:
                    time.sleep(1)
                    self.activate_script(types[type])
                except:
                    max_errors = max_errors - 1
            if max_errors == 0 and DEBUG:
                import traceback
                print("ERROR ACTIVATING '{}', '{}', '{}'".format(type,e,traceback.print_exc()))

    def activate_script(self, script):
        checker = script['checker']
        args = script['args'] if 'args' in script else None
        name = script['script']
        if args:
            res = checker(**args)
        else:
            res = checker()

        if not res:
            if not os.path.isfile(name):
                raise Exception('{} not found'.format(name))
            try:
                subprocess.call([name], shell=True, stderr=open(os.devnull,'w'), stdout=open(os.devnull,'w'))
            except Exception as e:
                raise Exception('Error calling {}'.format(name))
            if args:
                res = checker(**args)
            else:
                res = checker()
            if not res:
                raise Exception('Error trying to activate {}'.format(name))
        return True

    @proxy
    def get_quotas(self,*args,**kwargs):
        uparam = ''
        if 'humanunits' in kwargs:
            if kwargs['humanunits'] == True:
                uparam = '-asup'
            else:
                uparam = '-aup'
        else:
            uparam = '-asup'
        try:
            quotalist = subprocess.check_output(['repquota',uparam,'-Ocsv'])
        except subprocess.CalledProcessError as e:
            if hasattr(e,'output'):
                quotalist = e.output.strip()
            else:
                raise Exception('Error getting quotalist, {}'.format(e))
        except Exception as e:
            raise Exception('Error getting quotalist, {}'.format(e))
        quotalist = quotalist.strip().split('\n')
        quotadict = {}
        skip = 1
        for line in quotalist:
            if skip == 1:
                skip=0
                continue
            fields = line.split(',')
            quotadict[fields[0]] = {}
            quotadict[fields[0]]['spacestatus'] = fields[1]
            quotadict[fields[0]]['filestatus'] = fields[2]
            quotadict[fields[0]]['spaceused'] = fields[3]
            quotadict[fields[0]]['spacesoftlimit'] = fields[4]
            quotadict[fields[0]]['spacehardlimit'] = fields[5]
            quotadict[fields[0]]['spacegrace'] = fields[6]
            quotadict[fields[0]]['fileused'] = fields[7]
            quotadict[fields[0]]['filesoftlimit'] = fields[8]
            quotadict[fields[0]]['filehardlimit'] = fields[9]
            quotadict[fields[0]]['filegrace'] = fields[10]
        return quotadict

    @proxy
    def get_userquota(self,*args,**kwargs):
        retlist = []
        for user in args:
            retlist.append(self.get_quota_user2(user=user))
        return retlist

    @proxy
    def set_userquota(self,user,quota,*args,**kwargs):
        if len(args) == 0:
            margin = 0
        else:
            margin = args[0]
        #print 'setting {} = {}'.format(user,quota)
        try:
            return self.set_quota_user(user=user,quota=quota,margin=margin,**kwargs)
        except Exception as e:
            return str(e)

    def apply_quotasdict(self,quotadict):
        for user in quotadict:
            self.set_userquota(user,quotadict[user]['quota'],quotadict[user]['margin'],persistent=False)

    @proxy
    def get_status(self):
        return self.get_status_file()

    def get_local_status(self):
        ret = {}
        ret['running_system'] = self.detect_running_system()
        ret['use_nfs'] = self.detect_nfs_mount()
        try:
            ret['status_serversync'],fs,mount = self.detect_status_folder('/net/server-sync')
            try:
                ret['status_quotas'] = self.check_active_quotas(fs)
            except Exception as e:
                ret['status_quotas'] = 'Fail checking if quotas are active on filesystem {}, {}'.format(fs,e)
        except Exception as e:
            ret['status_serversync']='Fail checking if /net/server-sync are configured, i will use \'all\' as device to check if quotas are active {}'.format(e)
            try:
                ret['status_quotas'] = self.check_active_quotas(fs)
            except Exception as e2:
                try:
                    ret['status_quotas'] = self.check_active_quotas('all')
                except Exception as e3:
                    ret['status_quotas'] = 'Fail checking if quotas are active, {}, {}, {} '.format(e,e2,e3)
        ret['status_file'] = self.get_status()
        return ret

    @proxy
    def get_quotafile(self):
        return self.get_quotas_file()

    @proxy
    def set_status(self,status):
        return self.set_status_file(status=status)

    @proxy
    def detect_status_folder(self,folder):
        qmounts = self.get_mounts_with_quota()
        mount=folder
        fs= '/'
        fs,mount = self.detect_mount_from_path(folder)
        done=False
        if qmounts:
            for qm in qmounts:
                if qm['mountpoint'] == mount:
                    fs = qm['fs']
                    done = True
        return (done,fs,mount)

    @proxy
    def configure_net_serversync(self):
        #qmounts = self.get_mounts_with_quota()
        mount = '/net/server-sync'
        fs= '/'
        #fs,mount = self.detect_mount_from_path(mount)
        #done=False
        #if qmounts:
        #    for qm in qmounts:
        #        if qm['mountpoint'] == mount:
        #            fs = qm['fs']
        #            done = True
        #            return True
        done,fs,mount = self.detect_status_folder('/net/server-sync')

        ret = None
        if not done:
            self.set_status_file(True)
            ret = self.set_mount_with_quota(fs)
            self.remount(mount)
            self.check_quotaon()
            self.check_quotas_status(status={'user':'on','group':'on','project':'off'},device=mount,quotatype=['user','group'])
        return ret

    @proxy
    def stop_quotas(self):
        self.activate('quotaoff')
        return self.check_quotaon()

    @proxy
    def start_quotas(self):
        self.activate('quotaon')
        return self.check_quotaon()

    @proxy
    def deconfigure_net_serversync(self):
        mount = '/net/server-sync'
        fs= '/'
        fs,mount = self.detect_mount_from_path(mount)
        self.activate('quotaoff')
        ret = self.unset_mount_with_quota(mount)
        self.set_status_file(False)
        try:
            self.activate('quotaon')
        except:
            pass
        return ret

    def periodic_actions(self):
        if self.get_status():
            if not self.check_quotas_status(status={'user':'on','group':'on','project':'off'},device='all',quotatype=['user','group']):
                self.activate('quotaon')
            if not self.check_rquota_active():
                self.activate('quotarpc')
            self.normalize_quotas()
            return True
        else:
            return False

    def n4d_cron(self, minutes):
        if DEBUG:
            print('n4d_cron called')
        type = self.detect_running_system()
        if DEBUG:
            print('detected {}'.format(type))
        if type and (type == 'master' or type == 'independent'):
            self.periodic_actions()
        return True

def test_quotas():
    test = QuotaManager()
    print 'CHECK QUOTAS FILTERED USER ALUS01 (1)'
    q = test.get_quotas()
    if 'alus01' in q:
        for k in sorted(q['alus01']):
            print k,q['alus01'][k]
    print 'CHECK QUOTAS FILTERED USER ALUS01 (2)'
    q = test.get_quotas2()
    if 'alus01' in q:
        for k in sorted(q['alus01']):
            print k,q['alus01'][k]
    print 'CHECK QUOTA USER ALUS01 (1)'
    print test.get_quota_user('alus01')
    print 'CHECK QUOTA USER ALUS01 (2)'
    print test.get_quota_user2('alus01')
    print 'CHECK QUOTA USER ALUS01 EXTENDED (1)'
    print test.get_quota_user('alus01',True)
    print 'CHECK QUOTA USER ALUS01 EXTENDED (2)'
    print test.get_quota_user2('alus01',True)

def test_set_fs():
    test = QuotaManager()
    print 'DETECTING SYSTEM'
    d = test.detect_running_system()
    print d
    print 'GET MOUNTS'
    print test.get_fstab_mounts()
    print 'GET MOUNTS WITH QUOTAS'
    out=test.get_mounts_with_quota()
    print out
    mount = '/net/server-sync'
    fs= '/'
    print 'DETECT MOUNT SERVERSYNC {}'.format(mount)
    fs,mount = test.detect_mount_from_path(mount)
    print "DETECTED {} {}".format(fs,mount)
    done=False
    if out:
        for x in out:
            if x['mountpoint'] == mount:
                fs = x['fs']
                done = True
    if not done:
        print 'SET SERVER-SYNC {}'.format(fs)
        print test.set_mount_with_quota(fs)
    print 'REMOUNT ALL (DUMMY)'
    print test.remount('all')
    print 'REMOUNT SERVER-SYNC {}'.format(mount)
    print test.remount(mount)
    print 'REMOUNT SD {}'.format(fs)
    print test.remount(fs)
    print 'CHECK QUOTAON'
    print test.check_quotaon()
    print 'CHECK SERVER-SYNC ON {}'.format(mount)
    print test.check_quotas_status(status={'user':'on','group':'on','project':'off'},device=mount,quotatype=['user','group'])
    print 'UNSET SERVER-SYNC {}'.format(mount)
    print test.unset_mount_with_quota(mount)
    print 'CHECK QUOTAON (None)'
    print test.check_quotaon()
    print 'CHECK SD OFF {}'.format(fs)
    print test.check_quotas_status(status={'user':'off','group':'off','project':'off'},device=fs,quotatype=['user','group'])
    print 'SET SERVER-SYNC {}'.format(mount)
    print test.set_mount_with_quota(mount)
    print 'CHECK QUOTAON'
    print test.check_quotaon()
    print 'N4D CALL'
    print test.n4d_cron(0)
    print 'CHECK SD ON {}'.format(fs)
    print test.check_quotas_status(status={'user':'on','group':'on','project':'off'},device=fs,quotatype=['user','group'])
    print 'CHECK SERVER-SYNC/ ON {}'.format(mount)
    print test.check_quotas_status(status={'user':'on','group':'on','project':'off'},device=mount,quotatype=['user','group'])
    print 'CHECK QUOTA USER ALUS01'
    print test.get_quota_user('alus01')
    print 'SET QUOTA USER ALUS01 = 100'
    print test.set_quota_user('alus01','100M')
    print 'CHECK QUOTA USER ALUS01 (100M)'
    print test.get_quota_user('alus01')
    print 'CHECK QUOTA USER ALUS01 (100M) EXTENDED'
    print test.get_quota_user('alus01',True)
    print 'UNSET QUOTA USER ALUS01 = 0'
    print test.set_quota_user('alus01','0')
    print 'CHECK QUOTA USER ALUS01 (0)'
    print test.get_quota_user('alus01')
    print 'GET ALL QUOTAS'
    print test.get_quota_user()
    print 'GET ALL QUOTAS EXTENDED'
    print test.get_quota_user(extended_info=True)
    print 'CHECK QUOTA USER ALUS001 (None)'
    print test.get_quota_user('alus0001')
    print 'UNSET SD {}'.format(fs)
    print test.unset_mount_with_quota(fs)
    print 'CHECK QUOTAON (None)'
    print test.check_quotaon()
    print 'SET SD {}'.format(fs)
    print test.set_mount_with_quota(fs)
    print 'CHECK QUOTAON'
    print test.check_quotaon()

if __name__ == '__main__' and len(sys.argv) != 1 and sys.argv[1] == 'getquotas':
    test_quotas()

if __name__ == '__main__' and len(sys.argv) == 1:
    test_set_fs()
