import os,sys,time
import re
import subprocess
import json
import xmlrpclib
import getpass
import socket
import time
import pwd
import grp
import ldap
import threading
import logging as _logging
import logging.handlers as _handlers

from functools import wraps
import inspect

#
# TODO:
# -Allow use rquotad with parameter -S allowing set remote quotas from nfs share edquota -Frpc -u <user>
# -Check run inside master|slave|independent server(maybe detecting mount with nfs type), maybe repquota (not support -Frpc) is not valid and we've to fallback to setquota|getquota
#

DEBUG = False
ALLOW_DELETED_USERS = False
AUTORESET_DELETED_USERS = True
THREADED = True
CRON_TIMEOUT = 30
MAX_INTERVAL_DROP_NS_CACHES = 30
MAX_MYQUOTA_INTERVAL = 120


LOGFORMAT='QuotaManager:%(lineno)d:%(levelname)s:> %(message)s'
_logging.basicConfig(format=LOGFORMAT)
logging = _logging.getLogger()
_syslog_handler = _handlers.SysLogHandler(address='/dev/log')
_syslog_handler.setFormatter(_logging.Formatter(fmt=LOGFORMAT))
if DEBUG:
	logging.setLevel(_logging.DEBUG)
	_syslog_handler.setLevel(_logging.DEBUG)
else:
	logging.setLevel(_logging.INFO)
	_syslog_handler.setLevel(_logging.INFO)

logging.addHandler(_syslog_handler)

def DBG(thing):
	if DEBUG != True:
		return
	import inspect
	stack = inspect.stack()[1]
	funcname = stack[3]
	callpoint = "{}:{}".format(stack[1],stack[2])
	line = str.strip(stack[4][0])
	print("DEBUG@{}({}[{}]) --> {}".format(funcname,callpoint,line,thing))

class QuotaManager:
	def __init__(self,enable_cron=True):
		# functions that never try to run natively without n4d, fake client not allowed
		self.functions_need_root = ['get_quotas','get_userquota','set_userquota','set_status','configure_net_serversync','deconfigure_net_serversync','start_quotas','stop_quotas','read_autofs_file','reset_all_users']
		self.anon_functions = ['get_myquota_proxied']
		self.fake_client = False
		self.type_client = None
		self.client = None
		self.n4d_server = None
		self.auth = None
		self.system_groups = None
		self.system_users = None
		self.get_client()
		# threaded cron
		self.threaded=THREADED
		self.thread_worker=None
		self.resolution_timer_thread=CRON_TIMEOUT
		self.last_worker_execution=0
		self.exit_thread=False
		if enable_cron:
			self.make_thread_cron()
		self.last_ns_drop_cache = 0
		# cache get myquota
		self.myquota_data = {}

	def make_thread_cron(self):
		if not self.threaded:
			return
		self.thread_worker = threading.Thread(target=self.threaded_cron,name='Daemon cron QuotaManager')
		self.thread_worker.setDaemon(True)
		self.thread_worker.start()

	def set_credentials(self,user,pwd):
		self.auth=(user,pwd)

	def get_client(self,xmlrpc=None):
		if xmlrpc != None and DEBUG:
			logging.debug('Getting client overriding xmlrpc to: {}'.format(xmlrpc))
			self.client = None
		if type(self.client) == type(None):
			self.client = self.init_client(xmlrpc)
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
		#logging.debug('Startup actions in proxied call {} {} {}'.format(func,args,kwargs))
		def decorator(self,*args,**kwargs):
			#logging.debug('into decorator {} {} {}'.format(self,args,kwargs))

			@wraps(func)
			def wrapper(*args,**kwargs):
				ret = "CALLING ERROR"
				logging.debug('into wrapper({}) {} {}'.format(func.__name__,args,kwargs))
				if self.type_client == 'slave':
					# functions that can be done on ((if condition) slave machine), not need to proxy through master server
					exceptions_function_cut_expansion = ['detect_remote_nfs_mount','read_autofs_file']
				else:
					exceptions_function_cut_expansion = []

				rpcserver=None # auto-mode
				if self.fake_client and func.__name__ in self.functions_need_root:
					if os.getuid() != 0:
						self.fake_client = False
						rpcserver='http://127.0.0.1:9779' # manual-mode
						logging.debug('Overriding fake mode')

				if self.fake_client or func.__name__ in exceptions_function_cut_expansion:
					logging.debug('Running fake mode')
					try:
						ret = func(self,*args,**kwargs)
					except Exception as e:
						logging.critical('Error calling {} with cut expansion, exception: {}'.format(func.__name__,e))
					logging.debug('Result from {}: {}\n'.format(func.__name__,ret))
				else:
					logging.debug('Running xmlrpc mode')
					try:
						self.client = self.get_client(xmlrpc=rpcserver)
					except Exception as e:
						if rpcserver:
							logging.critical('Exception when getting a client with custom rpcserver({}), {}'.format(rpcserver,e))
						else:
							logging.critical('Exception when getting a client, {}'.format(e))
					try:
						self.client.listMethods()
						#
						# TODO: check and emit warning if method used it's not configured as xmlrpc call
						# missing into n4d conf file
						#
					#except ResponseNotReady as e:
					#    print('Couldn\'t create N4D client, aborting call ({}), {}'.format(func.__name__,e))
					except Exception as e:
						logging.critical('Couldn\'t create N4D client, aborting call ({}),{}'.format(func.__name__,e))
						return
					logging.debug('running n4d mode with server {}'.format(self.n4d_server))
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
					if func.__name__ in self.anon_functions:
						self.auth = ''
					else:
						if type(self.auth) == type(None):
							self.auth = self.get_auth(func.__name__)
						if type(self.auth) == type(None):
							ret = "N4D doesn't provide this function, check n4d configuration"
							return ret
					params = []
					params.append(self.auth)
					params.append('QuotaManager')
					params.extend(args)
					logging.debug('calling {} with params {}'.format(func.__name__,params))
					ret = getattr(self.client,func.__name__)(*params)
					logging.debug('Result from {}: {}\n'.format(func.__name__,ret))
				return ret
			#logging.debug('created wrapper {} {}'.format(args,kwargs))
			return wrapper(*args,**kwargs)
		return decorator

	def check_ping(self,host):
		ret = False
		try:
			with open(os.devnull,'w') as dn:
				subprocess.check_call(['ping','-c','1',host],stderr=dn,stdout=dn)
			ret = True
		except:
			pass
		return ret

	def get_all_system_groups(self):
		try:
			return sorted(set([ x.gr_name for x in grp.getgrall() ]))
		except Exception as e:
			return []

	def drop_ns_caches(self):
		t = int(time.time())
		if t < self.last_ns_drop_cache + MAX_INTERVAL_DROP_NS_CACHES:
			return
		dbs=['group','passwd']
		try:
			for db in dbs:
				with open(os.devnull,'w') as dn:
					subprocess.check_call(['/usr/sbin/nscd','--invalidate='+db],env=self.make_env(),stderr=dn, stdout=dn)
			self.last_ns_drop_cache = t
		except:
			pass

	def get_users_group(self,group):
		try:
			self.drop_ns_caches()
			return sorted(grp.getgrnam(group).gr_mem)
		except KeyError as e:
			return []
		except Exception as e:
			return str(e)

	@proxy
	def detect_remote_nfs_mount(self,mount='/net/server-sync'):
		try:
			return self.detect_nfs_mount(mount)
		except Exception as e:
			logging.error('Error detecting nfs mount, {}'.format(e))
			return None

	def try_to_automount(self):
		try:
			with open(os.devnull,'w') as dn:
				subprocess.check_call(["bash -c 'cd /net/server-sync/home;ls'"],shell=True, stderr=dn, stdout=dn)
		except:
			pass

	def detect_nfs_mount(self,mount='/net/server-sync'):
		try:
			self.try_to_automount()
			nfsmounts = subprocess.check_output(['findmnt','-J','-t','nfs'],env=self.make_env())
			if nfsmounts == '':
				return False
			nfsmounts_obj = json.loads(nfsmounts)
			parsed_nfsmounts = [ x.get('target') for x in nfsmounts_obj.get('filesystems',[]) ]
			if mount:
				if mount in parsed_nfsmounts:
					return True
				for pnfs in parsed_nfsmounts:
					if pnfs.startswith(mount):
						return True
				return False
			else:
				return False
		except Exception as e:
			raise SystemError('Error detecting nfs mount {}, {}'.format(mount,e))

	def any_slave(self,ips=[]):
		try:
			truncated = [ '.'.join(ip.split('.')[0:2]) for ip in ips ]
			if '10.3' in truncated:
				return True
			else:
				return False
		except Exception as e:
			logging.warning('Exception checking slave network, {}'.format(e))
			return None

	def detect_running_system(self):
		#if self.type_client:
		#    return self.type_client
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
			try:
				if self.any_slave(iplist): # classroom range 10.3.X.X
					if self.detect_nfs_mount(): # nfs mounted or not
						type_client = 'slave'
						self.fake_client = False
					else:
						self.fake_client = True
						type_client = 'independent'
				else:
					self.fake_client = True
					type_client = 'independent'
			except Exception as e:
				logging.error('Exception checking type of server, {}'.format(e))
		elif srv_ip is not None: # dns 'server' is known but is not assigned to me, maybe i am a client
			type_client = 'client'
			self.fake_client = False
		else: # 'server' dns is unknown
			type_client = 'other'
			self.fake_client = True

		self.type_client = type_client
		return type_client

	def get_ip_addr_valid(self,ip_url):
		# check & return ip format with or without https
		def is_ip(ip):
			iplist=re.findall(r'(\d+\.\d+\.\d+\.\d)',ip)
			if not iplist:
				return False
			if len(iplist) != 1:
				return False
			ip=iplist[0]
			iplist = ip.split('.')
			if len(iplist) != 4:
				return False
			for x in iplist:
				if int(x) > 255:
					return False
			return '.'.join(iplist)

		# check url and get valid ip address
		def get_valid_ip_from_dns(url):
			if 'http' in url[0:4]:
				url=url.split('//')
				if len(url) < 2:
					return False
				url=url[1]
			t = url.split('/')
			url = t[0]
			try:
				ip=socket.gethostbyname(url)
			except:
				return False
			return ip

		try:
			ip_url = is_ip(ip_url)
			if ip_url:
				ip = ip_url
			else:
				try:
					ip = get_valid_ip_from_dns(ip_url)
				except Exception as e:
					raise Exception("Error translating ip '{}',{}".format(ip_url,e))
				if not ip:
					raise Exception("Error translating ip '{}'".format(ip_url))
			if self.check_ping(ip):
				return ip
			else:
				raise Exception("'{}' is unreachable".format(ip_url))
		except:
			raise Exception("Error translating ip '{}'".format(ip_url))

	def init_client(self,xmlrpc=None):
		if xmlrpc: # custom rpc server, this case is used by user permission calls on the fs that need to be routed through rpc calls
			# sanitize
			xmlrpc = str(xmlrpc).lower()
			try:
				ip = self.get_ip_addr_valid(xmlrpc)
			except Exception as e:
				raise Exception('Can\'t create xml client, {}, {}'.format(xmlrpc,e))
			url = 'https://' + str(ip) +':9779'
		else: # automatic discovering where does the method need to be called 
			try:
				type = self.detect_running_system()
			except Exception as e:
				logging.error('Exception initiating client, {}'.format(e))
			url = ''
			if type == 'master':
				url = 'fake'    # try to run directly without rpc
			elif type == 'independent': # slaves without nfs mounted or independent servers
				url = 'fake'    # try to run directly without rpc
			elif type == 'slave': # slave's routes his calls to master server
				url = 'https://10.3.0.254:9779' # slave's routes through master server
				if not self.check_ping('10.3.0.254'):
					logging.warning('Nfs master server is not reachable!')
			else:
				try:
					srv_ip = socket.gethostbyname('server')
					if not self.check_ping(srv_ip):
						logging.warning('server {} is not reachable!'.format(srv_ip))
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
			ips = subprocess.check_output(['ip','-o','a','s'],env=self.make_env())
		except subprocess.CalledProcessError as e:
			if hasattr(e,'output'):
				ips = e.output.strip()
			else:
				raise SystemError('Error trying to get local ips, {}'.format(e))
		except Exception as e:
			raise SystemError('Error trying to get local ips, {}'.format(e))
		iplist = []
		for line in ips.split('\n'):
			m = re.search('inet\s+([0-9]{1,3}(?:[.][0-9]{1,3}){3}/[0-9]{1,2})\s+',line)
			if m:
				iplist.append(m.group(1))
		return iplist

	@proxy
	def read_autofs_file(self,autofile):
		if not os.path.exists(autofile):
			raise ValueError('Autofs file not found')
		contents = ""
		try:
			with open(autofile,'r') as fp:
				contents = fp.readlines()
			reg = "\s*[*]\s+.*\s+(\S+)&"
			target = "ERROR"
			no_match = True
			for line in contents:
				match = re.match(reg,line)
				if match:
					target = match.group(1)
					no_match = False
					break
			if no_match:
				raise LookupError("Unable to parse {} (autofile)".format(autofile))
			if target[-1] == '/':
				target = target[:-1]
			return target
		except Exception as e:
			raise e

	def detect_mount_from_path(self,ipath):
		if not os.path.exists(ipath):
			raise ValueError('Path not found')
		try:
			mounts = self.get_fstab_mounts()
			logging.debug("Detected fstab mounts '{}'".format(mounts))
		except Exception as e:
			logging.error('Error getting fstab mounts, {}'.format(e))
			raise e
		out = None
		try:
			out = json.loads(subprocess.check_output(['findmnt','-J','-T',str(ipath)],env=self.make_env()))
			fstype = out['filesystems'][0]['fstype']
			if fstype == "autofs":
				targetfs = self.read_autofs_file(out['filesystems'][0]['source'])
				targetmnt = out['filesystems'][0]['target']
				#if autofs: skips check with fstab
				return targetfs,targetmnt
			if fstype and fstype != "autofs":
				targetfs = out['filesystems'][0]['source']
				targetmnt = out['filesystems'][0]['target']
		except Exception as e:
			logging.error('Error getting mount mapping, {}'.format(e))
			raise e
		try:
			if targetfs in [ x['fs'] for x in mounts ] or targetfs in [ x['alias'] for x in mounts ]:
				return targetfs, targetmnt
			else:
				logging.critical("target fs ({}) from /net/server-sync not matched in fstab mounts".format(targetfs))
				raise LookupError('Filesystem {} not matched from readed fstab'.format(ipath))
				return None
		except Exception as e:
			raise LookupError('Error searching mount list, {}'.format(e))

	def get_comments(self, filename):
		if not os.path.isfile(filename):
			raise ValueError('Not valid filename to get comments, {}'.format(filename))
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
			ids = subprocess.check_output(['blkid','-o','list'],env=self.make_env())
		except subprocess.CalledProcessError as e:
			if hasattr(e,'output'):
				ids = e.output.strip()
			else:
				raise SystemError('Error trying to get block id\'s'.format(e))
		except Exception as e:
			raise SystemError('Error trying to get block id\'s'.format(e))
		ids = ids.strip().split('\n')
		blklist = []
		for line in ids:
			m = re.match(r'^(?P<fs>/\S+)\s+(?P<type>\S+)\s+(?P<mountpoint>\S+)\s+(?P<uuid>\S+)$',line)
			if m:
				blklist.append(m.groupdict())
		if not blklist:
			raise EnvironmentError('Couldn\'t get block list uuids, maybe need run as superuser')
		return blklist

	def get_idx_mapping_lsblk(self):
		out = []
		try:
			# each version of lsblk outputs distinct information, this is the safest method
			ids = subprocess.check_output(['lsblk','-P','-o','NAME,FSTYPE,MOUNTPOINT,UUID'],env=self.make_env())
		except subprocess.CalledProcessError as e:
			if hasattr(e,'output'):
				ids = e.output.strip()
			else:
				raise SystemError('Error trying to get block id\'s'.format(e))
		except Exception as e:
			raise SystemError('Error trying to get block id\'s'.format(e))

		ids = ids.strip().split('\n')
		blklist = []
		for line in ids:
			m = re.match(r'^NAME="(?P<fs>[^"]*)"\s+FSTYPE="(?P<type>[^"]*)"\s+MOUNTPOINT="(?P<mountpoint>[^"]*)"\s+UUID="(?P<uuid>[^"]*)"$',line)
			if m:
				dout = m.groupdict()
				if 'uuid' in dout and dout['uuid'] != '':
					if os.path.exists(dout['fs']):
						blklist.append(dout)
						continue
					
					devfname="{}/{}".format('/dev',dout['fs'])
					if os.path.exists(devfname):
						dout['fs'] = devfname
						blklist.append(dout)
						continue
					
					devfname="{}/{}".format('/dev/mapper',dout['fs'])
					if os.path.exists(devfname):
						dout['fs'] = devfname
						blklist.append(dout)
						continue
					
					logging.warning("Error finding device name {} ".format(dout['fs']))
		if not blklist:
			raise EnvironmentError('Couldn\'t get block list uuids, maybe the output format of lsblk ... has changed !!')
		return blklist

	def get_realname(self,devicelink):
		out = []
		try:
			# each version of lsblk outputs distinct information, this is the safest method
			realname = subprocess.check_output(['readlink','-f',str(devicelink)],env=self.make_env())
		except subprocess.CalledProcessError as e:
			if hasattr(e,'output'):
				realname = e.output.strip()
			else:
				raise SystemError('Error trying to get realname from {}, {}\'s'.format(devicelink,e))
		except Exception as e:
			raise SystemError('Error trying to get realname from {}, {}'.format(devicelink,e))
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
			logging.debug('blocklist from lsblk: {}'.format(blklist))
		except Exception as e:
			try:
				blklist = self.get_idx_mapping_blkid()
				logging.debug('blocklist from blkid: {}'.format(blklist))
			except Exception as e2:
				raise SystemError('Couldn\'t get block id\'s !!\nlsblk says: {}\nblkid says: {}\n'.format(e,e2))

		for linefstab in out:
			if linefstab['fs'].lower()[0:4] == 'uuid':
				for blk in blklist:
					logging.debug('Checking {} with {}'.format(linefstab,blk))
					if linefstab['fs'].lower() == 'uuid='+blk['uuid'].lower():
						linefstab['fs'] = blk['fs']
						linefstab['uuid'] = blk['uuid']
						break
				if not linefstab.get('uuid'):
					logging.error('Error mapping uuid from {}'.format(linefstab))
					raise SystemError('Error mapping uuid from {}'.format(linefstab))
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
						raise SyntaxError('Malformed option'.fomat(part))
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
			raise LookupError('No target filesystems to remove quotas')
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
		try:
			self.activate('quotaoff')
		except Exception as e:
			logging.error('Fail deactivating quotas {}'.format(e))
		for target in targets:
			try:
				self.remount(target['mountpoint'],forceumount=False)
			except:
				if target['mountpoint'] == "/":
					logging.warning("WARNING: Forced umount not allowed on / need to restart")
				else:
					logging.warning("Forced remount for path {}".format(target['mointpoint']))
					self.remount(target['mountpoint'],forceumount=True)
		for file in quotafiles:
			os.unlink(file)
		quota_mounts = self.get_mounts_with_quota()
		if quota_mounts:
			try:
				self.activate('quotaon')
			except Exception as e:
				logging.error('Fail activating quotas, {}'.format(e))
		return True

	def remount(self,mount='all',forceumount=False):
		if not mount:
			raise ValueError('Need mount when call remount')
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
				raise LookupError('No target filesystems to remove quotas')
		else:
			cmd_append.append('-a')
		cmd = ['mount','-o','remount']
		if mount == 'all':
			try:
				cmd.extend(cmd_append)
				out = subprocess.check_output(cmd,env=self.make_env())
			except subprocess.CalledProcessError as e:
				if hasattr(e,'output'):
					out = e.output
					return False
				else:
					raise SystemError('Error trying to remount ({}) {}, {}'.format(cmd,mount,e))
			except Exception as e:
					raise SystemError('Error trying to remount ({}) {}, {}'.format(cmd,mount,e))
		else:
			for target in targets:
				if forceumount:
					cmdtmp = ['umount','-l',target['mountpoint']]
					try:
						out = subprocess.check_output(cmdtmp,env=self.make_env())
					except subprocess.CalledProcessError as e:
						if hasattr(e,'output'):
							out = e.output
							return False
						else:
							raise SystemError('Error trying to remount ({}),{}, {}'.format(cmdtmp,mount,e))
					except Exception as e:
						raise SystemError('Error trying to remount ({}) {}, {}'.format(cmdtmp,mount,e))

					cmdtmp = ['mount','-o',target['options'],target['mountpoint']]
					try:
						out = subprocess.check_output(cmdtmp,env=self.make_env())
					except subprocess.CalledProcessError as e:
						if hasattr(e,'output'):
							out = e.output
							return False
						else:
							raise SystemError('Error trying to remount ({}),{}, {}'.format(cmdtmp,mount,e))
					except Exception as e:
						raise SystemError('Error trying to remount ({}) {}, {}'.format(cmdtmp,mount,e))
				else:
					cmdtmp = cmd + ['-o',target['options'],target['mountpoint']]
					try:
						out = subprocess.check_output(cmdtmp,env=self.make_env())
					except subprocess.CalledProcessError as e:
						if hasattr(e,'output'):
							out = e.output
							return False
						else:
							raise SystemError('Error trying to remount ({}),{}, {}'.format(cmdtmp,mount,e))
					except Exception as e:
						raise SystemError('Error trying to remount ({}) {}, {}'.format(cmdtmp,mount,e))
		return True

	def set_mount_with_quota(self, mount=None):
		if mount == None:
			raise ValueError('Mandatory mountpoint when setting quotas')
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
					raise RuntimeWarning('Mount {} already with quota'.format(mountitem['mountpoint']))
				else:
					if mountitem['type'] not in ['ext3','ext4','xfs','reiserfs']:
						raise TypeError('Type {type} for filesystem {fs} not suitable for quotas'.format(**mountitem))
					targets.append(mountitem)
			else:
				nontargets.append(mountitem)
		if not targets:
			raise LookupError('No target filesystems to add quotas')
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
		try:
			self.activate('quotaoff')
		except Exception as e:
			logging.error('Fail deactivating quotas {}'.format(e))
		for target in targets:
			try:
				out=subprocess.check_output(['quotacheck','-vguma'],stderr=subprocess.STDOUT,env=self.make_env())
			except subprocess.CalledProcessError as e:
				if hasattr(e,'output'):
					raise SystemError('Error trying to check initial quotas on {}, {}, {}'.format(target['fs'],e,e.output.strip()))
				else:
					raise SystemError('Error trying to check initial quotas on {}, {}'.format(target['fs'],e))
			except Exception as e:
				raise SystemError('Error trying to check initial quotas on {}, {}'.format(target['fs'],e))
		try:
			self.activate('quotaon')
			self.activate('quotarpc')
		except Exception as e:
			logging.error('Fail activating quotas {}'.format(e))
		return True

	def get_system_users(self,use_cache=False):
		if use_cache and self.system_users:
			return self.system_users
		if not use_cache:
			self.drop_ns_caches()
		try:
			pwdlist = subprocess.check_output(['getent','passwd'],env=self.make_env())
		except subprocess.CalledProcessError as e:
			if hasattr(e,'output'):
				pwdlist = e.output.strip()
			else:
				raise SystemError('Error getting userlist, {}'.format(e))
		except Exception as e:
			raise SystemError('Error getting userlist, {}'.format(e))
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
			try:
				with open(filepath,'w') as fp:
					fp.write("{}\n")
			except Exception as e:
				raise ValueError('Missing quotas file {}, fail when creating {}'.format(filepath,e))
		try:
			with open(filepath,'r') as fp:
				qinfo = json.load(fp)
		except Exception as e:
			raise SystemError('Error reading file quotas {}, {}'.format(filepath,e))
		if type(qinfo) != type(dict()):
			raise SystemError('Error reading file quotas {}, expected dictionary'.format(filepath))
		return qinfo

	def set_quotas_file(self,quotasdict={}):
		folder = '/etc/lliurex-quota'
		file = 'quotas'
		filepath = folder + '/' + file
		if type(quotasdict) != type(dict()):
			raise ValueError('Invalid dictionary quotas passed to set_quotas_file')
		if not os.path.isdir(folder):
			try:
				os.mkdir(folder)
			except Exception as e:
				raise SystemError('Error creating quotas dir {}, {}'.format(folder,e))
		try:
			with open(filepath,'w') as fp:
				json.dump(quotasdict,fp,sort_keys=True)
		except Exception as e:
			raise SystemError('Error writting file quotas {}, {}'.format(filepath,e))
		return True

	def get_moving_directories(self):
		try:
			import net.Lliurex.Classroom.MovingProfiles as moving
			mp = moving.MovingProfiles('')
			return mp.cfg['include'].values()
		except:
			raise ImportError('Unable to get moving directories')

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
		# def print_dict_ordered(d,level=0,filter='^(file|space|quota|margin|norm|hard|soft)',userfilter='alus01',usefilter=False):
		# 	try:
		# 		filtered = False
		# 		ret = ''
		# 		inc = 4
		# 		space = ' '*(level+inc)
		# 		dspace = space + space
		# 		for x,y in ((ks,d[ks]) for ks in sorted(d.keys())):
		# 			if usefilter:
		# 				if not (re.match(filter,x) or re.match(userfilter,x)):
		# 					filtered = True
		# 					continue
		# 			if isinstance(y,dict):
		# 				ret += '\n{}{}{}{}'.format(space,x,dspace,str(print_dict_ordered(y,level+inc)))
		# 			else:
		# 				ret += '\n{}{} -> {}'.format(space,x,y)
		# 		if filtered:
		# 			return '{}\nWARNING THIS IS FILTERED DATA, REMOVE FILTER TO VIEW FULL DATA\n'.format(ret)
		# 		else:
		# 			return ret
		# 	except Exception as e:
		# 		import traceback
		# 		logging.info('{},\n{}'.format(e,traceback.print_exc()))

		logging.debug('INIT NORMALIZATION PROCESS')

		# FIRST PASS(A): GET QUOTAS APPLIED ON SYSTEM
		quotas = self.get_quotas(humanunits=False,quotamanager=True)
		#logging.debug('quotas from fs (raw) (absolute values) {}'.format(print_dict_ordered(quotas)))
		logging.debug('quotas from fs (raw) (absolute values) {}'.format(quotas))
		qdict = {}

		def abs_to_relative(soft,hard):
			hard=self.normalize_units(hard)
			soft=self.normalize_units(soft)
			if hard - soft < 0:
				soft = hard
			margin = hard - soft
			return {'quota': soft,'margin':margin}

		# FIRST PASS(B): STORE QUOTAS INTO DICT
		for quotauser in quotas:
			qdict.setdefault(quotauser,abs_to_relative(quotas[quotauser]['spacesoftlimit'],quotas[quotauser]['spacehardlimit']))

		#logging.debug('qdict (quotas from fs (not absolute values)) {}'.format(print_dict_ordered(qdict)))
		logging.debug('qdict (quotas from fs (not absolute values)) {}'.format(qdict))

		# qdict stores quotas readed from quota subsystem calling repquota, qdict represents actual quotas used by fs

		# SECOND PASS(A): GET ALL GROUPS AND STORE DEFAULT EMPTY QUOTAS FOR ALL ITEM (GROUP)
		sysgroups = self.get_all_system_groups();
		emptygroups = {}
		users_into_groups = {}
		for x in sysgroups:
			emptygroups.setdefault(x,{'margin':0,'quota':0})
			# SECOND PASS(B): BUILD DICT WITH USER->LIST GROUPS THAT IS MEMBER
			sgu = self.get_users_group(x)
			for user in sgu:
				if user in users_into_groups:
					users_into_groups[user].append(x);
				else:
					users_into_groups.setdefault(user,[x]);
		logging.debug('System groups: {}'.format(sysgroups))
		logging.debug('Users into groups: {}'.format(users_into_groups))

		# THIRD PASS(A): GET ALL QUOTAS CONFIGURED FROM APPLICATION OR BUILD NEW FILE WITH DEFAULT QUOTAS
		try:
			qfile = self.get_quotas_file()
			if qfile == {}:
				self.set_quotas_file({'users':qdict,'groups':emptygroups})
				qfile = {'users': qdict,'groups': emptygroups}
		except:
			self.set_quotas_file({'users':qdict, 'groups':emptygroups})
			qfile = qdict

		# qfile stores administrator configured quotas without normalization process

		# THIRD PASS(B): ADD POSSIBLE USER/GROUP DIFERENCES INTO DICT THAT REPRESENTS FILE AND ASSING DEFAULT QUOTAS
		users = self.get_system_users()
		new_users = [ user for user in users if user not in qfile['users'] ]
		deleted_users = [ user for user in qfile['users'] if user not in users ]
		#for user in users:
		#    if user not in qfile['users']:
		for user in new_users:
			qfile['users'].setdefault(user,{'quota':0,'margin':0})
		for user in deleted_users:
			qfile['users'].pop(user,None)
		for g in sysgroups:
			if g not in qfile['groups']:
				qfile['groups'].setdefault(g,{'quota':0,'margin':0})
		#logging.debug('qfile (quotas from/to configfile) {}'.format(print_dict_ordered(qfile)))
		logging.debug('qfile (quotas from/to configfile) {}'.format(qfile))
		# override the minium quota, user or group quota (mandatory)

		# FOURTH PASS: CALCULATE USER QUOTAS TO BE APPLIED FUNCTION OF MEMBER OF GROUPS
		override_quotas = {}
		# CHECK USER QUOTA, IF HAS ONE NONE OF GROUP NEED TO BE USED
		all_users = qfile['users'].keys()
		remove_user = []
		for user in all_users:
			if 'quota' in qfile['users'][user] and qfile['users'][user]['quota'] != 0:
				remove_user.append(user)
		logging.debug('Users with his own user quota: {}'.format(remove_user))
		for user in remove_user:
			all_users.remove(user)
		
		# CHECK GENERIC GROUPS
		generic_groups = ['students','teachers','admins']
		for user in all_users: # (this users have user quota = 0, only uses group quotas) 
			if user in users_into_groups:
				groups_from_user = users_into_groups[user]
			else:
				logging.debug('*** User out from user-group mapping: {}'.format(user))
				continue;
			if not groups_from_user:
				logging.debug('*** User without group: {}'.format(user))
				continue;
			quota_from_group = None
			for group in [ g for g in groups_from_user if g not in generic_groups ]:
				if group in qfile['groups'] and qfile['groups'][group]['quota'] != 0:
					logging.debug('User {} has group quota of {} on {}'.format(user,qfile['groups'][group]['quota'],group))
					if not quota_from_group:
						quota_from_group = qfile['groups'][group]
						logging.debug('New quota is candidate')
					else:
						if qfile['groups'][group]['quota'] > quota_from_group['quota']:
							quota_from_group = qfile['groups'][group]
							logging.debug('Quota is candidate after comparing with last candidate')
						else:
							logging.debug('Quota is not greater than last candidate')
			if quota_from_group:
				logging.debug('Group quota found, generic groups not needed')
			else:
				for generic_group in generic_groups:
					if generic_group in groups_from_user and generic_group in qfile['groups'] and qfile['groups'][generic_group]['quota'] != 0:
						logging.debug('User {} has generic group quota of {} on {}'.format(user,qfile['groups'][generic_group]['quota'],generic_group))
						if not quota_from_group:
							quota_from_group = qfile['groups'][generic_group]
							logging.debug('Generic quota is candidate')
						else:
							if qfile['groups'][generic_group]['quota'] > quota_from_group['quota']:
								quota_from_group = qfile['groups'][generic_group]
								logging.debug('Generic quota is candidate after comparing with last candidate')
							else:
								logging.debug('Generic quota is not greater than last candidate')
			if quota_from_group:
				override_quotas.setdefault(user,quota_from_group)
		
		################### OLD METHOD
		####
		#### IF IT IS MEMBER OF TWO GROUPS: LOWER LIMIT IS APPLIED
		#### IF IT HAS USER QUOTA: GROUP QUOTA IS NOT APPLIED		
		#for sys_group in sysgroups:
		#	if qfile['groups'][sys_group]['quota'] != 0:
		#		userlist_from_sys_group = self.get_users_group(sys_group)
		#		for user_from_sysgroup in userlist_from_sys_group:
		#			mandatory_group = sys_group
		#			
		#			# SEARCH OTHER GROUPS WITH LOWER QUOTA
		#			if user_from_sysgroup in users_into_groups: 
		#				for group_of_user in users_into_groups[user_from_sysgroup]:
		#					if group_of_user in qfile['groups'] and 'quota' in qfile['groups'][group_of_user]:
		#						if qfile['groups'][group_of_user]['quota'] != 0 and qfile['groups'][group_of_user]['quota'] < qfile['groups'][sys_group]['quota']:
		#							mandatory_group = group_of_user
		#				
		#			# SEARCH IF PERSONAL QUOTA IS APPLIED
		#			if user_from_sysgroup in qfile['users'] and 'quota' in qfile['users'][user_from_sysgroup]:
		#				if qfile['users'][user_from_sysgroup]['quota'] == 0: # IF USER QUOTA APPLIED OVERRIDE WILL NOT BE DONE
		#					override_quotas.setdefault(user_from_sysgroup,qfile['groups'][mandatory_group]) 
		
		if len(override_quotas.keys()) > 0:
			logging.info('Overriding quotas for user {}'.format(override_quotas.keys()))
		else:
			logging.debug('No needed to override any quota')

		# begin normalization process
		# FIFTH PASS: NORMALIZE QUOTA & MARGIN VALUES 
		# FIFTH PASS: CHECK DATA DUPLICATION DUE TO MOVING PROFILES 

		userinfo = {}
		for user in qfile['users']:
			userinfo.setdefault(user,{'quota':qfile['users'][user],'normquota':{'hard':0,'soft':0}})
			if user in override_quotas:
				userinfo[user]['quota']=override_quotas[user]
			dpath = self.get_moving_dir(user)

			try:
				if dpath: 

			# detected moving profile's possible duplicated data

					userinfo[user]['moving_quota'] = self.get_user_space(folder=dpath,user=user)[user]

			# real quota must ignore that (moving data) increase of size 

					logging.debug('Getting moving for user ({}) --> {}'.format(user,dpath))
					logging.debug('moving quota {}'.format(userinfo[user]['moving_quota']))

					userinfo[user]['normquota']['hard'] = userinfo[user]['quota']['quota'] + userinfo[user]['quota']['margin'] + (userinfo[user]['moving_quota'] * 2)
					userinfo[user]['normquota']['soft'] = userinfo[user]['quota']['quota'] + (userinfo[user]['moving_quota'] * 2) 
				else:
					userinfo[user]['normquota']['hard'] = userinfo[user]['quota']['quota'] + userinfo[user]['quota']['margin']
					userinfo[user]['normquota']['soft'] = userinfo[user]['quota']['quota']
			except Exception as e:
				import traceback
				logging.error("ERROR NORMALIZING {} {} {}".format(str(e),traceback.format_exc(),user))
				return "{} {} {}".format(str(e),traceback.format_exc(),user)
		#logging.debug('userinfo (normalized data) {}'.format(print_dict_ordered(userinfo)))
		logging.debug('userinfo (normalized data) {}'.format(userinfo))

		# userinfo stores the quotas that should be applied to fs

		qdict2 = {}
		utmp=''
		try:
			for user in userinfo:
				utmp=user
				if user in qdict:
					if user not in quotas:
						continue
					if int(quotas[user]['spacesoftlimit']) != int(userinfo[user]['normquota']['soft']) or int(quotas[user]['spacehardlimit']) != int(userinfo[user]['normquota']['hard']):
						logging.debug('MODIFY USER {} ({},{}) vs ({},{})'.format(user,quotas[user]['spacesoftlimit'],quotas[user]['spacehardlimit'],userinfo[user]['normquota']['soft'],userinfo[user]['normquota']['hard']))
						qdict2.setdefault(user,abs_to_relative(userinfo[user]['normquota']['soft'],userinfo[user]['normquota']['hard']))
				#if userinfo[user]['quota']['quota'] == 0:
				#    if user in qdict and qdict[user]['quota'] != userinfo[user]['quota']['quota']:
				#        qdict2.setdefault(user,{'quota':0,'margin':0})
				#else:
				#    if user in qdict and qdict[user]['quota'] != (userinfo[user]['normquota']['hard'] - userinfo[user]['normquota']['soft']):
				#        qdict2.setdefault(user,{'quota':userinfo[user]['normquota']['soft'],'margin':userinfo[user]['normquota']['hard']-userinfo[user]['normquota']['soft']})
		except Exception as e:
			import traceback
			logging.debug("ERROR COMPARING QUOTAS {} {} {}".format(str(e),traceback.format_exc(),qdict[utmp]))
			return "{} {} {}".format(str(e),traceback.format_exc(),qdict[utmp])

		# qdict2 stores only quotas that must be updated

		# SIXTH PASS: WRITE CHANGES INTO FILE (IF NEW FILE OR NEW USERS/GROUPS DETECTED) AND APPLY FINAL QUOTAS FOR USERS

		#logging.debug('qdict2 (quotas updated) (if empty, none will be updated) {}'.format(print_dict_ordered(qdict2)))
		logging.debug('qdict2 (quotas updated) (if empty, none will be updated) {}'.format(qdict2))
		logging.debug('Writing quotas file: {}'.format(qfile))
		self.set_quotas_file(qfile)
		self.apply_quotasdict(qdict2)
		return True

	def get_user_space(self,folder=None,user=None):
		if user == None or folder == None:
			raise ValueError('Need user and folder getting user space')
		if not os.path.isdir(folder):
			raise ValueError('Invalid folder to get userspace')
		us = self.get_system_users()
		uparam = ''
		if user not in us:
			if str(user).lower() != 'all':
				raise LookupError('Invalid user to get userspace')
		else:
			uparam = '-user {}'.format(user)
		try:
			sizes = subprocess.check_output(['find {} {} -printf "%u %s\n"'.format(folder,uparam) + "| awk '{user[$1]+=$2}; END{ for( i in user) print i \" \" user[i]}'"],shell=True,env=self.make_env())
		except subprocess.CalledProcessError as e:
			if hasattr(e,'output'):
				pwdlist = e.output.strip()
			else:
				raise SystemError('Error getting consumed space by user {}, {}'.format(user,e))
		except Exception as e:
			raise SystemError('Error getting consumed space by user {}, {}'.format(user,e))
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

	def get_system_groups(self,use_cache=False):
		if use_cache and self.system_groups:
			return self.system_groups
		if not use_cache:
			self.drop_ns_caches()
		try:
			grplist = subprocess.check_output(['getent','group'],env=self.make_env())
		except subprocess.CalledProcessError as e:
			if hasattr(e,'output'):
				grplist = e.output.strip()
			else:
				raise SystemError('Error getting grouplist, {}'.format(e))
		except Exception as e:
			raise SystemError('Error getting grouplist, {}'.format(e))
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

	def get_quotas2(self, format='vfsv0', humanunits=True, quotamanager=False):
		users = self.get_system_users()
		quotadict = {}
		for user in users:
			if not quotamanager and not ALLOW_DELETED_USERS and user[0] == '#':
				continue
			quotadict.setdefault(user,self.get_quota_user2(user=user,extended_info=True,format=format,humanunits=humanunits,quotamanager=quotamanager))
		return quotadict

	def get_quota_user2(self, user='all', extended_info=False, format='vfsv0', humanunits=True,quotamanager=False):
		if not quotamanager and not ALLOW_DELETED_USERS and user[0] == '#':
			return None
		if user == 'all':
			return self.get_quotas2(quotamanager=quotamanager)
		users = self.get_system_users()
		if user not in users:
			raise ValueError('No such user')
		if humanunits == True:
			uparam = '-s'
		else:
			uparam = ''
		try:
			with open(os.devnull,'w') as dn:
				if uparam:
					out = subprocess.check_output(['/usr/bin/quota','-v',uparam,'-w','-p','-F',format,'-u',user],env=self.make_env(),stderr=dn)
				else:
					out = subprocess.check_output(['/usr/bin/quota','-v','-w','-p','-F',format,'-u',user],env=self.make_env(),stderr=dn)
		except subprocess.CalledProcessError as e:
			if hasattr(e,'output'):
				out = e.output.strip()
			else:
				raise SystemError('Error getting quota for user {} , {}'.format(user,e))
		except Exception as e:
			raise SystemError('Error getting quota for user {}, {}'.format(user,e))

		quotainfo={}
		if not out:
			raise ValueError('Quota not enabled')
		try:
			out = out.split('\n')[2]
			out = out.split()
		except:
			raise ValueError('Quota format wrong')
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

	def get_quota_user(self, user='all', extended_info=False, quotamanager=False):
		if not quotamanager and not ALLOW_DELETED_USERS and user[0] == '#':
			return None
		quotas = self.get_quotas(quotamanager=quotamanager)
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

	def set_quota_group(self, group='', quota='0M', margin='0M'):
		qfile = self.get_quotas_file()
		nquota = self.normalize_units(quota);
		nmargin = self.normalize_units(margin);
		if group not in qfile['groups']:
			qfile['groups'].setdefault(group,{'quota':nquota,'margin':nmargin});
		else:
			qfile['groups'][group]={'quota':nquota,'margin':nmargin}
		self.set_quotas_file(qfile)
		self.normalize_quotas()
		return True

	def set_quota_user(self, user='all', quota='0M', margin='0M', mount='all', filterbygroup=['teachers', 'students'], persistent=True):
		if str(user) and str(user)[0] == '#':
			user = str(user)[1:]
		filterbygroup=[]
		userlist = self.get_system_users()
		groups = self.get_system_groups()
		#print 'set_quota user user = {} quota = {}'.format(user,quota)
		targetuser = []
		if user != 'all':
			#if user not in userlist:
			#    raise ValueError('Invalid user, {}'.format(user))
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
						#if user in userlist:
						targetuser.append(user)
			else:
				targetuser = userlist
		if not targetuser:
			raise LookupError('No users available to apply quota, called user={}'.format(user))
		if not re.findall(r'\d+[KMG]?',str(quota)):
			raise ValueError('Invalid quota value, {}'.format(quota))
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
				raise ValueError('mountpoint not valid, {}'.format(mount))
		if persistent:
			qfile = self.get_quotas_file()
		for useritem in targetuser:
			if useritem[0] == "#":
				useritem = useritem[1:]
			cmd = ['setquota','-u',useritem,str(quota),str(quota+margin),'0','0']
			if devicelist:
				for dev in devicelist:
					cmd.extend([dev])
					try:
						out = subprocess.check_output(cmd,env=self.make_env())
					except subprocess.CalledProcessError as e:
						if hasattr(e,'output'):
							out = e.output.strip()
						else:
							raise SystemError('Error setting quota on {} = margin({}) quota({}) for user {}, {}'.format(mount,margin,quota,user,e))
					except Exception as e:
						raise SystemError('Error setting quota on {} = margin({}) quota({}) for user {}, {}'.format(mount,margin,quota,user,e))
			else:
				cmd.extend(append_command)
				try:
					out = subprocess.check_output(cmd,env=self.make_env())
				except subprocess.CalledProcessError as e:
					if hasattr(e,'output'):
						out = e.output.strip()
					else:
						raise SystemError('Error setting quota on {} = margin({}) quota({}) for user {}, {}'.format(mount,margin,quota,user,e))
				except Exception as e:
					raise SystemError('Error setting quota on {} = margin({}) quota({}) for user {}, {}'.format(mount,margin,quota,user,e))
			if persistent and useritem in qfile['users']:
				qfile['users'][useritem] = {'quota':quota,'margin':margin}
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
			raise TypeError('Unknown unit when normalize {}'.format(quotavalue))
		return value

	@proxy
	def check_active_quotas(self,mount):
		ret = None
		try:
			ret=self.check_quotas_status(status={'user':'on','group':'on','project':'off'},device=mount,quotatype=['user','group'])
			return ret
		except AssertionError as e:
			return False
		except Exception as e:
			raise SystemError('Error checking quotas, {}'.format(e))

	def check_quotas_status(self, status=None, device='all', quotatype='all'):
		logging.debug("Checking quota status for: status={},device={},quotatype={}".format(status,device,quotatype))
		valid_types = ['user','group','project']
		if not status:
			raise ValueError('Need valid status when check quotas, {}'.format(status))
		for status_key in status:
			if str(status[status_key]).lower() not in ['on','off']:
				raise ValueError('Need valid status when check {} quotas, {}'.format(status_key,status[status_key]))
		if quotatype == 'all':
			typelist = valid_types
		else:
			if isinstance(quotatype,str):
				if str(quotatype).lower() not in valid_types:
					Exception('Not valid type to check quota on device')
			else:
				if not isinstance(quotatype,list):
					raise TypeError("Type '{}' not valid".format(quotatype))
				typelist = [ str(t).lower() for t in quotatype if str(t).lower() in valid_types ]
				if not typelist:
					raise TypeError("Type '{}' not valid".format(quotatype))

		status_quotaon = self.check_quotaon()
		logging.debug("Quota on result: {}".format(status_quotaon))
		if not status_quotaon: # empty, not configured quotas
			if status == 'off':
				return True
			else:
				raise AssertionError('No devices with quota found')
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
					raise LookupError('Device not found when trying to check quota status, {}'.format(device))
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

	def make_env(self,oenv=os.environ.copy()):
		env={}
		env=oenv.copy()
		substitution = { 'LANG': 'C', 'LANGUAGE':'en', 'LC_.*':'en_US.UTF-8'}
		for var in substitution:
			reg = re.compile('^'+var+'$')
			for ovar in oenv:
				m=reg.match(ovar)
				if m:
					env[m.string]=substitution[var]
		return env

	def check_quotaon(self):
		try:
			out = subprocess.check_output(['quotaon','-pa'],env=self.make_env())
			out = out.strip()
		except subprocess.CalledProcessError as e:
			if hasattr(e,'output'):
				out = e.output.strip()
			else:
				raise SystemError('Error unexpected output from quotaon, {}'.format(e))
		except Exception as e:
			raise SystemError('Error checking quotaon {}'.format(e))
		tmp = re.findall(r'(user|group|project) quota on (\S+) \((\S+)\) is (on|off)',out,re.IGNORECASE)
		out = {}
		for line in tmp:
			out.setdefault(line[0],{'mount':{},'device':{}})
			out[line[0]]['mount'].setdefault(line[1],line[3])
			out[line[0]]['device'].setdefault(line[2],line[3])
			try:
				rn = self.get_realname(line[2])
				if os.path.exists(rn):
					out[line[0]].setdefault('alias',{})
					out[line[0]]['alias'].setdefault(rn,line[3])
			except Exception as e:
				pass
		return out if out else None

	def check_rquota_active(self):
		try:
			rpcinfo = subprocess.check_output(['rpcinfo','-p'],env=self.make_env())
		except Exception as e:
			raise SystemError('Error checking rpcinfo, {}'.format(e))
		return True if 'rquotad' in rpcinfo else False

	def activate(self, type, silent=False):
		scripts_path = '/usr/share/quota/'
		types = {
				'quotaon': {'script': scripts_path + 'quotaon.sh', 'checker': self.check_quotas_status, 'args': {'status':{'user':'on','group':'on','project':'off'},'device':'all','quotatype':['user','group']} },     # todo: check/handle project quotas
				'quotaoff': {'script': scripts_path + 'quotaoff.sh', 'checker': self.check_quotas_status, 'args': {'status':{'user':'off','group':'off','project':'off'},'device':'all','quotatype':['user','group']} }, # todo: check/handle project quotas 
				'quotarpc': {'script': '/usr/sbin/rpc.rquotad', 'checker': self.check_rquota_active }
				}
				#'quotarpc': {'script': scripts_path + 'quotarpc.sh', 'checker': self.check_rquota_active }
				#}
		if type not in types.keys():
			raise ValueError('{} not valid type for activation'.format(type))
		if silent:
			types[type]['checker']=None
		try:
			self.activate_script(types[type])
		except Exception as e:
			max_errors = 3
			while max_errors > 0:
				try:
					time.sleep(1)
					self.activate_script(types[type])
					max_errors = -1
				except:
					max_errors = max_errors - 1
			if max_errors == 0 and DEBUG:
				import traceback
				logging.error("ERROR ACTIVATING '{}', '{}', '{}'".format(type,e,traceback.print_exc()))

	def activate_script(self, script):
		checker = script['checker'] if 'checker' in script else None
		args = script['args'] if 'args' in script else None
		name = script['script']

		res = None
		if checker:
			if args:
				res = checker(**args)
			else:
				res = checker()
			logging.debug('Testing activation of {} against {} with result {}'.format(name,args,res))

		if not res:
			if not os.path.isfile(name):
				raise ValueError('{} not found'.format(name))
			try:
				with open(os.devnull,'w') as dn:
					subprocess.call([name], shell=True, stderr=dn, stdout=dn, env=self.make_env())
				logging.debug('Successfully executed {}'.format(name))
			except Exception as e:
				logging.debug('Execution of {} Fail, {}'.format(name,e))
				raise SystemError('Error calling {}'.format(name))
			if checker:
				if args:
					res = checker(**args)
				else:
					res = checker()
				logging.debug('Final testing for activation of {} against {} with result {}'.format(name,args,res))
				if not res:
					raise SystemError('Error trying to activate {}'.format(name))
		return True

	def sync_quotas(self,*args,**kwargs):
		current_detected = self.get_quotas(humanunits=False,quotamanager=True)

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
		if 'quotamanager' in kwargs and kwargs['quotamanager'] == True:
			all_entries=True
		else:
			all_entries=False
		try:
			quotalist = subprocess.check_output(['repquota',uparam,'-Ocsv'],env=self.make_env())
		except subprocess.CalledProcessError as e:
			if hasattr(e,'output'):
				quotalist = e.output.strip()
			else:
				raise SystemError('Error getting quotalist, {}'.format(e))
		except Exception as e:
			raise SystemError('Error getting quotalist, {}'.format(e))
		quotalist = quotalist.strip().split('\n')
		quotadict = {}
		skip = 1
		for line in quotalist:
			if skip == 1:
				skip=0
				continue
			fields = line.split(',')
			if AUTORESET_DELETED_USERS and str(fields[0]) and str(fields[0])[0] == '#':
				if str(fields[5]) != '0':
					#print('RESETTING {}'.format(fields[0]))
					self.reset_user(fields[0][1:])
				#else:
					#print('ALREADY RESETED {}'.format(fields[0]))
				continue
			if not all_entries and not ALLOW_DELETED_USERS:
				if str(fields[0]) and str(fields[0])[0] == '#':
					continue

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
			retlist.append(self.get_quota_user2(user=user,quotamanager=False))
		return retlist

	@proxy
	def get_myquota_proxied(self,user):
		ctime = int(time.time())
		myquota = self.myquota_data.get(user,None)
		if myquota:
			myquota_time = myquota.get('time',None)
			if ctime < myquota_time + MAX_MYQUOTA_INTERVAL:
				return '{},{},{},{}'.format(True,user,myquota.get('used',None),myquota.get('quota',None))
			else:
				logging.debug("Cache myquota expired for user {}".format(user))
				myquota = None
		if not myquota:
			try:
				quota = self.get_quota_user2(user=user,quotamanager=False,extended_info=True,humanunits=False)
				if not isinstance(quota,dict):
					raise ValueError('Invalid quota value got from server')
			except ValueError as e:
				return '{},{},{}'.format(False,user,'Quota not available '+str(e))
			except Exception as e:
				import traceback
				return '{},{},{}'.format(False,user,e+' '+traceback.format_exc())
			if quota:
				quota_used=quota.get('spaceused',None)
				quota_hard=quota.get('spacehardlimit',None)
			else:
				return '{},{}'.format(False,user)
			self.myquota_data[user] = {'time':ctime,'used':quota_used,'quota':quota_hard}
			logging.debug("Setting cache myquota for user {} -> {}".format(user,self.myquota_data[user]))
			return '{},{},{},{}'.format(True,user,quota_used,quota_hard)

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

	def reset_user(self,user):
		try:
			return self.set_userquota(user,0)
		except Exception as e:
			return str(e)

	@proxy
	def reset_all_users(self):
		try:
			return self.set_quota_user(user='all',quota=0,margin=0,filterbygroup=[])
		except Exception as e:
			return str(e)

	@proxy
	def set_groupquota(self,group,quota,*args,**kwargs):
		if len(args) == 0:
			margin = 0
		else:
			margin = args[0]
		try:
			return self.set_quota_group(group=group,quota=quota,margin=margin,**kwargs)
		except Exception as e:
			return str(e)

	def apply_quotasdict(self,quotadict):
		logging.debug('Applying quotas for users {}'.format(quotadict.keys()))
		for user in quotadict:
			self.set_userquota(user,quotadict[user]['quota'],quotadict[user]['margin'],persistent=False)

	@proxy
	def get_status(self):
		return self.get_status_file()

	def get_local_status(self):
		ret = {'local':{},'remote':{}}
		ret['local']['running_system'] = self.detect_running_system()
		ret['local']['use_nfs'] = self.detect_nfs_mount()
		status = None
		try:
			status = self.detect_status_folder('/net/server-sync')
			if not isinstance(status,dict):
				#raise Exception('Unknown return from detect_status_folder, {}'.format(status))
				ret['remote']['status_serversync'] = status
			else:
				ret['remote']['status_serversync'] = status.get('done')
				try:
					ret['remote']['status_quotas'] = self.check_active_quotas(status.get('fs'))
				except Exception as e:
					ret['remote']['status_quotas'] = 'Fail checking if quotas are active on filesystem {}, {}'.format(status.get('fs'),e)
		except Exception as e:
			import traceback
			logging.debug('Fail checking if /net/server-sync are configured, i will use \'all\' as device to check if quotas are active, {}, {}'.format(e,traceback.print_exc()))
			ret['remote']['status_serversync']= status
			try:
				ret['remote']['status_quotas'] = self.check_active_quotas(status.get('fs'))
			except Exception as e2:
				try:
					ret['remote']['status_quotas'] = self.check_active_quotas('all')
				except Exception as e3:
					ret['remote']['status_quotas'] = 'Fail checking if quotas are active, {}, {}, {} '.format(e,e2,e3)
		ret['remote']['status_file'] = self.get_status()
		ret['remote']['use_nfs'] = self.detect_remote_nfs_mount()
		return ret

	@proxy
	def get_quotafile(self):
		return self.get_quotas_file()

	@proxy
	def set_status(self,status):
		return self.set_status_file(status=status)

	@proxy
	def detect_status_folder(self,folder):
		try:
			qmounts = self.get_mounts_with_quota()
		except Exception as e:
			raise Exception('Error getting mounts with quota, {}'.format(e))
		mount=folder
		fs= '/'
		try:
			fs,mount = self.detect_mount_from_path(folder)
		except Exception as e:
			raise Exception('Error getting status folder, {}'.format(e))
		done=False
		if qmounts:
			for qm in qmounts:
				if qm['mountpoint'] == mount:
					fs = qm['fs']
					done = True
		return {'done':done,'fs':fs,'mount':mount }

	@proxy
	def configure_net_serversync(self):
		try:
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
			try:
				status = self.detect_status_folder('/net/server-sync')
			except Exception as e:
				logging.warning('Error getting status of folder /net/server-sync, {}'.format(e))
				status = None

			if not isinstance(status, dict):
				logging.warning('Error unknown type returned from detect_status_folder')
				return None

			ret = None
			if not status.get('done'):
				self.set_status_file(True)
				ret = self.set_mount_with_quota(status.get('fs'))
				self.remount(status.get('mount'))
				self.check_quotaon()
				self.check_quotas_status(status={'user':'on','group':'on','project':'off'},device=status.get('mount'),quotatype=['user','group'])
				self.set_groupquota(group='teachers',quota='100G')
				self.set_groupquota(group='students',quota='50G')
				self.normalize_quotas()
			return ret
		except Exception as e:
			logging.error('Exception occured configuring /net/server-sync, {}'.format(e))
			return False

	@proxy
	def stop_quotas(self):
		try:
			self.activate('quotaoff')
			return self.check_quotaon()
		except Exception as e:
			logging.error('Exception occured stopping quotas, {}'.format(e))
			return False

	@proxy
	def start_quotas(self):
		try:
			self.activate('quotaon')
			return self.check_quotaon()
		except Exception as e:
			logging.error('Exception occured starting quotas, {}'.format(e))
			return False

	def get_groups(self):
		base="ou=Managed,ou=Groups,dc=ma5,dc=lliurex,dc=net"
		type_system = 'x'
		try:
			type_system = self.detect_running_system()
		except:
			pass
		if type_system not in ['client','other']:
			url="ldaps://localhost"
		else:
			url="ldaps://server"
		try:
			client=ldap.initialize(url)
		except Exception as e:
			SystemError('Error connecting ldap server, {}'.format(e))
		try:
			result = client.search_s(base,ldap.SCOPE_SUBTREE)
			# pasted code from LdapManager get_available_groups plugin
			group_list = []
			for group in result:
				g_path,dic=group
				dic["path"]=g_path
				if "posixGroup" in dic["objectClass"]:
					 group_list.append(dic)
			return group_list
		except Exception as e:
			logging.error('Exception occured getting groups, {}'.format(e))
			return [e]

	@proxy
	def deconfigure_net_serversync(self):
		try:
			mount = '/net/server-sync'
			fs= '/'
			fs,mount = self.detect_mount_from_path(mount)
			self.activate('quotaoff')
			ret = self.unset_mount_with_quota(mount)
			self.set_status_file(False)
			# activate other quotas
			try:
				self.activate('quotaon',silent=True)
			except:
				pass
			return ret
		except Exception as e:
			logging.error('Exception occured deconfiguring /net/server-sync, {}'.format(e))
			return False

	def myquota(self):
		user_id = os.getuid()
		if user_id:
			user_name = pwd.getpwuid(user_id)
			try:
				user_name = user_name.pw_name
			except:
				return '{}'.format(False)
		else:
			return '{},{}'.format(False,user_id)
		return self.get_myquota_proxied(user_name)

	def periodic_actions(self):
		if self.get_status():
			try:
				if not self.check_quotas_status(status={'user':'on','group':'on','project':'off'},device='all',quotatype=['user','group']):
					self.activate('quotaon')
				if not self.check_rquota_active():
					self.activate('quotarpc')
			except AssertionError as e:
				return False
			except Exception as e:
				return False
			self.sync_quotas()
			self.normalize_quotas()
			return True
		else:
			return False

	def n4d_cron(self, minutes):
		if self.threaded:
			return
		self.worker_code()

	def threaded_cron(self):
		if not self.threaded:
			return
		while (not self.exit_thread):
			ctime = int(time.time())
			if ctime > self.last_worker_execution + self.resolution_timer_thread: # do jobs
				self.last_worker_execution=ctime
				self.worker_code()
				logging.debug('Done threaded cron at: {}'.format(ctime))
			time.sleep(0.5)

	def worker_code(self):
		try:
			logging.debug('n4d_cron called')
			type = self.detect_running_system()
			logging.debug('Detected running system as {}'.format(type))
			if type and (type == 'master' or type == 'independent'):
				self.periodic_actions()
			return True
		except Exception as e:
			logging.warning('Exception occured on periodic job, {}'.format(e))
			import traceback
			logging.warning('Trace: {}'.format(traceback.format_exc()))
			return False
