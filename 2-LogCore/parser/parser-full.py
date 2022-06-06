#!/usr/bin/python
import auparse
import audit
import logging
import sys
import os
from os import path
import json
import time
import struct
import binascii
import uuid

from collections import defaultdict

from modules import FileMap, Stream, Event

host_name = "Victim3"
log = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

class ParseError(Exception):
    pass

def get_ts(au):
    event = au.get_timestamp()
    ts = "{0}.{1}:{2}".format(event.sec, event.milli, event.serial)
    return ts

def get_rc(au):
    return au.find_field('exit')

def get_subject(au):
    pid = au.find_field('pid')
    exe = au.find_field('exe')
    try: 
	exe = exe.decode("hex")
    except:
	pass

    if exe.startswith('"'):
    	exe = exe[1:]
    if exe.endswith('"'):
    	exe = exe[:-1]

    

    subject = "{0}:{1}".format(pid, exe)
    return (subject, pid, exe)

class Parser(object):
    first = True

    def __init__(self):
        self.fmap = FileMap()
        self.in_flow = Stream("forward.csv")
        self.out_flow = Stream("backwards.csv")

    def parse_file(self, au_log):
        """Parse an audit log saved in a file."""
        au = auparse.AuParser(auparse.AUSOURCE_FILE, au_log)

        while au.parse_next_event():
	    if (au.get_type_name() =="USER_START"):
            	event = self.handle_USER_START(au)
	    #print (au.get_type_name())
	    #raw_input()
            elif au.get_type() == 1300:
                self.parse_syscall(au)
            au.next_record()

    def parse_syscall(self, au):
        """ Parse a audit log.

        Warning: Order of parsing matters.
        """
        sysnum = au.find_field('syscall')
        self.syscall = sys_table[sysnum]

        #XXX. First syscall is the close() before the execve() for the tracing.
        if self.first:
            self.first = False
            return

        #log.debug("Parsing syscall: {0}".format(self.syscall))
        if self.syscall in ['open', 'openat', 'execve']:
            event = self.handle_open(au)
            #event = (ts, subject, self.syscall, resource, i_map[resource])
        elif self.syscall in ['read', 'readv']:
            event = self.handle_read(au)
        elif self.syscall in ['write', 'writev']:
            event = self.handle_write(au)
        elif self.syscall in ['close']:
            event = self.handle_close(au)
	elif self.syscall in ['connect', 'accept']:
		event = self.handle_connect(au)
	elif self.syscall in ['clone']:
		event = self.handle_clone(au)
	elif self.syscall in ['fchmodat', 'chmod', 'fchmod']:
            event = self.handle_chmod(au)
	elif self.syscall in ['fchownat', 'chown', 'fchown', 'lchown']:
            event = self.handle_chown(au)
	elif self.syscall in ['unlink', 'unlinkat']:
            event = self.handle_unlink(au)

        else:
            event = "not used."

        if event and event != 'not used.':
            print event

    def handle_new(self, au):
        """ Add resource descriptor to map.

        XXX. Order of fields matter when using find_field.

        1. Adds a mapping from <pid>:fd --> inode.
        """
	syscall= au.find_field('syscall') 
	
        fd = get_rc(au)

        if int(fd) < 0:
            return

	a2 = au.find_field('a2')  # uid   (for chown)  ,   mode for chmod
	a3 = au.find_field('a3')  # gid (for chown)
        items = au.find_field('items')
	#ppid = au.find_field('ppid')
	
	#print ("ppid", ppid)
	#flag1=None
	uid = None
	euid = None
	if (syscall == '59'):
		#subject, pid, exe = get_subject(au)
		pid = au.find_field('pid')		
		exe = au.find_field('exe')
		try: 
			exe = exe.decode("hex")
		except:
			pass

		if exe.startswith('"'):
			exe = exe[1:]
		if exe.endswith('"'):
			exe = exe[:-1]    

		subject = "{0}:{1}".format(pid, exe)

		if ("whoami" in exe):
			print ("exe", exe)
			#print ("name", name)
			print ("pid", pid)
			print (au.get_record_text())
			#flag1 = "True"
			#raw_input("")	
		process_uuid, exe = self.fmap.find_process(pid)		
		
		if not process_uuid:		    	
			
			process_uuid = self.fmap.add_process(subject)
		
				
	else:
		subject, pid, exe = get_subject(au)	
		#subject is pid:exe

		# adjust exe: if exe is in hex, convet it to Ascii
		#try: 
		#	exe = exe.decode("hex")
		#except:
		#	pass
		 		

		process_uuid = self.fmap.add_process(subject)	

	
        key = "{0}:{1}".format(pid, fd)

	flag =0
        record_text = au.get_record_text()
	print (record_text)
	#if (ts == "1617161944.787:132899420"):
	#	flag = 1
	#	print ("hit")
	#	raw_input("Press Enter to continue...")	

	
        # Get CWD.	
			
	au.next_record()
	#if (flag1 =="True"):
	#	print ("exe", exe)
	#	#print ("name", name)
	#	print ("pid", pid)
	#	print (au.get_record_text())
	#	raw_input("")

	sys_type = au.find_field('type')
	exe_a1 = None
	exe_a2 = None	
	if (sys_type == 'EXECVE'):
		argc = au.find_field('argc')

		if (int(argc) ==2):
			exe_a1 = au.find_field('a1')
		elif (int(argc) >=3):
			exe_a1 = au.find_field('a1')
			exe_a2 = au.find_field('a2')
		else:
			pass	
		exe_a1 = None if not exe_a1 else exe_a1
		exe_a2 = None if not exe_a2 else exe_a2
		#if (int(argc) == 3):
		#	print("exe_a1", exe_a1)
		#	print("exe_a2", exe_a2)
		#	raw_input()
		#print("aaaaaaaaa")
		#print (au.get_record_text())
		#raw_input("")
		#cwd = au.find_field('cwd')
		#print("type", au.find_field('type'))			
		#raw_input("")
		#if (not au.find_field('type')):
		if (int(argc) == 2 or int(argc) == '3'):
			pass
		else:
		
			au.next_record()
		#print ("sys_type", sys_type)
		#raw_input("Press Enter to continue...")
	#if (flag1 =="True"):			
	#	print (au.get_record_text())
	#	raw_input("")
	#if (au.find_field('type') == "PATH" and flag1 =="True"):
	#	print ("exe", exe)
	#	#print ("name", name)
	#	print ("pid", pid)
	#	print (au.get_record_text())
	#	raw_input("")

        cwd = au.find_field('cwd')
	
        au.next_record()
	

        name = au.find_field('name')
		

        if not name:
            log.debug("Name returned None: {0}".format(record_text))
            return
	
	#if ("whoami" in name and syscall == '59'):
	#	print ("exe", exe)
	#	print ("name", name)
	#	print ("pid", pid)
	#	raw_input("")
	
	# REMOVING " FROM START AND END OF STRING	
	if name.startswith('"'):
		name = name[1:]
	if name.endswith('"'):
		name = name[:-1]

	if cwd.startswith('"'):
		cwd = cwd[1:]
	if cwd.endswith('"'):
		cwd = cwd[:-1]

        if fd not in ['0', '1', '2']:
            ino = au.find_field('inode')
            au.get_record_text
            inode = hex(int(au.find_field('inode')))
        else:
            # stdin, stdout, ...
            inode = fd
	#if (sys_type == "EXECVE"):
		#print ("name", name)
		#print ("cwd", cwd)
		#raw_input("Press Enter to continue...")
        name = name if '.' != name[0] else path.join(cwd + name[1:])
	name = name if '/' == name[0] else path.join(cwd + '/' +name)	    
	if (exe == "usr/bin/whoami" and syscall == 'EXECVE'):
		print ("exe", exe)
		print ("name", name)
		print ("pid", pid)
		raw_input("")
	if (syscall == '59'):
		object_process = "{0}:{1}".format(pid, name)
		
		object_uuid = self.fmap.add_process(object_process)

	else:
		
		object_uuid = self.fmap.add_file_object(inode, name)	

	self.fmap.add_file(pid, fd, name, inode, object_uuid)	
	
	# get mode for chmod
	if self.syscall in ['execve']: 
		return (process_uuid, exe, object_uuid, name, exe_a1, exe_a2) 	
	elif self.syscall in ['fchmodat', 'chmod', 'fchmod']:
		#try:			
		a2 = oct(int(a2, 16))		
		#except:
		#	pass

		return (process_uuid, exe, inode, a2)

	elif  self.syscall in ['fchownat', 'chown', 'fchown', 'lchown']:
		#try: 
		
		a2 = int(a2, 16)
		#except:
		#	pass		
		
		return (process_uuid, exe, inode, a2)

	else:

		return (process_uuid, exe, inode)

    def handle_saddr(self, au):
        """ Add resource descriptor to map.

        XXX. Order of fields matter when using find_field.

        1. Adds a mapping from <pid>:fd --> inode.
        """
        fd = get_rc(au)

        #if int(fd) < 0:
        #   return (None, None)


        items = au.find_field('items')
        subject, pid, exe = get_subject(au)
	#subject is pid:exe
	
	# adjust exe: if exe is in hex, convet it to Ascii
	#try: 
	#	exe = exe.decode("hex")
	#except:
	#	pass

        record_text = au.get_record_text()

        # Get saddr.
        au.next_record()
        saddr = au.find_field('saddr')        
        if not saddr:
            log.debug("saddr returned None: {0}".format(record_text))
            return

	
	process_uuid = self.fmap.add_process(subject)	

	packed_data = binascii.unhexlify(saddr)
	if (len(packed_data) != 16):
		return
	s = struct.Struct('2B2B2B2B2B2B2B2B')
	unpacked_data = s.unpack(packed_data)

	#print ('Unpacked Values:', unpacked_data)

	#($f1, $f2, $p1, $p2, @addr) = unpack("A2A2A2A2A2A2A2A2", $saddr);

	family = int(unpacked_data[0]) + 256 * int(unpacked_data[1])
	port = 256 * int(unpacked_data[2]) + int(unpacked_data[3])
	ip1 = int(unpacked_data[4])
	ip2 = int(unpacked_data[5])
	ip3 = int(unpacked_data[6])
	ip4 = int(unpacked_data[7])
	saddress = "{0}.{1}.{2}.{3}:{4}".format(ip1, ip2, ip3, ip4, port)
	object_uuid = self.fmap.add_socket_object(saddress)
        return (process_uuid, exe, object_uuid, saddress)

    def handle_read(self, au):
        """syscalls: read, readv"""
        ts = get_ts(au)
        fd = au.find_field('a0')
        subject, pid, exe = get_subject(au)
	
	process_uuid = self.fmap.add_process(subject)
	subject = "{0}:{1}".format(process_uuid, exe)

        inode = self.fmap.get_inode(pid, fd)
	if (inode == 'stdin' or inode == 'stdout' or inode == 'stderr'):		
		object_name = inode
		object_uuid = fd
	else:				
		object_name = self.fmap.ino2name(inode)
		object_uuid = self.fmap.ino2uuid(inode)

        #event = Event(ts, subject, self.syscall, object_uuid, object_name, host_name)
	event = Event(ts, subject, "READ", object_uuid, object_name, host_name)
        self.in_flow.write(event)

    def handle_write(self, au):
        """syscalls: write, writev"""
        ts = get_ts(au)
        fd = au.find_field('a0')
        subject, pid, exe = get_subject(au)

	process_uuid = self.fmap.add_process(subject)
	subject = "{0}:{1}".format(process_uuid, exe)

        inode = self.fmap.get_inode(pid, fd)
	if (inode == 'stdin' or inode == 'stdout' or inode == 'stderr'):		
		object_name = inode
		object_uuid = fd
	else:				
		object_name = self.fmap.ino2name(inode)
		object_uuid = self.fmap.ino2uuid(inode)

        #event = Event(ts, subject, self.syscall, object_uuid, object_name, host_name)
	event = Event(ts, subject, "WRITE", object_uuid, object_name, host_name)
        self.in_flow.write(event)

    def handle_open(self, au):
        """syscalls open"""
        ts = get_ts(au)
	
	
        parsed_log = self.handle_new(au)
        if not parsed_log:
            return
	
	#try:
	if self.syscall in ['open', 'openat']:
        	process_uuid, exe, resource = parsed_log
	elif self.syscall in ['execve']:
		process_uuid, exe, object_uuid, object_name, a1, a2 = parsed_log
	
	
        if not process_uuid:
            return None
	subject = "{0}:{1}".format(process_uuid, exe)
	
	if not self.syscall in ['execve']:
		object_name = self.fmap.ino2name(resource)
		object_uuid = self.fmap.ino2uuid(resource)

	#if self.syscall in ['execve']:
	#	if a1:
	#		object_name = path.join(object_name + " " + a1[1:-1])
	#	if a2:
	#		object_name = path.join(object_name + " " + a2[1:-1])
		
        #event = Event(ts, subject, self.syscall, object_uuid, object_name, host_name)
	
	if self.syscall in ['open', 'openat']:
		event = Event(ts, subject, "OPEN", object_uuid, object_name, host_name)
	elif self.syscall in ['execve']:
		event = Event(ts, subject, "EXECUTE", object_uuid, object_name, host_name)			
		
        self.in_flow.write(event)
	
	
    def handle_clone(self, au):
        """syscalls: clone"""	
        ts = get_ts(au)
	child_pid = au.find_field('exit')
        fd = au.find_field('a0')
	
	
	subject, pid, exe = get_subject(au)

	#subject is pid:exe

		

	process_uuid = self.fmap.add_process(subject)
	subject = "{0}:{1}".format(process_uuid, exe)
	

	if not process_uuid:
		return None
	
	child_process = "{0}:{1}".format(child_pid, exe)
	
	child_uuid = self.fmap.add_process(child_process)

	
	#if not process_uuid:
	#	process_uuid = self.fmap.add_process(subject)

		
	
	
        #event = Event(ts, subject, self.syscall, object_uuid , object_name, host_name)
	event = Event(ts, subject, "CLONE", child_uuid , exe, host_name)
	#print (event)
	#raw_input("Press Enter to continue...")
        self.in_flow.write(event)


    def handle_connect(self, au):
        """syscalls connect"""	
        ts = get_ts(au)
        parsed_log = self.handle_saddr(au)
        if not parsed_log:
            return
        process_uuid, exe, object_uuid, saddress = parsed_log
        if not process_uuid:
            return None
	
	
	subject = "{0}:{1}".format(process_uuid, exe)

        #name = self.fmap.ino2name(resource)
	
	#event = Event(ts, subject, self.syscall, object_uuid, saddress, host_name)
	if (self.syscall =='connect'):
		event = Event(ts, subject, "CONNECT", object_uuid, saddress, host_name)
	elif (self.syscall =='accept'):
		event = Event(ts, subject, "ACCEPT", object_uuid, saddress, host_name)
	
        
        #XXX. Are opens necessary to store?
        self.in_flow.write(event)

    def handle_chmod(self, au):
        """syscalls chmod"""
        ts = get_ts(au)
	
	
        parsed_log = self.handle_new(au)
        if not parsed_log:
            return
	
        process_uuid, exe, resource, mode = parsed_log
	
        if not process_uuid:
            return None
	subject = "{0}:{1}".format(process_uuid, exe)
	
	object_name = self.fmap.ino2name(resource)
	object_uuid = self.fmap.ino2uuid(resource)

	object_name_mode = "{0}:{1}".format(object_name, mode)
        #event = Event(ts, subject, self.syscall, object_uuid, object_name, host_name)	
	
	event = Event(ts, subject, "MODIFY_FILE_ATTRIBUTES:chmod", object_uuid, object_name_mode, host_name)
		
        self.in_flow.write(event)

    def handle_chown(self, au):
        """syscalls chown"""
        ts = get_ts(au)
	
	
        parsed_log = self.handle_new(au)
        if not parsed_log:
            return
	
        process_uuid, exe, resource, owner = parsed_log
	
        if not process_uuid:
            return None
	subject = "{0}:{1}".format(process_uuid, exe)
	
	object_name = self.fmap.ino2name(resource)
	object_uuid = self.fmap.ino2uuid(resource)

	object_name_mode = "{0}:{1}".format(object_name, owner)
        #event = Event(ts, subject, self.syscall, object_uuid, object_name, host_name)	
	
	event = Event(ts, subject, "CHANGE_PRINCIPAL:chown", object_uuid, object_name_mode, host_name)
		
        self.in_flow.write(event)
		

    def handle_close(self, au):
        """syscalls close"""
        ts = get_ts(au)
        fd = au.find_field('a0')
        subject, pid, exe = get_subject(au)
        #XXX. Delete the fd related to this file.

	process_uuid = self.fmap.add_process(subject)
	subject = "{0}:{1}".format(process_uuid, exe)

        inode = self.fmap.get_inode(pid, fd)
        if not inode:
            return
	
	if (inode == 'stdin' or inode == 'stdout' or inode == 'stderr'):		
		object_name = inode
		object_uuid = fd
	else:				
		object_name = self.fmap.ino2name(inode)
		object_uuid = self.fmap.ino2uuid(inode)
        #self.fmap.del_file(pid, fd)

        #event = Event(ts, subject, self.syscall, object_uuid, object_name, host_name)
	event = Event(ts, subject, "CLOSE" , object_uuid, object_name, host_name)
        self.in_flow.write(event)

    def handle_unlink(self, au):       
        """syscalls unlink"""
	ts = get_ts(au)
	
	
	fd = get_rc(au)

        if int(fd) < 0:
            return

	items = au.find_field('items')
	
	
	subject, pid, exe = get_subject(au)	
	 		

	process_uuid = self.fmap.add_process(subject)

	if not process_uuid:
            return None
	subject = "{0}:{1}".format(process_uuid, exe)	


	flag =0
        record_text = au.get_record_text()
	print (record_text)
	#if (ts == "1617161944.787:132899420"):
	#	flag = 1
	#	print ("hit")
	#	raw_input("Press Enter to continue...")	

	
        # Get CWD.	
			
	au.next_record()

        cwd = au.find_field('cwd')
	
        au.next_record()
	

        name = au.find_field('name')

		
        if not name:
            log.debug("Name returned None: {0}".format(record_text))
            return
	# REMOVING " FROM START AND END OF STRING	
	if name.startswith('"'):
		name = name[1:]
	if name.endswith('"'):
		name = name[:-1]

	if cwd.startswith('"'):
		cwd = cwd[1:]
	if cwd.endswith('"'):
		cwd = cwd[:-1]

        
	name = name if '.' != name[0] else path.join(cwd + name[1:])
	name = name if '/' == name[0] else path.join(cwd + '/' +name)	    
	
	inode = hex(int(au.find_field('inode')))
		
	object_uuid, object_name = self.fmap.remove_file_object(inode, name)	
	
	
	event = Event(ts, subject, "UNLINK", object_uuid, object_name, host_name)
	
		
        self.in_flow.write(event)

    def handle_USER_START(self, au):
	
	ts = get_ts(au)
	pid = au.find_field('pid')
	account = au.find_field('acct')
	
    	if account.startswith('"'):
    		account = account[1:]
    	if account.endswith('"'):
    		account = account[:-1]

	exe = au.find_field('exe')
	try: 
		exe = exe.decode("hex")
    	except:
		pass

    	if exe.startswith('"'):
    		exe = exe[1:]
    	if exe.endswith('"'):
    		exe = exe[:-1]

	process_uuid, pid_exe = self.fmap.find_process(pid)
	#print(process_uuid, pid_exe)
	#raw_input()			
	if not (exe == pid_exe):
		#print(process_uuid, pid_exe, exe)
		#raw_input()
		return None
	        	
        if not process_uuid:
        	return None

	subject = "{0}:{1}".format(process_uuid, exe)
	
	
	object_uuid = process_uuid

	object_name = "{0}:{1}".format(exe, account)
	
	event = Event(ts, subject, "START_USER", object_uuid, object_name, host_name)
	#print (ts, subject, "START_USER", object_uuid, object_name, host_name)	
	#raw_input()
        self.in_flow.write(event)



def main():
    au_log = sys.argv[1]
    #print (uuid.uuid1())
    #raw_input("Press Enter to continue...")
    #std = {'0': 'stdin', '1' : 'stdout', '2' : 'stderr'}
    #std_r = {v : k for (k,v) in std.iteritems()}
    #print ("std_r")
    #raw_input("Press Enter to continue...")
    
    Parser().parse_file(au_log)
    
if __name__ == '__main__':
    with open('./sys_table.json') as infile:
        sys_table = json.load(infile)
    main()

