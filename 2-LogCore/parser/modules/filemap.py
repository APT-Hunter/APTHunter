from collections import defaultdict
import logging
import sys
import uuid

log = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

class FileMap(object):
    std = {'0': 'stdin', '1' : 'stdout', '2' : 'stderr'}
    std_r = {v : k for (k,v) in std.iteritems()}
    std_uuid = {'0': '0000-0000-0000-0000', '1' : '1111-1111-1111-1111', '2' : '2222-2222-2222-2222'}
    std_uuid_r = {v : k for (k,v) in std_uuid.iteritems()}    
    #print (std_r)
    #raw_input("Press Enter to continue...")

    def __init__(self):
        self.imap = defaultdict(lambda: dict(self.std))
        self.fmap = self.std_r
        self.fuuid = self.std_uuid_r 
	self.objectfile = self.std_r
	self.objectsocket = self.std_r
	self.objectuuid = self.std_uuid_r
	self.processlist = {}

    def get_inode(self, pid, fd):
        """Get inode value for pid, fd pair."""
        key = "{0}:{1}".format(pid, fd)

        if str(fd) in self.std.keys():
            return self.std[fd]	    
        elif pid in self.imap and fd in self.imap[pid]:
            return self.imap[pid][fd]
        else:
            log.debug("Failed to get inode for pid {0} fd {1}".format(pid, fd))
            return None

    def add_file(self, pid, fd, fname, inode, object_uuid):
        self.imap[pid][fd] = inode
        self.fmap[inode] = fname
	self.fuuid[inode] = object_uuid

    def del_file(self, pid, fd):
        """Delete a file from filemap after it has been closed."""
        del self.imap[pid][fd]

    def ino2name(self, inode):
        if inode in self.fmap:
            return (self.fmap[inode])
        else:
            return None

    def ino2uuid(self, inode):
        if inode in self.fuuid:
            return (self.fuuid[inode])
        else:
            return None

    def add_file_object(self, inode, fname):
	if not inode in self.objectfile:			
		self.objectfile[inode] = fname
		object_uuid = uuid.uuid1()
		self.objectuuid[inode] = object_uuid
		
	return (self.objectuuid[inode])

    def remove_file_object(self, inode, fname):
	if not inode in self.objectfile:			
		self.objectfile[inode] = fname
		object_uuid = uuid.uuid1()
		self.objectuuid[inode] = object_uuid
	o_uuid = self.objectuuid[inode]
	o_name = self.objectfile[inode]
	
	del self.objectuuid[inode]
	del self.objectfile[inode]
	
	return (o_uuid, o_name)

    def add_socket_object(self, saddress):
	if not saddress in self.objectsocket:			
		object_uuid = uuid.uuid1()
		self.objectsocket[saddress] = object_uuid
		
	return (self.objectsocket[saddress])

    def add_process(self, subject):
	if not subject in self.processlist:					
		process_uuid = uuid.uuid1()
		self.processlist[subject] = process_uuid		
	
	
	return (self.processlist[subject])

    def find_process(self, pid):
	p_uuid = ""
	p_name = ""		
	for p1 in reversed(list(self.processlist)):		
		if p1.startswith(str(pid)):
			#print("p1", self.processlist[p1], p1.split(":")[1])
			p_uuid = self.processlist[p1]
			p_name = p1.split(":")[1]
			#raw_input("Press Enter to continue...")
			break
			#return(self.processlist[p1], p1.split(":")[1]) 
			#return(self.processlist[p1])
	#return (self.processlist[subject])
	#return (0)
	return(p_uuid, p_name)

