#!/usr/bin/env python3


###################################
######   Neo4j Parser  ############
## This script extracts    ########
# attack stages         ###########
###    in stages     ##############
# based on stage rules	    #######
## Author: Moustafa Mahmoud #######
## Concordia University ###########
###################################

from neo4j import GraphDatabase
import pandas as pd
#from tabulate import tabulate

#from array import *
import time
import datetime
#from datetime import datetime  
from datetime import timedelta
import pytz
start_time = time.time()

#panada framework - display complete contents of a dataframe
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)

driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", "neo4jchanged"))
threat_scrore = 0
initial_comp_timestamp = datetime.datetime.now()
compromised_process = ''
detections= pd.DataFrame({'host':[], 'detection_type': [], 'detection_timestamp': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Incoming_Connections= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Outgoing_Connections= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
T1571_Non_Standard_Port= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})

Domain_Hijaking= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Intermediate_process': [], 'SYSCALL_2': [], 'IP Address': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
IntRecon= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Exfil= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Exfil_prov= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'Intermediate_process': [], 'SYSCALL_2': [],  'exfil': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
IntRecon_prov= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'Intermediate_process': [], 'SYSCALL_2': [], 'Recon': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
Priv_Escal= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'Intermediate_process': [], 'SYSCALL_2': [], 'Target': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
Proc_Inj= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Target': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})

timestamp_from = datetime.datetime.fromtimestamp(1557804480,  pytz.timezone("AMERICA/NEW_YORK"))
timestamp_to = datetime.datetime.fromtimestamp(1557804480+3600, pytz.timezone("AMERICA/NEW_YORK"))
print (timestamp_from)
print(timestamp_to)
#result = session.run("""MATCH p=(n1)<-[r:SYSCALL*2..]-(n2)<-[r2:SYSCALL]-(n3) 
#WHERE n1.caption = 'sshd' AND (n2.caption = 'sshd' OR n2.caption = 'bash') AND n3.caption contains 'scp'
#MATCH p2=(n1)-[r3:SYSCALL]-(n5) WHERE not r3.type ="CONNECT" AND not r3.type ="ACCEPT"
#RETURN n1.host as host, n1.caption as caption, r2.type as syscall, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""")

with driver.session() as session:
	# Drakon APT - Data Exfiltrate rule - paths that are common on the source subject, destination subject, r2.syscall, and timestamp are grouped and counted 
	# WLed scp that contains /tmp/ paths

	#result = session.run("""MATCH p=(n1)<-[r:SYSCALL*1..]-(n2)<-[r2:SYSCALL]-(n3) 
#WHERE n1.caption = 'sshd' AND (n2.caption = 'sshd' OR n2.caption = 'bash') AND n3.caption =~ 'scp.*' AND not n3.caption =~ '.*/tmp/.*'
#RETURN n1.host as host, n1.caption as caption, r2.type as syscall, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""")
#	for record in result:
#		#rel = record["host"]
#		#rel = record
#		#print(rel)
#		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
#		# data exfiltration 	
#		threat_scrore = 5
#		if (record["count"]<=5):
#			certainty_score = record["count"] 
#		else: 
#			certainty_score = 5		
#		detections = detections.append(pd.DataFrame({'host':[record["host"]], 'detection_type': ["Data exfiltration"], 'detection_timestamp': [record["timestamp"]],'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)		


#Drakon APT - Initial Compromise rule - paths that are common on the source subject, destination subject, r2.syscall, and timestamp are grouped and counted
### Incoming Coneections
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2) WHERE r.type =~"ACCEPT" and n2.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' and not n2.caption =~'128.55.12.51|128.55.12.75|128.55.12.106' and not n1.caption =~ 'sendmail|wget' and not n2.caption =~ '127.0.0.1.*' and n2.caption =~ '130.132.51.8.*|35.106.122.76.*' and not n1.host =~ 'ta1-cadets-3'
RETURN n1.host as host, n1.caption as caption, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration 	
		Incoming_Connections = Incoming_Connections.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

# Outgoing Connections
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2) WHERE r.type =~"CONNECT" and n2.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' and not n2.caption =~'128.55.12.*' and not n1.caption =~ 'firefox|sendmail|wget|pkg|fetch|netstat|ping' and not n2.caption =~ '127.0.0.1.*' and not n2.caption =~ '0.0.0.0:22|0000.*:22'
RETURN n1.host as host, n1.name as caption, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration
		threat_scrore = 5		
		certainty_score = 10
		 			
		Outgoing_Connections = Outgoing_Connections.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

#T1571: Non-Standard Port
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2) WHERE r.type =~"CONNECT" and n2.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' and not n2.caption =~'128.55.12.*' and not n1.caption =~ 'sendmail|wget|pkg|fetch|netstat|ping' and not n2.caption =~ '127.0.0.1.*' and not (n1.caption =~'ssh|sshd' and n2.caption =~'.*:22') and not (n1.caption =~'firefox' and n2.caption =~'.*:80|.*:443')
RETURN n1.host as host, n1.name as caption, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration
		threat_scrore = 5		
		certainty_score = 10
		 			
		T1571_Non_Standard_Port = T1571_Non_Standard_Port.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

#T1584: Compromise Infrastructure
# Domain Hijacking
#SSH Connection to IP after SSH daemon being modifed by Internet explorer service (e.g.,Firefox)
# Check if internet explorer service did other events
	result = session.run("""MATCH p=(n1)-[r1:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) 
WHERE n1.caption =~ 'firefox' AND n2.caption = 'sshd' AND r2.type =~"CONNECT" AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*'  and r2.timestamp >= r1.timestamp
RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r1.type as syscall, n2.caption as caption_n2, r2.type as syscall2, n3.caption as caption_n3, n2.name as name_n2, r2.timestamp as timestamp, count(n3) as count""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration 	
		threat_scrore = 5
		certainty_score = 10
		initial_comp_timestamp = record["timestamp"]
		compromised_process = record["name_n2"]
		print (initial_comp_timestamp)
		print (compromised_process)
		source_proc =  record["caption"] + ':' + record["name_1"]
		Domain_Hijaking = Domain_Hijaking.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall"]], 'Intermediate_process': [record["caption_n2"]], 'SYSCALL_2': [record["syscall2"]], 'IP Address': [record["caption_n3"]], 'Count': [record["count"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)


	# Drakon APT - Recon rule 
#	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2) 
#WHERE (n2.caption =~ 'whoami|hostname|ps.*' or n2.caption =~ 'netstat')
#RETURN n1.host as host, n1.caption as caption, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""")
#	for record in result:
#		#rel = record["host"]
#		#rel = record
#		#print(rel)
#		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
#		# data exfiltration 
#		threat_scrore = 2
#		certainty_score = 0
#		IntRecon = IntRecon.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

	# Firefox Drakon APT - Recon rule 
#	result = session.run("""MATCH p=(n1:SUBJECT)-[r1:SYSCALL]->(n2:SUBJECT)-[r2:SYSCALL*1..]->(n3:SUBJECT)-[r3:SYSCALL]->(n4:SUBJECT) WHERE (n4.caption =~ 'whoami|hostname|ps.*' or n4.caption =~ 'netstat') AND n1.name =~ 'DEF8FC47-7A9A-FBED-6B2A-08B2189BECCD' and r3.timestamp >= r1.timestamp and $date_from < r3.timestamp < $date_to and $date_from < r1.timestamp < $date_to RETURN n1.host as host, n1.caption as caption, n1.name as name_1, n3.caption as caption_n3, n3.name as name_3, r3.type as syscall3, n4.caption as caption_n4, r3.timestamp as timestamp, count(n4) as count""", date_from = timestamp_from, date_to = timestamp_to)
#	for record in result:
#		#rel = record["host"]
#		#rel = record
#		#print(rel)
#		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
#		# data exfiltration 
#		threat_scrore = 2
#		certainty_score = 10		
#		IntRecon_prov = IntRecon_prov.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]+':'+record["name_1"]], 'Intermediate_process': [record["caption_n3"]+':'+record["name_3"]], 'SYSCALL_2': [record["syscall3"]], 'Recon': [record["caption_n4"]], 'threat_Score': [threat_scrore], 'Count': [record["count"]], 'certainity_Score': [certainty_score]}),ignore_index=True)

	
# Privilege Escalation
	result = session.run("""MATCH p=(n1)-[r1:SYSCALL]->(n2)-[r2:SYSCALL*1..]->(n3)-[r3:SYSCALL]->(n4) 
WHERE n1.name = $process_condition AND n4.caption =~ 'sudo insmod.*' and r3.timestamp >= r1.timestamp and r3.timestamp  >= $timestamp_condition
RETURN n1.host as host, n1.name as caption, n3.caption as caption_n3, r3.type as syscall3, n4.caption as caption_n4, r3.timestamp as timestamp, count(n4) as count""", timestamp_condition = initial_comp_timestamp, process_condition = compromised_process
)
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration 	
		threat_scrore = 5
		certainty_score = 10		
		Priv_Escal = Priv_Escal.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'Intermediate_process': [record["caption_n3"]], 'SYSCALL_2': [record["syscall3"]], 'Target': [record["caption_n4"]], 'Count': [record["count"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

# Privilege Escalation
# T1055: Process injection
	result = session.run("""MATCH p=(n1)-[r1:SYSCALL]->(n2) 
WHERE r1.type =~ 'MODIFY_PROCESS'
SET n2:Compromised
SET n1:Culprit
RETURN n1.host as host, n1.name as caption, n2.name as caption_n2, r1.type as syscall, r1.timestamp as timestamp, count(n2) as count""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration 	
		threat_scrore = 5
		certainty_score = 10		
		Proc_Inj = Proc_Inj.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'Target': [record["caption_n2"]], 'Count': [record["count"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

######################## Exfil Stage ###################
# Drakon APT - Data Exfiltrate rule - 
	
#	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2)
#WHERE n2.caption =~ '.*/etc/passwd|.*/etc/shadow|.*/etc/hosts|.*/etc/pwd.db' and not n1.caption =~ 'alpine|whoami|top|sendmail|mail.local|ls|wget|ps|scp|pkg|id|netstat' and r.type = 'EXECUTE' and not #n1.host =~ 'ta1-cadets-3'
#RETURN n1.host as host, n1.caption as caption, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""")
#	for record in result:
#		#rel = record["host"]
#		#rel = record
#		#print(rel)
#		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
#		# data exfiltration 	
#		threat_scrore = 5		
#		certainty_score = 0		
#		Exfil = Exfil.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)		


		
driver.close()  # close the driver object

#with driver.session() as session:
######################## Exfil Stage prov ###################
# firefox Drakon APT - Data Exfiltrate rule -
# Commented but may be needed later: and not n1.caption =~ 'alpine|whoami|top|sendmail|mail.local|ssh|sshd|ls|wget|bash|ps|scp|pkg|id|netstat' 
#commented but may be needd later:and r3.timestamp >=  DateTime({ epochSeconds: toInteger(1557855720), timezone:'AMERICA/NEW_YORK'}) and r3.timestamp <=  DateTime({ epochSeconds: toInteger(1557855840), timezone:'AMERICA/NEW_YORK'}) 
# commented: time.truncate('hour', r3.timestamp) as timestamp
#commented: n1.name =~ '596E9A1F-6548-796C-2C61-654959591AC2'  
	
#	result = session.run("""MATCH p=(n1:SUBJECT:Compromised)-[r1:SYSCALL]->(n2)-[r2:SYSCALL*1..]->(n3)-[r3:SYSCALL]->(n4) 
#WHERE  n4.caption =~ '.*/etc/shadow|.*/etc/passwd' and r3.timestamp >= r1.timestamp and n1.name =~ 'DEF8FC47-7A9A-FBED-6B2A-08B2189BECCD'
#RETURN n1.host as host, n1.caption as caption, n3.caption as caption_n3, n4.caption as caption_n4, r3.type as syscall_2, r3.timestamp as timestamp, count(n4) as count""")
#	for record in result:
#		#rel = record["host"]
#		#rel = record
#		#print(rel)
#		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
#		# data exfiltration 	
#		threat_scrore = 5		
#		certainty_score = 10		
#		Exfil_prov = Exfil_prov.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'Intermediate_process': [record["caption_n3"]], 'SYSCALL_2': [record["syscall_2"]], 'exfil': [record["caption_n4"]], 'Count': [record["count"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

#driver.close()  # close the driver object


# Checking init comp rule (with high certinity) match (no previous incoming connections on the same socket)
for index1, row1 in Outgoing_Connections.iterrows():
	for index2, row2 in Incoming_Connections.iterrows():
		if (row1['detection_details'] == row2['detection_details']):
			Outgoing_Connections.at[index1, 'certainity_Score'] = 0

for index1, row1 in IntRecon.iterrows():
	for index2, row2 in Outgoing_Connections.iterrows():
		if (row1['host'] == row2['host'] and ( (row2['detection_timestamp'] + timedelta(minutes=10)) > row1['detection_timestamp'] >= row2['detection_timestamp'])):
			IntRecon.at[index1, 'certainity_Score'] = 10

#Exfiltrate: checking if the source process is one of the compromised processes
for index1, row1 in Exfil_prov.iterrows():
	for index2, row2 in Domain_Hijaking.iterrows():
		if (row1['host'] == row2['host'] and row1['source'] == row2['source']):
			Exfil_prov.at[index1, 'certainity_Score'] = 10


#for index1, row1 in Exfil.iterrows():
#	for index2, row2 in Proc_Inj.iterrows():
#		if (row1['host'] == row2['host'] and ( (row2['detection_timestamp'] + timedelta(minutes=240)) > row1['detection_timestamp'] >= row2['detection_timestamp'])):
#			Exfil.at[index1, 'certainity_Score'] = 10

#drop false detections
Outgoing_Connections = Outgoing_Connections[Outgoing_Connections.certainity_Score != 0]
IntRecon = IntRecon[IntRecon.certainity_Score != 0]
Exfil_prov = Exfil_prov[Exfil_prov.certainity_Score != 0]
#Exfil = Exfil[Exfil.certainity_Score != 0]


#print("Incoming_Connections")
#print(Incoming_Connections.sort_values(by=['detection_timestamp'], ascending=False))

print("Incoming_Connections")
print(Incoming_Connections.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("T1190 Exploit Public-Facing Applications (Initial Compromise)")
print(Outgoing_Connections.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("T1571 Non_Standard_Port (Initial Compromise)")
print(T1571_Non_Standard_Port.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("T1584-001 Domain_Hijaking")
print(Domain_Hijaking.sort_values(by=['detection_timestamp'], ascending=False))
print("")
#print("Internal Recon")
#print(IntRecon.sort_values(by=['detection_timestamp'], ascending=False))

#print("Internal Recon pROV")
#print(IntRecon_prov.sort_values(by=['detection_timestamp'], ascending=False))
#print("")
print("Privilage Escalation")
print("T1055: Process Injection")
print(Proc_Inj.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("T1068: Exploitation for Privilege Escalation")
print(Priv_Escal.sort_values(by=['detection_timestamp'], ascending=False))

print("")
#print("EXFIL PROV")
#print(Exfil_prov.sort_values(by=['detection_timestamp'], ascending=False))


#print("Data Exfiltrate")
#print(Exfil.sort_values(by=['detection_timestamp'], ascending=False))


#	    print(row1['c1'], row1['c2'])


#detections = detections.groupby(['host']).mean()

#print("")
#print("Host Detections")
#print((detections.sort_values(by=['host'])))

#print("")
#print(detections.groupby(['host']).agg({'threat_Score':'max', 'certainity_Score':'sum'}))

elapsed_time = time.time() - start_time
print("")
print ("Time taken(seconds):", elapsed_time)


#print (pd.concat([detections.groupby(['host']).max(),detections.groupby(['host']).mean()],axis=1))



#host= []
#detections = [][]   #detections[0][1] host number 0 and detection number 1  
#predicateObjectUUIDLlist = []
#predicateObjectPathLlist = []
#predicateObjectUUIDLlist.append(

#for predicateObject_UUID in predicateObjectUUIDLlist:
#						if (predicateObject_UUID == cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']):
#							col5 = predicateObjectPathLlist[predicateObjectUUIDLlist.index(predicateObject_UUID)]
#							break

#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
#detections = [1,2,"asds"]
#print (detections[2])


#obj.a = lambda: None 
#setattr(obj.a, 'smartness', 'Very Smart')
#print (obj.a)

