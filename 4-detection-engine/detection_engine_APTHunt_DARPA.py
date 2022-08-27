#!/usr/bin/env python3


###################################
######   APTHunter     ############
###  Detection Engine - DARPA #####
###################################
###################################

from neo4j import GraphDatabase
import pandas as pd
#from tabulate import tabulate

import os

#from array import *
import time
import datetime
#from datetime import datetime
from datetime import timedelta

from progress.bar import IncrementalBar

import pytz
start_time = time.time()

#panada framework - display complete contents of a dataframe
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)

driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", "neo4jchanged"))
threat_scrore = 0
#Trusted_IP_Addresses_subnet = "128.55.12"
Trusted_IP_Addresses_subnet = "192.168.8.135"
#path_csv = "/home/x10/APTHUNT/reducer/log-reducer-master/parser/results/cadets_eng3_scenario7/1/"
path_csv = "/home/x10/APTHUNT/reducer/log-reducer-master/parser/results/APT41/1/"

initial_comp_timestamp_list = []
compromised_process_list = []
detections= pd.DataFrame({'host':[], 'detection_type': [], 'detection_timestamp': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Incoming_Connections= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Outgoing_Connections= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
T1571_Non_Standard_Port= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})

Domain_Hijaking= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Intermediate_process': [], 'SYSCALL_2': [], 'IP Address': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
FootHold= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Send_Internal = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})

IntRecon= pd.DataFrame({'host':[], 'detection_timestamp': [], 'Compromised Process': [], 'Inter_process': [], 'SYSCALL_2': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Exfil= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Exfil_prov= pd.DataFrame({'host':[], 'detection_timestamp': [], 'Compromised Process': [], 'Intermediate_process': [], 'SYSCALL_3': [], 'exfil': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
Exfil_internal= pd.DataFrame({'host':[], 'detection_timestamp': [], 'Compromised Process': [], 'Intermediate_process': [], 'SYSCALL_3': [], 'exfil': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
IntRecon_prov= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'Intermediate_process': [], 'SYSCALL_2': [], 'Recon': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
Priv_Escal= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'Intermediate_process': [], 'SYSCALL_2': [], 'Target': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
Proc_Inj= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Target': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
Priv_Escal_2= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Target': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})

Clear_logs = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Untrusted_File_RM = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})

timestamp_from = datetime.datetime.fromtimestamp(1557804480,  pytz.timezone("AMERICA/NEW_YORK"))
timestamp_to = datetime.datetime.fromtimestamp(1557804480+3600, pytz.timezone("AMERICA/NEW_YORK"))
print (timestamp_from)
print(timestamp_to)
#result = session.run("""MATCH p=(n1)<-[r:SYSCALL*2..]-(n2)<-[r2:SYSCALL]-(n3) 
#WHERE n1.caption = 'sshd' AND (n2.caption = 'sshd' OR n2.caption = 'bash') AND n3.caption contains 'scp'
#MATCH p2=(n1)-[r3:SYSCALL]-(n5) WHERE not r3.type ="CONNECT" AND not r3.type ="ACCEPT"
#RETURN n1.host as host, n1.caption as caption, r2.type as syscall, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""")


print("I am APTHunt script")
if not os.path.exists(path_csv):
	os.makedirs(path_csv)	

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

#################################################################################
########################## Initial Compromise ###################################
#################################################################################

#Drakon APT - Initial Compromise rule - paths that are common on the source subject, destination subject, r2.syscall, and timestamp are grouped and counted
### Incoming Connections
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2) WHERE r.type =~"ACCEPT" and n2.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' and not n2.caption STARTS WITH $Trusted_Addresses 
RETURN n1.host as host, n1.caption as caption, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""", Trusted_Addresses = Trusted_IP_Addresses_subnet)
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration
		threat_scrore = 0		
		certainty_score = 0
		Incoming_Connections = Incoming_Connections.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

# Outgoing Connections
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2) WHERE r.type =~"CONNECT" and n2.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' and not n2.caption STARTS WITH $Trusted_Addresses and not n2.caption =~ '127.0.0.1.*' and not n2.caption =~ '0.0.0.0.*|0000.*' and not n1.caption =~ '/usr/lib/firefox/firefox|/bin/ping|sendmail|wget|pkg|fetch|netstat|ping|null'
RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""", Trusted_Addresses = Trusted_IP_Addresses_subnet)
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration
		threat_scrore = 5		
		certainty_score = 10		
		Outgoing_Connections = Outgoing_Connections.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

#T1571: Non-Standard Port
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2) WHERE r.type =~"CONNECT" and n2.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' and not n2.caption STARTS WITH $Trusted_Addresses and not n1.caption =~ 'sendmail|wget|pkg|fetch|netstat|ping|null' and not n2.caption =~ '127.0.0.1.*' and not (n1.caption =~'.*ssh|.*sshd' and n2.caption =~'.*:22') and not (n1.caption =~'/usr/lib/firefox/firefox|/bin/ping' and n2.caption =~'.*:80|.*:443|')
RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""", Trusted_Addresses = Trusted_IP_Addresses_subnet)
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration
		threat_scrore = 5		
		certainty_score = 10
		 			
		T1571_Non_Standard_Port = T1571_Non_Standard_Port.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

#T1584: Compromise Infrastructure
# Domain Hijacking
#SSH Connection to IP after SSH daemon being modifed by Internet explorer service (e.g.,Firefox)
# Check if internet explorer service did other events
	result = session.run("""MATCH p=(n1)-[r1:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) 
WHERE n1.caption =~ '/usr/lib/firefox' AND n2.caption = '/bin/ssh' AND r2.type =~"CONNECT" AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*'  and r2.timestamp >= r1.timestamp
RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r1.type as syscall, n2.caption as caption_n2, r2.type as syscall2, n3.caption as caption_n3, n2.name as name_n2, r2.timestamp as timestamp, count(n3) as count""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration 	
		threat_scrore = 5
		certainty_score = 10
		#initial_comp_timestamp = record["timestamp"]
		#compromised_process = record["name_n2"]
		#print (initial_comp_timestamp)
		#print (compromised_process)
		source_proc =  record["caption"] + ':' + record["name_1"]
		Domain_Hijaking = Domain_Hijaking.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall"]], 'Intermediate_process': [record["caption_n2"]], 'SYSCALL_2': [record["syscall2"]], 'IP Address': [record["caption_n3"]], 'Count': [record["count"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

driver.close()  # close the driver object

# Checking init comp rule (with high certinity) match (no previous incoming connections on the same socket)
for index1, row1 in Outgoing_Connections.iterrows():
	for index2, row2 in Incoming_Connections.iterrows():		
		if (row1['detection_details'] == row2['detection_details']):			
			Outgoing_Connections.at[index1, 'certainity_Score'] = 0

#drop false detections
Outgoing_Connections = Outgoing_Connections[Outgoing_Connections.certainity_Score != 0]

for index1, row1 in Outgoing_Connections.iterrows():
	initial_comp_timestamp_list.append(row1['detection_timestamp'])
	compromised_process_list.append(row1['source'].split(':')[1])		
		

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


#send to CSV files
Incoming_Connections.to_csv(path_csv+'Init_Comp_Incoming_Connections.csv',index=True)
Outgoing_Connections.to_csv(path_csv+'Init_Comp_Exploit_Public_Facing.csv',index=True)
T1571_Non_Standard_Port.to_csv(path_csv+'Init_Comp_T1571__Non_Standard_Port.csv',index=True)
Domain_Hijaking.to_csv(path_csv+'Init_Comp_T1584_001_Domain_Hijaking.csv',index=True)


      
#################################################################################
########################## FootHold #############################################
#################################################################################

with driver.session() as session:
	
	bar = IncrementalBar('Countdown', max = len(compromised_process_list))
	for index, compromised_process in enumerate(compromised_process_list):
		bar.next()
		initial_comp_timestamp = initial_comp_timestamp_list[index]
		# Establish FootHold
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3) WHERE n1.name = $process_condition AND r2.type =~'EXECUTE|FORK|CLONE' AND n3.caption =~ '/bin/.*' AND r2.timestamp >= $timestamp_condition 
	RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", timestamp_condition = initial_comp_timestamp, process_condition = compromised_process
	)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			threat_scrore = 5		
			certainty_score = 0
			 			
			FootHold = FootHold.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)


		# Drakon APT - Recon rule
		#Sensitive commands
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3) 
	WHERE n1.name = $process_condition AND r2.type =~'EXECUTE|FORK|CLONE' AND n3.caption =~ '/sbin/.*|/bin/.*|/usr/bin/.*|/usr/local/.*|/usr/sbin/.*' AND r2.timestamp >= $timestamp_condition 
	RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n2.caption as caption_2, n2.name as name_2, n3.caption as caption_3, localdatetime(r2.timestamp) as timestamp, count(n3) as count""", timestamp_condition = initial_comp_timestamp, process_condition = compromised_process
	)
	#localdatetime(r2.timestamp)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration 
			threat_scrore = 2
			certainty_score = 0
			IntRecon = IntRecon.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'Compromised Process': [record["caption"] + ':' + record["name_1"]], 'Inter_process':[record["caption_2"] + ':' + record["name_2"]], 'SYSCALL_2': [record["syscall2"]], 'detection_details': [record["caption_3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		# sensitive read for /etc/passwd, ...
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3) 
	WHERE n1.name = $process_condition AND r2.type =~'READ' AND n3.caption =~ '/etc/.*' AND r2.timestamp >= $timestamp_condition 
	RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n2.caption as caption_2, n3.caption as caption_3, localdatetime(r2.timestamp) as timestamp, count(n3) as count""", timestamp_condition = initial_comp_timestamp, process_condition = compromised_process
	)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration 
			threat_scrore = 2
			certainty_score = 0
			IntRecon = IntRecon.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'Compromised Process': [record["caption"] + ':' + record["name_1"]], 'Inter_process':[record["caption_2"]], 'SYSCALL_2': [record["syscall2"]], 'detection_details': [record["caption_3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)



	
	# Privilege Escalation using sudo
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3) 
	WHERE n2.caption =~ '/usr/bin/sudo' AND r2.type =~ 'EXECUTE' AND n1.name = $process_condition AND r2.timestamp >= $timestamp_condition 
	RETURN n3.host as host, n1.caption as caption,  n2.caption as caption_n2, r2.type as syscall_2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", timestamp_condition = initial_comp_timestamp, process_condition = compromised_process
	)
		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration 	
			threat_scrore = 5
			certainty_score = 10		
			Priv_Escal = Priv_Escal.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL_2': [record["syscall_2"]], 'Target': [record["caption_n3"]], 'Count': [record["count"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

	# Privilege Escalation
	# T1055: Process injection
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..2]->(n2)-[r2:SYSCALL]->(n3) 
	WHERE r2.type =~ 'MODIFY_PROCESS' AND (n1.name = $process_condition OR n2.name = $process_condition) AND r2.timestamp >= $timestamp_condition 	
	RETURN n3.host as host, n1.caption as caption, n2.caption as caption_n2 , r2.type as syscall_2, r2.timestamp as timestamp, count(n3) as count""", timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)
		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration 	
			threat_scrore = 5
			certainty_score = 10		
			Proc_Inj = Proc_Inj.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall_2"]], 'Target': [record["caption_n2"]], 'Count': [record["count"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

	### Privilage escalation using exploits of vulnerable services (e.g., load_helper.ko)

		result = session.run("""MATCH p=(n1)-[r1:SYSCALL]->(n2) 
	WHERE r1.type =~ 'CLONE' and n2.caption =~ '.*:0' and not n1.caption =~ '.*:0' and not n1.caption =~ 'null:null|:'
	SET n2:Compromised
	SET n1:Culprit
	RETURN n1.host as host, n1.caption as caption, n2.caption as caption_n2, r1.type as syscall, r1.timestamp as timestamp, count(n2) as count""")
		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration 	
			threat_scrore = 5
			certainty_score = 10		
			Priv_Escal_2 = Priv_Escal_2.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'Target': [record["caption_n2"]], 'Count': [record["count"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		# Lateral Movement
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3) WHERE n1.name = $process_condition AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND n3.caption STARTS WITH $Trusted_Addresses AND r2.timestamp >= $timestamp_condition 
	RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", timestamp_condition = initial_comp_timestamp, process_condition = compromised_process, Trusted_Addresses = Trusted_IP_Addresses_subnet
	)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			threat_scrore = 5		
			certainty_score = 10
			 			
			Send_Internal = Send_Internal.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		# Cleanup Tracks
		# Clear Logs:
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition OR n2.name = $process_condition) AND r2.type =~'UNLINK' AND n3.caption =~ '.*log.*' AND r2.timestamp >= $timestamp_condition 
	RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", timestamp_condition = initial_comp_timestamp, process_condition = compromised_process, Trusted_Addresses = Trusted_IP_Addresses_subnet
	)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			threat_scrore = 5		
			certainty_score = 10
			 			
			Clear_logs = Clear_logs.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		# Clear artifacts:
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition OR n2.name = $process_condition) AND r2.type =~'UNLINK' AND NOT n3.caption =~ '.*log.*' AND r2.timestamp >= $timestamp_condition 
	RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", timestamp_condition = initial_comp_timestamp, process_condition = compromised_process, Trusted_Addresses = Trusted_IP_Addresses_subnet
	)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			threat_scrore = 5		
			certainty_score = 10
			 			
			Untrusted_File_RM = Untrusted_File_RM.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
			
	bar.finish()

	bar = IncrementalBar('Countdown', max = len(IntRecon))
	for index1, row1 in IntRecon.iterrows():

		bar.next()               		
		result = session.run("""MATCH p=(n1)-[r1:SYSCALL*0..2]->(n2)-[r3:SYSCALL]->(n4) 
	WHERE (n1.name = $process_condition OR n2.name = $process_condition) AND r3.type =~'SENDMSG' AND n4.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND NOT n4.caption STARTS WITH $Trusted_Addresses
	RETURN n1.host as host, n1.caption as caption, n1.name as name_1, n2.caption as caption_2, n4.caption as caption_4, r3.type as syscall_3, r3.timestamp as timestamp, count(n4) as count""", process_condition = row1['Compromised Process'].split(':')[1], Trusted_Addresses = Trusted_IP_Addresses_subnet)
		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration 	
			threat_scrore = 5		
			certainty_score = 10		
			Exfil_prov = Exfil_prov.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'Compromised Process': [record["caption"] + ':' + record["name_1"]], 'Intermediate_process':[record["caption_2"]], 'SYSCALL_3': [record["syscall_3"]], 'exfil': [record["caption_4"]], 'Count': [record["count"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		result = session.run("""MATCH p=(n1)-[r1:SYSCALL*0..2]->(n2)-[r3:SYSCALL]->(n4) 
	WHERE (n1.name = $process_condition OR n2.name = $process_condition) AND r3.type =~'SENDMSG' AND n4.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND n4.caption STARTS WITH $Trusted_Addresses 
	RETURN n1.host as host, n1.caption as caption, n1.name as name_1, n2.caption as caption_2, n4.caption as caption_4, r3.type as syscall_3, r3.timestamp as timestamp, count(n4) as count""", process_condition = row1['Compromised Process'].split(':')[1], Trusted_Addresses = Trusted_IP_Addresses_subnet)
		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration 	
			threat_scrore = 5		
			certainty_score = 10		
			Exfil_internal = Exfil_internal.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'Compromised Process': [record["caption"] + ':' + record["name_1"]], 'Intermediate_process':[record["caption_2"]], 'SYSCALL_3': [record["syscall_3"]], 'exfil': [record["caption_4"]], 'Count': [record["count"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		
	bar.finish()				
driver.close()  # close the driver object


for index1, row1 in IntRecon.iterrows():
	for index2, row2 in Outgoing_Connections.iterrows():
		if (row1['host'] == row2['host'] and ( (row2['detection_timestamp'] + timedelta(minutes=10)) > row1['detection_timestamp'] >= row2['detection_timestamp'])):
			IntRecon.at[index1, 'certainity_Score'] = 10

#Exfiltrate: checking if the source process is one of the compromised processes
#for index1, row1 in Exfil_prov.iterrows():
#	for index2, row2 in Domain_Hijaking.iterrows():
#		if (row1['host'] == row2['host'] and row1['source'] == row2['source']):
#			Exfil_prov.at[index1, 'certainity_Score'] = 10


#for index1, row1 in Exfil.iterrows():
#	for index2, row2 in Proc_Inj.iterrows():
#		if (row1['host'] == row2['host'] and ( (row2['detection_timestamp'] + timedelta(minutes=240)) > row1['detection_timestamp'] >= row2['detection_timestamp'])):
#			Exfil.at[index1, 'certainity_Score'] = 10


#IntRecon = IntRecon[IntRecon.certainity_Score != 0]
#Exfil_prov = Exfil_prov[Exfil_prov.certainity_Score != 0]
#Exfil = Exfil[Exfil.certainity_Score != 0]


#print("Incoming_Connections")
#print(Incoming_Connections.sort_values(by=['detection_timestamp'], ascending=False))


print("Establish Foothold")
#print(FootHold.sort_values(by=['detection_timestamp'], ascending=False))
print(FootHold.groupby(['host','source','SYSCALL','detection_details']).agg({'detection_timestamp':'min'}).sort_values(by=['detection_timestamp'], ascending=True))
#print(FootHold.groupby('source').first())
print("")
print("Internal Recon")
#print(IntRecon.sort_values(by=['detection_timestamp'], ascending=False))
#print("")
print(IntRecon.groupby(['host','Compromised Process','Inter_process','SYSCALL_2','detection_details']).agg(First_Occurence = ('detection_timestamp', 'min'), Last_Occurence=('detection_timestamp', 'max'), Count = ('detection_timestamp', 'nunique')).sort_values(by=['First_Occurence'], ascending=True))
#print("First Occurrence")
#print(IntRecon.groupby(['host','Compromised Process','Inter_process','SYSCALL_2','detection_details']).agg({'detection_timestamp':'min'}).sort_values(by=['detection_timestamp'], ascending=True))
#print("")
#print("Last Occurrence")
#print(IntRecon.groupby(['host','Compromised Process','Inter_process','SYSCALL_2','detection_details']).agg({'detection_timestamp':'max'}).sort_values(by=['detection_timestamp'], ascending=True))


#print("Internal Recon pROV")
#print(IntRecon_prov.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("Privilage Escalation")
print("T1055: Process Injection")
print(Proc_Inj.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("T1068: Exploitation for Privilege Escalation")
print(Priv_Escal.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("T1068: Exploitation for Privilege Escalation-2")
print(Priv_Escal_2.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("")
print("Lateral Movement")
print(Send_Internal.sort_values(by=['detection_timestamp'], ascending=False))


print("")
print("EXFIL PROV")
#print(Exfil_prov.sort_values(by=['detection_timestamp'], ascending=False))
#print(Exfil_prov.groupby(['host','Compromised Process','Intermediate_process','SYSCALL_3','exfil']).agg({'detection_timestamp':[min, max]}).sort_values(by=['detection_timestamp'], ascending=True))

print(Exfil_prov.groupby(['host','Compromised Process','Intermediate_process','SYSCALL_3','exfil']).agg(First_Occurence = ('detection_timestamp', 'min'), Last_Occurence=('detection_timestamp', 'max'), Count = ('detection_timestamp', 'nunique')).sort_values(by=['First_Occurence'], ascending=True))
print("")

print("EXFIL Internal")
print(Exfil_internal.groupby(['host','Compromised Process','Intermediate_process','SYSCALL_3','exfil']).agg(First_Occurence = ('detection_timestamp', 'min'), Last_Occurence=('detection_timestamp', 'max'), Count = ('detection_timestamp', 'nunique')).sort_values(by=['First_Occurence'], ascending=True))
print("")

print("")
print("Cleanup Tracks")
print("Clear logs")
print(Clear_logs.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("Untrusted File RM")
print(Untrusted_File_RM.sort_values(by=['detection_timestamp'], ascending=False))


## send to CSV files

FootHold.to_csv(path_csv+'FootHold.csv',index=True)
IntRecon.to_csv(path_csv+'IntRecon.csv',index=True)
Proc_Inj.to_csv(path_csv+'Priv_escal_Proc_Inj.csv',index=True)
Priv_Escal.to_csv(path_csv+'Priv_Escal.csv',index=True)
Priv_Escal_2.to_csv(path_csv+'Priv_Escal_2.csv',index=True)
Send_Internal.to_csv(path_csv+'Send_Internal.csv',index=True)
Exfil_prov.to_csv(path_csv+'Exfil_prov.csv',index=True)
Exfil_internal.to_csv(path_csv+'Exfil_internal.csv',index=True)
Clear_logs.to_csv(path_csv+'Cleanup_Clear_logs.csv',index=True)
Untrusted_File_RM.to_csv(path_csv+'Cleanup_Untrusted_File_RM.csv',index=True)

file_time_taken = open(path_csv+"Time_taken.txt","w")
elapsed_time = time.time() - start_time
file_time_taken.write("Time taken (Seconds): ")
file_time_taken.write(str(elapsed_time))

print("")
print ("Time taken(seconds):", elapsed_time)

# nunique: is the number of unique dates

#print("Data Exfiltrate")
#print(Exfil.sort_values(by=['detection_timestamp'], ascending=False))


#	    print(row1['c1'], row1['c2'])


#detections = detections.groupby(['host']).mean()

#print("")
#print("Host Detections")
#print((detections.sort_values(by=['host'])))

#print("")
#print(detections.groupby(['host']).agg({'threat_Score':'max', 'certainity_Score':'sum'}))




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

