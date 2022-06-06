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

from datetime import datetime  
from datetime import timedelta
start_time = time.time()

#panada framework - display complete contents of a dataframe
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)

driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", "neo4jchanged"))
threat_scrore = 0
detections= pd.DataFrame({'host':[], 'detection_type': [], 'detection_timestamp': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Incoming_Connections= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Outgoing_Connections= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
IntRecon= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Exfil= pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})

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
# Outgoing Connections
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2) WHERE r.type =~"CONNECT" and n2.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' and not n2.caption =~'128.55.12.51|128.55.12.75|128.55.12.106' and not n1.caption =~ 'sshd|ssh|sendmail|wget|pkg|fetch|netstat' and not n2.caption =~ '127.0.0.1.*' and not n1.host =~ 'ta1-cadets-3'
RETURN n1.host as host, n1.caption as caption, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration
		threat_scrore = 5		
		certainty_score = 10
		 			
		Outgoing_Connections = Outgoing_Connections.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

### Incoming Coneections
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2) WHERE r.type =~"ACCEPT" and n2.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' and not n2.caption =~'128.55.12.51|128.55.12.75|128.55.12.106' and not n1.caption =~ 'sshd|ssh|sendmail|wget' and not n2.caption =~ '127.0.0.1.*' and not n1.host =~ 'ta1-cadets-3'
RETURN n1.host as host, n1.caption as caption, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration 	
		Incoming_Connections = Incoming_Connections.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)


	# Drakon APT - Recon rule 
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2) 
WHERE (n2.caption =~ 'whoami|hostname|ps.*' or n1.caption =~ 'netstat') and not n1.host =~ 'ta1-cadets-3'
RETURN n1.host as host, n1.caption as caption, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration 
		threat_scrore = 2
		certainty_score = 0
		IntRecon = IntRecon.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)


######################## Exfil Stage ###################
# Drakon APT - Data Exfiltrate rule - 
	
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2)
WHERE n2.caption =~ '.*/etc/passwd|.*/etc/shadow|/.*etc/hosts|.*/etc/pwd.db' and not n1.caption =~ 'alpine|whoami|top|sendmail|mail.local|ssh|sshd|ls|wget|bash|ps|scp|pkg|id|netstat' and not n1.host =~ 'ta1-cadets-3'
RETURN n1.host as host, n1.caption as caption, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration 	
		threat_scrore = 5		
		certainty_score = 0		
		Exfil = Exfil.append(pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)		


driver.close()  # close the driver object

# Checking init comp rule (with high certinity) match (no previous incoming connections on the same socket)
for index1, row1 in Outgoing_Connections.iterrows():
	for index2, row2 in Incoming_Connections.iterrows():
		if (row1['detection_details'] == row2['detection_details']):
			Outgoing_Connections.at[index1, 'certainity_Score'] = 0

for index1, row1 in IntRecon.iterrows():
	for index2, row2 in Outgoing_Connections.iterrows():
		if (row1['host'] == row2['host'] and ( (row2['detection_timestamp'] + timedelta(minutes=10)) > row1['detection_timestamp'] >= row2['detection_timestamp'])):
			IntRecon.at[index1, 'certainity_Score'] = 10

for index1, row1 in Exfil.iterrows():
	for index2, row2 in Outgoing_Connections.iterrows():
		if (row1['host'] == row2['host'] and ( (row2['detection_timestamp'] + timedelta(minutes=10)) > row1['detection_timestamp'] >= row2['detection_timestamp'])):
			Exfil.at[index1, 'certainity_Score'] = 10

#drop false detections
Outgoing_Connections = Outgoing_Connections[Outgoing_Connections.certainity_Score != 0]
IntRecon = IntRecon[IntRecon.certainity_Score != 0]
Exfil = Exfil[Exfil.certainity_Score != 0]


#print("Incoming_Connections")
#print(Incoming_Connections.sort_values(by=['detection_timestamp'], ascending=False))

print("Incoming_Connections")
print(Incoming_Connections.sort_values(by=['detection_timestamp'], ascending=False))

print("Outgoing_Connections (Initial Compromise)")
print(Outgoing_Connections.sort_values(by=['detection_timestamp'], ascending=False))


print("Internal Recon")
print(IntRecon.sort_values(by=['detection_timestamp'], ascending=False))


print("Data Exfiltrate")
print(Exfil.sort_values(by=['detection_timestamp'], ascending=False))


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

