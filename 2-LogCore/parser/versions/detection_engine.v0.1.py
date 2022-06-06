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

start_time = time.time()

#panada framework - display complete contents of a dataframe
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', -1)

driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", "neo4jchanged"))
threat_scrore = 0
detections= pd.DataFrame({'host':[], 'detection_type': [], 'detection_timestamp': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})


#result = session.run("""MATCH p=(n1)<-[r:SYSCALL*2..]-(n2)<-[r2:SYSCALL]-(n3) 
#WHERE n1.caption = 'sshd' AND (n2.caption = 'sshd' OR n2.caption = 'bash') AND n3.caption contains 'scp'
#MATCH p2=(n1)-[r3:SYSCALL]-(n5) WHERE not r3.type ="CONNECT" AND not r3.type ="ACCEPT"
#RETURN n1.host as host, n1.caption as caption, r2.type as syscall, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""")

with driver.session() as session:
	# Drakon APT - Data Exfiltrate rule - paths that are common on the source subject, destination subject, r2.syscall, and timestamp are grouped and counted 
	# WLed scp that contains /tmp/ paths
	result = session.run("""MATCH p=(n1)<-[r:SYSCALL*1..]-(n2)<-[r2:SYSCALL]-(n3) 
WHERE n1.caption = 'sshd' AND (n2.caption = 'sshd' OR n2.caption = 'bash') AND n3.caption =~ 'scp.*' AND not n3.caption =~ '.*/tmp/.*'
RETURN n1.host as host, n1.caption as caption, r2.type as syscall, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration 	
		threat_scrore = 5
		if (record["count"]<=5):
			certainty_score = record["count"] 
		else: 
			certainty_score = 5		
		detections = detections.append(pd.DataFrame({'host':[record["host"]], 'detection_type': ["Data exfiltration"], 'detection_timestamp': [record["timestamp"]],'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)		




	# Drakon APT - Recon rule - paths that are common on the source subject, destination subject, r2.syscall, and timestamp are grouped and counted
	result = session.run("""MATCH p=(n1)<-[r:SYSCALL*2..]-(n2)<-[r2:SYSCALL]-(n3) 
WHERE n1.caption = 'sshd' AND (n2.caption = 'sshd' OR n2.caption = 'bash') AND n3.caption =~ 'whoami|hostname|ps.*'
RETURN n1.host as host, n1.caption as caption, r2.type as syscall, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration 	
		threat_scrore = 3
		if (record["count"]<=5):
			certainty_score = record["count"] 
		else: 
			certainty_score = 5		
		detections = detections.append(pd.DataFrame({'host':[record["host"]], 'detection_type': ["Recon"], 'detection_timestamp': [record["timestamp"]],'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

driver.close()  # close the driver object

print("Detections")
print(detections.sort_values(by=['detection_timestamp'], ascending=False))

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

