#!/usr/bin/env python3


###################################
######   Neo4j Parser  ############
########      &&	   ########
# attack stages extraction ########
###    in stages     ##############
### based on stage rules    #######
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
import pytz

from progress.bar import IncrementalBar
from ipaddress import ip_address, IPv4Address


start_time = time.time()

#panada framework - display complete contents of a dataframe
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)

driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", "neo4jchanged"))
threat_scrore = 0
initial_comp_timestamp_list = []
compromised_process_list = []
detections= pd.DataFrame({'host':[], 'detection_type': [], 'detection_timestamp': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Untrusted_Read= pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Untrusted_Read_Unique = pd.DataFrame({})
Make_file_Exec = pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Intermediate_process': [],'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Make_Mem_Exec = pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Intermediate_process': [],'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Untrusted_File_Exec= pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Initial_Comp= pd.DataFrame({'host':[], 'source': [], 'direct_source': []})
Shell_Exec= pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
CnC= pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Sudo_Exec= pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Switch_SU= pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Sensitive_Read= pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Intermediate_process': [],'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Sensitive_Read_Unique= pd.DataFrame({})
Sensitive_Command= pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Intermediate_process': [],'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Sensitive_Command_Unique= pd.DataFrame({})
Send_Internal= pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Sensitive_Leak= pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Destroy_System = pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Intermediate_process': [],'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Clear_logs = pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Intermediate_process': [],'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Sensitive_Temp_RM = pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Intermediate_process': [],'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Untrusted_File_RM = pd.DataFrame({'host':[], 'stage':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Intermediate_process': [],'detection_details': [], 'threat_Score': [], 'certainity_Score': []})


#Threat_scores = pd.DataFrame({'host':[], 'source': [], 'threat_Score': []})

timestamp_from = datetime.datetime.fromtimestamp(1557804480,  pytz.timezone("AMERICA/NEW_YORK"))
timestamp_to = datetime.datetime.fromtimestamp(1557804480+3600, pytz.timezone("AMERICA/NEW_YORK"))
print (timestamp_from)
print(timestamp_to)

# contains all internal and tursted Ips  (HOLMES)
Trusted_IP_Addresses_subnet = "128.55.12"

#path_csv = "./results/theia_eng3_scenario3/1/"
#path_csv = "./results/cadets_eng3_scenario7/8/"
path_csv = "./results/trace_eng3_scenario1/1/"

if not os.path.exists(path_csv):
	os.makedirs(path_csv)


with driver.session() as session:

### Untrusted_Read
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2) WHERE r.type =~"READ|CONNECT"
RETURN n1.host as host, n1.caption as caption, n1.name as name_n1, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp""")
	for record in result:
		#rel = record["host"]
		#rel = record
		#print(rel)
		#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
		# data exfiltration
		certainty_score = 0
		Untrusted_Read = Untrusted_Read.append(pd.DataFrame({'host':[record["host"]], 'stage':["1"], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_n1"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)



driver.close()  # close the driver object

# Check Untrusted_Read: the object: IP is not trusted
IPAddress =""
bar = IncrementalBar('Countdown', max = len(Untrusted_Read.index))	
for index1, row1 in Untrusted_Read.iterrows():
	bar.next()
	try:
		IPAddress = row1['detection_details'].split(':')[0]
		if type(ip_address(IPAddress)) is IPv4Address:
				#print ("IPv4")
				# check if the IP is not trusted
				if (not IPAddress.startswith(Trusted_IP_Addresses_subnet) and not IPAddress == "0.0.0.0" and not IPAddress == "127.0.0.1"):
					# Initial comp: Untrusted Read (S,P) found
                                        # this condition is to filter out TPs/FPs to calculate the Threat score then
					#if not (IPAddress == "35.106.122.76" or IPAddress == "69.155.209.87"):
					Untrusted_Read.at[index1, 'certainity_Score'] = 10
					# S: L (2) , W: 11/10=1.1 (initial comp)
					Untrusted_Read.at[index1, 'threat_Score'] = 2**1.1
					Initial_Comp = Initial_Comp.append(pd.DataFrame({'host':[record["host"]], 'source': [row1['source']], 'direct_source': [row1['source']]}),ignore_index=True)
		else:
			#print ("IPv6")
			pass
	except ValueError:
		#print ("Not a valid IP address")
		continue
bar.finish()


#drop false Untrusted_Read
Untrusted_Read = Untrusted_Read[Untrusted_Read.certainity_Score != 0]

print("Initial compromise...")
print("Untrusted_Read")
print(Untrusted_Read.sort_values(by=['detection_timestamp'], ascending=False))


#Prepare the uniquie list of Untrusted Read prcoesses
#Untrusted_Read_Unique = Untrusted_Read.groupby(['source']).agg({'threat_Score':'sum'})
Untrusted_Read_Unique = Untrusted_Read.drop_duplicates(subset=['source'])

#print (len(Untrusted_Read.index))
#_continue = input('Continue? (Y/n)\n')
#if (_continue == "Y"):
#        pass
#else:
#        quit()


with driver.session() as session:
	
	bar = IncrementalBar('Countdown', max = len(Untrusted_Read_Unique.index))	
	for index1, row1 in Untrusted_Read_Unique.iterrows():		
		bar.next()		
                # Initial comp		
		#Make_file_Exec(P, F)		
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*0..3]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition OR n2.name = $process_condition) AND r2.type =~'MODIFY_FILE_ATTRIBUTES:chmod'                
                RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n2.caption as caption_n2, n2.name as name_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 11/10=1.1 (Int Comp)
			threat_scrore = 8**1.1
			certainty_score = 10

			Make_file_Exec = Make_file_Exec.append(pd.DataFrame({'host':[record["host"]], 'stage':["1"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'Intermediate_process': [record["caption_n2"] + ':' + record["name_n2"]],'detection_details': [record["syscall2"] + "  " + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
			# add P to the initial comp processes
			if(not row1['source'].split(':')[1] == record["name_n2"]):
				Initial_Comp = Initial_Comp.append(pd.DataFrame({'host':[record["host"]], 'source': [row1['source']], 'direct_source': [record["caption_n2"] + ':' + record["name_n2"]]}),ignore_index=True)

		#Make_Mem_Exec(P,M)		
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*0..3]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition OR n2.name = $process_condition) AND r2.type =~'MPROTECT' AND n3.caption =~ '.*PROT_EXEC.*'               
                RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n2.caption as caption_n2, n2.name as name_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: M (6) , W: 11/10=1.1 (Int Comp)
			threat_scrore = 6**1.1
			certainty_score = 10

			Make_Mem_Exec = Make_Mem_Exec.append(pd.DataFrame({'host':[record["host"]], 'stage':["1"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'Intermediate_process': [record["caption_n2"] + ':' + record["name_n2"]],'detection_details': [record["syscall2"] + "  " + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
			# add P to the initial comp processes
			if(not row1['source'].split(':')[1] == record["name_n2"]):
				Initial_Comp = Initial_Comp.append(pd.DataFrame({'host':[record["host"]], 'source': [row1['source']], 'direct_source': [record["caption_n2"] + ':' + record["name_n2"]]}),ignore_index=True)

                
		# Untrusted_file_Exec(F,P)
		#1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'EXECUTE'
		RETURN n2.host as host, n2.caption as caption, n2.name as name_2, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: C (10) , W: 11/10=1.1 (initial comp)
			threat_scrore = 10**1.1
			certainty_score = 10

			Untrusted_File_Exec = Untrusted_File_Exec.append(pd.DataFrame({'host':[record["host"]], 'stage':["1"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
			
		#2)
		result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n22)-[r11:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'EXECUTE'
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, n2.caption as caption_n2, n2.name as name_n2, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: C (10) , W: 11/10=1.1 (initial comp)
			threat_scrore = 10**1.1
			certainty_score = 10

			Untrusted_File_Exec = Untrusted_File_Exec.append(pd.DataFrame({'host':[record["host"]], 'stage':["1"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
			# add P to the initial comp processes			
			Initial_Comp = Initial_Comp.append(pd.DataFrame({'host':[record["host"]], 'source': [row1['source']], 'direct_source': [record["caption_n2"] + ':' + record["name_n2"]]}),ignore_index=True)

			
		#3)
		result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2)-[r11:SYSCALL]->(n22)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition) AND r2.type =~'EXECUTE'
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, n2.caption as caption_n2, n2.name as name_n2, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: C (10) , W: 11/10=1.1 (initial comp)
			threat_scrore = 10**1.1
			certainty_score = 10

			Untrusted_File_Exec = Untrusted_File_Exec.append(pd.DataFrame({'host':[record["host"]], 'stage':["1"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
			# add P to the initial comp processes			
			Initial_Comp = Initial_Comp.append(pd.DataFrame({'host':[record["host"]], 'source': [row1['source']], 'direct_source': [record["caption_n2"] + ':' + record["name_n2"]]}),ignore_index=True)

	bar.finish()
	print("Initial Compromise - Done ...")

	#Prepare the uniquie list of Initial Compromise prcoesses
	Initial_Comp = Initial_Comp.drop_duplicates()
	
	#Initial_Comp_Unique = Initial_Comp.groupby(['source','direct_source']).agg({'threat_Score':'sum'})
	
	bar = IncrementalBar('Countdown', max = len(Initial_Comp.index))	
	for index1, row1 in Initial_Comp.iterrows():		
		bar.next()
	
                # Establish FootHold
		#Shell_Exec(F,P)
                # 1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'EXECUTE' AND n3.caption =~ '/bin/.*'
		RETURN n2.host as host, n2.caption as caption, n2.name as name_2, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: M (6) , W: 12/10=1.2 (FootHold)
			threat_scrore = 6**1.2
			certainty_score = 10

			Shell_Exec = Shell_Exec.append(pd.DataFrame({'host':[record["host"]], 'stage':["2"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		
		# 2)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'EXECUTE' AND n3.caption =~ '/bin/.*'
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: M (6) , W: 12/10=1.2 (FootHold)
			threat_scrore = 6**1.2
			certainty_score = 10

			Shell_Exec = Shell_Exec.append(pd.DataFrame({'host':[record["host"]], 'stage':["2"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		# 3)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition) AND r2.type =~'EXECUTE' AND n3.caption =~ '/bin/.*'
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: M (6) , W: 12/10=1.2 (FootHold)
			threat_scrore = 6**1.2
			certainty_score = 10

			Shell_Exec = Shell_Exec.append(pd.DataFrame({'host':[record["host"]], 'stage':["2"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
			
		
		#CnC(P, S):
		#1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND NOT n3.caption STARTS WITH $Trusted_Addresses
		RETURN n2.host as host, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1], Trusted_Addresses=Trusted_IP_Addresses_subnet
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: L (2) , W: 12/10=1.2 (FootHold)
			threat_scrore = 2**1.2
			certainty_score = 10

			CnC = CnC.append(pd.DataFrame({'host':[record["host"]], 'stage':["2"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#2)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND NOT n3.caption STARTS WITH $Trusted_Addresses
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1], Trusted_Addresses=Trusted_IP_Addresses_subnet
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: L (2) , W: 12/10=1.2 (FootHold)
			threat_scrore = 2**1.2
			certainty_score = 10

			CnC = CnC.append(pd.DataFrame({'host':[record["host"]], 'stage':["2"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
			
		#3)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition) AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND NOT n3.caption STARTS WITH $Trusted_Addresses
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1], Trusted_Addresses=Trusted_IP_Addresses_subnet
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: L (2) , W: 12/10=1.2 (FootHold)
			threat_scrore = 2**1.2
			certainty_score = 10

			CnC = CnC.append(pd.DataFrame({'host':[record["host"]], 'stage':["2"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
                #Priv. Escalation
		#Sudo Exec(F, P):
		#1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'EXECUTE' AND n3.caption =~ '/sbin/.*|.*sudo'
		RETURN n2.host as host, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 13/10=1.3 (Priv. Escalation)
			threat_scrore = 8**1.3
			certainty_score = 10

			Sudo_Exec = Sudo_Exec.append(pd.DataFrame({'host':[record["host"]], 'stage':["3"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		#2)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'EXECUTE' AND n3.caption =~ '/sbin/.*|.*sudo'
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 13/10=1.3 (Priv. Escalation)
			threat_scrore = 8**1.3
			certainty_score = 10

			Sudo_Exec = Sudo_Exec.append(pd.DataFrame({'host':[record["host"]], 'stage':["3"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		#3)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition) AND r2.type =~'EXECUTE' AND n3.caption =~ '/sbin/.*|.*sudo'
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 13/10=1.3 (Priv. Escalation)
			threat_scrore = 8**1.3
			certainty_score = 10

			Sudo_Exec = Sudo_Exec.append(pd.DataFrame({'host':[record["host"]], 'stage':["3"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		
		#Switch_SU(U, P)
		# this one is incomplete. It needs to check if the user.id is one of the super users.
		#1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'CHANGE_PRINCIPAL:setuid'
		RETURN n2.host as host, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 13/10=1.3 (Priv. Escalation)
			threat_scrore = 8**1.3
			certainty_score = 10

			Switch_SU = Switch_SU.append(pd.DataFrame({'host':[record["host"]], 'stage':["3"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#2)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'CHANGE_PRINCIPAL:setuid'
		RETURN n1.host as host, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 13/10=1.3 (Priv. Escalation)
			threat_scrore = 8**1.3
			certainty_score = 10

			Switch_SU = Switch_SU.append(pd.DataFrame({'host':[record["host"]], 'stage':["3"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#3)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'CHANGE_PRINCIPAL:setuid'
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 13/10=1.3 (Priv. Escalation)
			threat_scrore = 8**1.3
			certainty_score = 10

			Switch_SU = Switch_SU.append(pd.DataFrame({'host':[record["host"]], 'stage':["3"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		
	bar.finish()


	
	#Thread 2
	bar = IncrementalBar('Countdown', max = len(Initial_Comp.index))
	for index1, row1 in Initial_Comp.iterrows():		
		bar.next()                
		#Int. Recon
		#Sensitive Read(F, P)		
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*0..2]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition OR n2.name = $process_condition) AND r2.type =~'READ'
                AND n3.caption =~ '/etc/.*'
                RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n2.caption as caption_n2, n2.name as name_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: M (6) , W: 14/10=1.4 (Int. Recon)
			threat_scrore = 6**1.4
			certainty_score = 10

			Sensitive_Read = Sensitive_Read.append(pd.DataFrame({'host':[record["host"]], 'stage':["4"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'Intermediate_process': [record["caption_n2"] + ':' + record["name_n2"]],'detection_details': [record["syscall2"] + "  " + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

					
		#Sensitive Command(P; P'):  (i.e., P forked P')
		#1)			
		result = session.run("""MATCH p=(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE n22.name = $process_condition AND r2.type =~'FORK|CLONE' AND n3.caption =~ '/sbin/.*|/bin/.*|/usr/bin/.*|/usr/local/.*|/usr/sbin/.*'
                RETURN n3.host as host, r2.type as syscall2, n2.caption as caption_n2, n2.name as name_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)
                # whoami|hostname|ps.*|netstat: should appear from that query
		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 14/10=1.4 (Int. Recon)
			threat_scrore = 8**1.4
			certainty_score = 10			
			Sensitive_Command = Sensitive_Command.append(pd.DataFrame({'host':[record["host"]], 'stage':["4"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'Intermediate_process': [record["caption_n2"] + ':' + record["name_n2"]],'detection_details': [record["syscall2"] + "  " + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#2)
		result = session.run("""MATCH p=(n11)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE n11.name = $process_condition AND r2.type =~'FORK|CLONE' AND n3.caption =~ '/sbin/.*|/bin/.*|/usr/bin/.*|/usr/local/.*|/usr/sbin/.*'                
                RETURN n3.host as host,  r2.type as syscall2, n2.caption as caption_n2, n2.name as name_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 14/10=1.4 (Int. Recon)
			threat_scrore = 8**1.4
			certainty_score = 10			
			Sensitive_Command = Sensitive_Command.append(pd.DataFrame({'host':[record["host"]], 'stage':["4"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'Intermediate_process': [record["caption_n2"] + ':' + record["name_n2"]],'detection_details': [record["syscall2"] + "  " + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#3)
		result = session.run("""MATCH p=(n1)-[r111:SYSCALL]->(n11)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE n1.name = $process_condition AND r2.type =~'FORK|CLONE' AND n3.caption =~ '/sbin/.*|/bin/.*|/usr/bin/.*|/usr/local/.*|/usr/sbin/.*'                
                RETURN n1.host as host,  r2.type as syscall2, n2.caption as caption_n2, n2.name as name_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 14/10=1.4 (Int. Recon)
			threat_scrore = 8**1.4
			certainty_score = 10			
			Sensitive_Command = Sensitive_Command.append(pd.DataFrame({'host':[record["host"]], 'stage':["4"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'Intermediate_process': [record["caption_n2"] + ':' + record["name_n2"]],'detection_details': [record["syscall2"] + "  " + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
			
			
                # Lateral Movement
                # Send Internal(P, S):
                #1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND n3.caption STARTS WITH $Trusted_Addresses
		RETURN n2.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1], Trusted_Addresses = Trusted_IP_Addresses_subnet
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: M (6) , W: 15/10=1.5 (Lateral Movement)
			threat_scrore = 6**1.5
			certainty_score = 10
			Send_Internal = Send_Internal.append(pd.DataFrame({'host':[record["host"]], 'stage':["5"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#2)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND n3.caption STARTS WITH $Trusted_Addresses
		RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1], Trusted_Addresses = Trusted_IP_Addresses_subnet
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: M (6) , W: 15/10=1.5 (Lateral Movement)
			threat_scrore = 6**1.5
			certainty_score = 10
			Send_Internal = Send_Internal.append(pd.DataFrame({'host':[record["host"]], 'stage':["5"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#3)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition) AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND n3.caption STARTS WITH $Trusted_Addresses
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1], Trusted_Addresses = Trusted_IP_Addresses_subnet
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: M (6) , W: 15/10=1.5 (Lateral Movement)
			threat_scrore = 6**1.5
			certainty_score = 10
			Send_Internal = Send_Internal.append(pd.DataFrame({'host':[record["host"]], 'stage':["5"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		
		#Complete Mission
		#Destroy System(F, P):
		#1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'WRITE|UNLINK'
                AND n3.caption =~ '/etc/.*|/proc/.*|/boot/.*'
                RETURN n2.host as host, r2.type as syscall2, n2.caption as caption_n2, n2.name as name_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)
                # .*/etc/passwd|.*/etc/shadow|.*/etc/hosts|.*/etc/pwd.db: will be reterived by the query
		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: c (10) , W: 16/10=1.6 (Complete Mission)
			threat_scrore = 10**1.6
			certainty_score = 10
			Destroy_System = Destroy_System.append(pd.DataFrame({'host':[record["host"]], 'stage':["6"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'Intermediate_process': [record["caption_n2"] + ':' + record["name_n2"]],'detection_details': [record["syscall2"] + "  " + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#2)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'WRITE|UNLINK'
                AND n3.caption =~ '/etc/.*|/proc/.*|/boot/.*'
                RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n2.name as name_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: c (10) , W: 16/10=1.6 (Complete Mission)
			threat_scrore = 10**1.6
			certainty_score = 10
			Destroy_System = Destroy_System.append(pd.DataFrame({'host':[record["host"]], 'stage':["6"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'Intermediate_process': [record["caption_n2"] + ':' + record["name_n2"]],'detection_details': [record["syscall2"] + "  " + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#3)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition) AND r2.type =~'WRITE|UNLINK'
                AND n3.caption =~ '/etc/.*|/proc/.*|/boot/.*'
                RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n2.caption as caption_n2, n2.name as name_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: c (10) , W: 16/10=1.6 (Complete Mission)
			threat_scrore = 10**1.6
			certainty_score = 10
			Destroy_System = Destroy_System.append(pd.DataFrame({'host':[record["host"]], 'stage':["6"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'Intermediate_process': [record["caption_n2"] + ':' + record["name_n2"]],'detection_details': [record["syscall2"] + "  " + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

                # Cleanup Tracks
		# Clear Logs(P, F):
		#1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'UNLINK'
                AND n3.caption =~ '.*log.*'
                RETURN n2.host as host, r2.type as syscall2, n2.caption as caption_n2, n2.name as name_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: h (8) , W: 17/10=1.7 ( Cleanup Tracks)
			threat_scrore = 8**1.7
			certainty_score = 10
			Clear_logs = Clear_logs.append(pd.DataFrame({'host':[record["host"]], 'stage':["7"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'Intermediate_process': [record["caption_n2"] + ':' + record["name_n2"]],'detection_details': [record["syscall2"] + "  " + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#2)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'UNLINK'
                AND n3.caption =~ '.*log.*'
                RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n2.name as name_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: h (8) , W: 17/10=1.7 ( Cleanup Tracks)
			threat_scrore = 8**1.7
			certainty_score = 10
			Clear_logs = Clear_logs.append(pd.DataFrame({'host':[record["host"]], 'stage':["7"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'Intermediate_process': [record["caption_n2"] + ':' + record["name_n2"]],'detection_details': [record["syscall2"] + "  " + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#3)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition) AND r2.type =~'UNLINK'
                AND n3.caption =~ '.*log.*'
                RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n2.caption as caption_n2, n2.name as name_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: h (8) , W: 17/10=1.7 ( Cleanup Tracks)
			threat_scrore = 8**1.7
			certainty_score = 10
			Clear_logs = Clear_logs.append(pd.DataFrame({'host':[record["host"]], 'stage':["7"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'Intermediate_process': [record["caption_n2"] + ':' + record["name_n2"]],'detection_details': [record["syscall2"] + "  " + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		#Cleanup Tracks
		#Untrusted File RM(P, F):
		# any files other than log files. 
		#1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'UNLINK' AND NOT n3.caption =~ '.*log.*'
		RETURN n2.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: m (6) , W: 17/10=1.7 (Complete Mission)
			threat_scrore = 6**1.7
			certainty_score = 10
			Untrusted_File_RM = Untrusted_File_RM.append(pd.DataFrame({'host':[record["host"]], 'stage':["7"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#2)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'UNLINK' AND NOT n3.caption =~ '.*log.*'
		RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: m (6) , W: 17/10=1.7 (Complete Mission)
			threat_scrore = 6**1.7
			certainty_score = 10
			Untrusted_File_RM = Untrusted_File_RM.append(pd.DataFrame({'host':[record["host"]], 'stage':["7"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		#3)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition) AND r2.type =~'UNLINK' AND NOT n3.caption =~ '.*log.*'
		RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['direct_source'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: m (6) , W: 17/10=1.7 (Complete Mission)
			threat_scrore = 6**1.7
			certainty_score = 10
			Untrusted_File_RM = Untrusted_File_RM.append(pd.DataFrame({'host':[record["host"]], 'stage':["7"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)


	bar.finish()
	################ End of Thread 2 ################

	#Prepare the uniquie list of Sensitive_Read prcoesses
	print(Sensitive_Read)
	Sensitive_Read_Unique = Sensitive_Read.drop_duplicates(subset=['source', 'Intermediate_process'])
		
	bar = IncrementalBar('Countdown', max = len(Sensitive_Read_Unique.index))

	for index1, row1 in Sensitive_Read_Unique.iterrows():
		bar.next()
                #Complete Mission
		#Sensitive Leak(P, S) part1:
		#1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND NOT n3.caption STARTS WITH $Trusted_Addresses
		RETURN n2.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['Intermediate_process'].split(':')[1], Trusted_Addresses=Trusted_IP_Addresses_subnet)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 16/10=1.6 (Complete Mission)
			threat_scrore = 8**1.6
			certainty_score = 10
			Sensitive_Leak = Sensitive_Leak.append(pd.DataFrame({'host':[record["host"]], 'stage':["6"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		#2)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND NOT n3.caption STARTS WITH $Trusted_Addresses
		RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['Intermediate_process'].split(':')[1], Trusted_Addresses=Trusted_IP_Addresses_subnet)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 16/10=1.6 (Complete Mission)
			threat_scrore = 8**1.6
			certainty_score = 10
			Sensitive_Leak = Sensitive_Leak.append(pd.DataFrame({'host':[record["host"]], 'stage':["6"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#3)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition) AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND NOT n3.caption STARTS WITH $Trusted_Addresses
		RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['Intermediate_process'].split(':')[1], Trusted_Addresses=Trusted_IP_Addresses_subnet)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 16/10=1.6 (Complete Mission)
			threat_scrore = 8**1.6
			certainty_score = 10
			Sensitive_Leak = Sensitive_Leak.append(pd.DataFrame({'host':[record["host"]], 'stage':["6"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		#Cleanup Tracks
		#Sensitive Temp RM(P, F)::
		#1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'UNLINK'
		RETURN n2.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['Intermediate_process'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: m (6) , W: 17/10=1.7 (Complete Mission)
			threat_scrore = 6**1.7
			certainty_score = 10
			Sensitive_Temp_RM = Sensitive_Temp_RM.append(pd.DataFrame({'host':[record["host"]], 'stage':["7"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#2)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'UNLINK'
		RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['Intermediate_process'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: m (6) , W: 17/10=1.7 (Complete Mission)
			threat_scrore = 6**1.7
			certainty_score = 10
			Sensitive_Temp_RM = Sensitive_Temp_RM.append(pd.DataFrame({'host':[record["host"]], 'stage':["7"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		#3)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition) AND r2.type =~'UNLINK'
		RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['Intermediate_process'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: m (6) , W: 17/10=1.7 (Complete Mission)
			threat_scrore = 6**1.7
			certainty_score = 10
			Sensitive_Temp_RM = Sensitive_Temp_RM.append(pd.DataFrame({'host':[record["host"]], 'stage':["7"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

	
	bar.finish()

	#Prepare the uniquie list of Sensitive_Command prcoesses
	Sensitive_Command_Unique = Sensitive_Command.drop_duplicates(subset=['source', 'Intermediate_process'])
		
	bar = IncrementalBar('Countdown', max = len(Sensitive_Command_Unique.index))
	for index1, row1 in Sensitive_Command_Unique.iterrows():
		bar.next()
                #Complete Mission
		#Sensitive Leak(P, S) part2:
		#1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND NOT n3.caption STARTS WITH $Trusted_Addresses
		RETURN n2.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['Intermediate_process'].split(':')[1], Trusted_Addresses=Trusted_IP_Addresses_subnet
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 16/10=1.6 (Complete Mission)
			threat_scrore = 8**1.6
			certainty_score = 10
			Sensitive_Leak = Sensitive_Leak.append(pd.DataFrame({'host':[record["host"]], 'stage':["6"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#2)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND NOT n3.caption STARTS WITH $Trusted_Addresses
		RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['Intermediate_process'].split(':')[1], Trusted_Addresses=Trusted_IP_Addresses_subnet
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 16/10=1.6 (Complete Mission)
			threat_scrore = 8**1.6
			certainty_score = 10
			Sensitive_Leak = Sensitive_Leak.append(pd.DataFrame({'host':[record["host"]], 'stage':["6"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		#3)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition) AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND NOT n3.caption STARTS WITH $Trusted_Addresses
		RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['Intermediate_process'].split(':')[1], Trusted_Addresses=Trusted_IP_Addresses_subnet
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: H (8) , W: 16/10=1.6 (Complete Mission)
			threat_scrore = 8**1.6
			certainty_score = 10
			Sensitive_Leak = Sensitive_Leak.append(pd.DataFrame({'host':[record["host"]], 'stage':["6"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		#Cleanup Tracks
		#Sensitive Temp RM(P, F)::
		#1)
		result = session.run("""MATCH p=(n2)-[r2:SYSCALL]->(n3) WHERE (n2.name = $process_condition) AND r2.type =~'UNLINK'
		RETURN n2.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['Intermediate_process'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: m (6) , W: 17/10=1.7 (Complete Mission)
			threat_scrore = 6**1.7
			certainty_score = 10
			Sensitive_Temp_RM = Sensitive_Temp_RM.append(pd.DataFrame({'host':[record["host"]], 'stage':["7"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)
		#2)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n22.name = $process_condition) AND r2.type =~'UNLINK'
		RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['Intermediate_process'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: m (6) , W: 17/10=1.7 (Complete Mission)
			threat_scrore = 6**1.7
			certainty_score = 10
			Sensitive_Temp_RM = Sensitive_Temp_RM.append(pd.DataFrame({'host':[record["host"]], 'stage':["7"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		#3)
		result = session.run("""MATCH p=(n1)-[r11:SYSCALL]->(n22)-[r:SYSCALL]->(n2)-[r2:SYSCALL]->(n3) WHERE (n1.name = $process_condition) AND r2.type =~'UNLINK'
		RETURN n1.host as host, r2.type as syscall2, n2.caption as caption_n2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""", process_condition = row1['Intermediate_process'].split(':')[1]
		)

		for record in result:
			#rel = record["host"]
			#rel = record
			#print(rel)
			#detections ["host", "detection_type", "detection_details", threat_Score, certainity_Score]
			# data exfiltration
			# S: m (6) , W: 17/10=1.7 (Complete Mission)
			threat_scrore = 6**1.7
			certainty_score = 10
			Sensitive_Temp_RM = Sensitive_Temp_RM.append(pd.DataFrame({'host':[record["host"]], 'stage':["7"], 'detection_timestamp': [record["timestamp"]], 'source': [row1['source']], 'SYSCALL': ['...'], 'detection_details': [record["caption_n2"] + ' SENDMSG ' + record["caption_n3"]], 'threat_Score': [threat_scrore], 'certainity_Score': [certainty_score]}),ignore_index=True)

		
	bar.finish()

driver.close()  # close the driver object


print("Initial compromise...")
print("Untrusted_Read")
print(Untrusted_Read.sort_values(by=['detection_timestamp'], ascending=False))
print("")


#send to CSV files
Untrusted_Read.to_csv(path_csv+'Untrusted_Read.csv',index=False)

print("Make_file_Exec")
print(Make_file_Exec.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Make_file_Exec.to_csv(path_csv+'Make_file_Exec.csv',index=False)

print("Make_Mem_Exec")
print(Make_Mem_Exec.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Make_Mem_Exec.to_csv(path_csv+'Make_Mem_Exec.csv',index=False)


print("Untrusted_File_Exec")
print(Untrusted_File_Exec.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Untrusted_File_Exec.to_csv(path_csv+'Untrusted_File_Exec.csv',index=False)

print("")
print("Establish_Foothold...")
print("")
print("Shell_Exec")
print(Shell_Exec.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Shell_Exec.to_csv(path_csv+'Shell_Exec.csv',index=False)

print("CnC")
print(CnC.sort_values(by=['detection_timestamp'], ascending=False))
print("")
CnC.to_csv(path_csv+'CnC.csv',index=False)
print("")
print("Privilage Escalation...")
print("")
print("Sudo_Exec")
print(Sudo_Exec.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Sudo_Exec.to_csv(path_csv+'Sudo_Exec.csv',index=False)
print("Switch_SU")
print(Switch_SU.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Switch_SU.to_csv(path_csv+'Switch_SU.csv',index=False)
print("")
print("Internal Recon ...")
print("")
print("Sensitive_Read")
print(Sensitive_Read.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Sensitive_Read.to_csv(path_csv+'Sensitive_Read.csv',index=False)
print("Sensitive_Command")
print(Sensitive_Command.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Sensitive_Command.to_csv(path_csv+'Sensitive_Command.csv',index=False)
print("")
print("Lateral Movement ...")
print("")
print("Send_Internal")
print(Send_Internal.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Send_Internal.to_csv(path_csv+'Send_Internal.csv',index=False)

print("")
print("Complete Mission ...")
print("")
print("Sensitive_Leak")
print(Sensitive_Leak.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Sensitive_Leak.to_csv(path_csv+'Sensitive_Leak.csv',index=False)
print("Destroy_System")
print(Destroy_System.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Destroy_System.to_csv(path_csv+'Destroy_System.csv',index=False)

print("")
print("Cleanup Tracks ...")
print("Clear_logs")
print(Clear_logs.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Clear_logs.to_csv(path_csv+'Clear_logs.csv',index=False)

print("Untrusted_File_RM")
print(Untrusted_File_RM.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Untrusted_File_RM.to_csv(path_csv+'Untrusted_File_RM.csv',index=False)

print("Sensitive_Temp_RM")
print(Sensitive_Temp_RM.sort_values(by=['detection_timestamp'], ascending=False))
print("")
Sensitive_Temp_RM.to_csv(path_csv+'Sensitive_Temp_RM.csv',index=False)


# Calculating Threat Score for TP 
print("")

try:
        Threat_scores = Untrusted_Read.groupby(['host','stage','source']).agg({'threat_Score':'sum'})
except:
        pass


try:
	Threat_scores = pd.concat([Threat_scores,Untrusted_File_Exec.groupby(['host','stage','source']).agg({'threat_Score':'sum'})]) 
except:
	pass

try:
	Threat_scores = pd.concat([Threat_scores,Make_Mem_Exec.groupby(['host','stage','source']).agg({'threat_Score':'sum'})]) 
except:
	pass

try:
	Threat_scores = pd.concat([Threat_scores,Make_file_Exec.groupby(['host','stage','source']).agg({'threat_Score':'sum'})]) 
except:
	pass


try:
	Threat_scores = pd.concat([Threat_scores,Shell_Exec.groupby(['host','stage','source']).agg({'threat_Score':'sum'})])	
except:
        pass

try:
	Threat_scores = pd.concat([Threat_scores,CnC.groupby(['host','stage','source']).agg({'threat_Score':'sum'})])        
except:
        pass

try:
	Threat_scores = pd.concat([Threat_scores,Sudo_Exec.groupby(['host','stage','source']).agg({'threat_Score':'sum'})])        
except:
        pass

try:
	Threat_scores = pd.concat([Threat_scores,Switch_SU.groupby(['host','stage','source']).agg({'threat_Score':'sum'})])        
except:
        pass

try:
	Threat_scores = pd.concat([Threat_scores,Sensitive_Read.groupby(['host','stage','source']).agg({'threat_Score':'sum'})])        
except:
        pass

try:
	Threat_scores = pd.concat([Threat_scores,Sensitive_Command.groupby(['host','stage','source']).agg({'threat_Score':'sum'})])        
except:
        pass

try:
	Threat_scores = pd.concat([Threat_scores,Send_Internal.groupby(['host','stage','source']).agg({'threat_Score':'sum'})])        
except:
        pass
                          
try:
	Threat_scores = pd.concat([Threat_scores,Sensitive_Leak.groupby(['host','stage','source']).agg({'threat_Score':'sum'})])        
except:
        pass

try:
	Threat_scores = pd.concat([Threat_scores,Destroy_System.groupby(['host','stage','source']).agg({'threat_Score':'sum'})])        
except:
       pass

try:
	Threat_scores = pd.concat([Threat_scores,Clear_logs.groupby(['host','stage','source']).agg({'threat_Score':'sum'})])        
except:
       pass
try:
	Threat_scores = pd.concat([Threat_scores,Sensitive_Temp_RM.groupby(['host','stage','source']).agg({'threat_Score':'sum'})])        
except:
       pass
try:
	Threat_scores = pd.concat([Threat_scores,Untrusted_File_RM.groupby(['host','stage','source']).agg({'threat_Score':'sum'})])        
except:
       pass


print("")
print ("Threat scoress per stage per path")
print(Threat_scores.groupby(['host','stage','source']).agg({'threat_Score':'sum'}))

(Threat_scores.groupby(['host','stage','source']).agg({'threat_Score':'sum'})).to_csv(path_csv+'Threat_scores_stage_source.csv',index=True)


print("")
print("Total Threat Scores per path...")
print(Threat_scores.groupby(['host','source']).agg({'threat_Score':'sum'}))

(Threat_scores.groupby(['host','source']).agg({'threat_Score':'sum'})).to_csv(path_csv+'Threat_scores_source.csv',index=True)

print("")
print("Total Threat Score per Host...")
print(Threat_scores.groupby(['host']).agg({'threat_Score':'sum'}))



file_time_taken = open(path_csv+"Time_taken.txt","w")
elapsed_time = time.time() - start_time
file_time_taken.write("Time taken (Seconds): ")
file_time_taken.write(str(elapsed_time))

print("")
print ("Time taken(seconds):", elapsed_time)



print("Running APTHUNT")
os.system('python3 /home/x10/APTHUNT/reducer/log-reducer-master/parser/detection_engine.py')

print("APTHUNT Done ...")

