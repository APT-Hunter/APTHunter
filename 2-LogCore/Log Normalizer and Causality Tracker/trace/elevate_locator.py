#!/usr/bin/env python3


###################################
######   DARPA Parser  ############
## This script extracts    ########
# attack data events    ###########
###    in stages     ##############
# based on the ground truth #######
## Author: Moustafa Mahmoud #######
## Concordia University ###########
###################################
##### Version Details    ##########
#####     V0.4          ###########
# stage locator - multistage  #####
# multi process - multi branch ####
#  Execute-FORK-ACCEPT-CONNECT ####
# Init Comp: collect ACCEPT    ####
#   and CONNECT Events         ####
# Don't check backward object  ####
###################################
# Import json module
import json
import csv

import time

start_time = time.time()
start_time_slice = time.time()
i =1
# Open the existing JSON file for loading into a variable
#Val = input("Enter value: \n")
#DateFrom = 1523028060000000000
DateFrom  = 1558015140000000000
#DateTo   = 1523031000000000000
DateTo    = 1558015860000000000
# here we start with object and do backward tracking: 
#whoami object: 
#In: ta1-cadets-1-e5-official-2.bin.100.json.1
#key_object = "8FA40B6F-BAF5-AF51-B5BA-4F9291AFCEAC"
#Output files: whoami_backwards.csv' and whoami_forward.csv'
#key_object_cmd = "whoami"
Recon = ["whoami", "hostname", "ps"]
Exfil = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/pwd.db"]
InitComp = [""]
InitComp_native_process = ["sshd", "ssh", "sendmail", "wget"]
key_object = "null" 
path_len = 0
#working_on_target = False
flag = False
#scp -r /etc/passwd admin@128.55.12.51:./docs/
#In ta1-cadets-1-e5-official-2.bin.116.json
#Output files: scp_etc_passwd_forward.csv and scp_etc_passwd_backwards.csv
#key_object = "B8FFD54B-E634-C156-B4E6-8D03E6C1084F"

object_recon_list = []
object_exfil_list = []
InitComp_native_process_list = []
backward_object = "null"
backward_object_list = []
backward_object_path_length = []
predicateObjectUUIDLlist = []
predicateObjectPathLlist = []
process_UUID_list = []
process_name_list = []
objects_UUID_list = []
objects_name_list = []
fileList = ['ta1-trace-2-e5-official-1.bin.129.json.1']

#fileList = ['ta1-cadets-1-e5-official-2.bin.120.json.1', 'ta1-cadets-1-e5-official-2.bin.120.json',
#'ta1-cadets-1-e5-official-2.bin.119.json.1', 'ta1-cadets-1-e5-official-2.bin.119.json',
#'ta1-cadets-1-e5-official-2.bin.118.json.1', 'ta1-cadets-1-e5-official-2.bin.118.json',
#'ta1-cadets-1-e5-official-2.bin.117.json.1', 'ta1-cadets-1-e5-official-2.bin.117.json',
#'ta1-cadets-1-e5-official-2.bin.116.json.1', 'ta1-cadets-1-e5-official-2.bin.116.json',
#'ta1-cadets-1-e5-official-2.bin.115.json.1', 'ta1-cadets-1-e5-official-2.bin.115.json',
#'ta1-cadets-1-e5-official-2.bin.114.json.1', 'ta1-cadets-1-e5-official-2.bin.114.json',
#'ta1-cadets-1-e5-official-2.bin.113.json.1', 'ta1-cadets-1-e5-official-2.bin.113.json',
#'ta1-cadets-1-e5-official-2.bin.112.json.1', 'ta1-cadets-1-e5-official-2.bin.112.json',
#'ta1-cadets-1-e5-official-2.bin.111.json.1', 'ta1-cadets-1-e5-official-2.bin.111.json',
#'ta1-cadets-1-e5-official-2.bin.110.json.1', 'ta1-cadets-1-e5-official-2.bin.110.json',
#'ta1-cadets-1-e5-official-2.bin.109.json.1', 'ta1-cadets-1-e5-official-2.bin.109.json',
#'ta1-cadets-1-e5-official-2.bin.108.json.1', 'ta1-cadets-1-e5-official-2.bin.108.json',
#'ta1-cadets-1-e5-official-2.bin.107.json.1', 'ta1-cadets-1-e5-official-2.bin.107.json',
#'ta1-cadets-1-e5-official-2.bin.106.json.1', 'ta1-cadets-1-e5-official-2.bin.106.json',
#'ta1-cadets-1-e5-official-2.bin.105.json.1', 'ta1-cadets-1-e5-official-2.bin.105.json',
#'ta1-cadets-1-e5-official-2.bin.104.json.1', 'ta1-cadets-1-e5-official-2.bin.104.json',
#'ta1-cadets-1-e5-official-2.bin.103.json.1', 'ta1-cadets-1-e5-official-2.bin.103.json']




previousEvent = "null"
previousSeq = 0

## read Subjects and Objects
with open('subjects.csv') as csv_file1:
	csv_reader1 = csv.reader(csv_file1, delimiter=',')	  		
	for row in csv_reader1:
		process_UUID_list.append(row[0])
		process_name_list.append(row[1])
		
with open('objects.csv') as csv_file2:
	csv_reader2 = csv.reader(csv_file2, delimiter=',')	  		
	for row in csv_reader2:
		objects_UUID_list.append(row[0])
		objects_name_list.append(row[1])

#Find key recon objects
for key_object_recon in Recon:
	for index, process_name in enumerate(process_name_list):
		if (process_name.startswith(key_object_recon)):
			object_recon_list.append(process_UUID_list[index])			
			print("recon "+ process_name)
			print("recon " + process_UUID_list[index])
#find key exgiltrate 
for key_object_exf in Exfil:
	for index, object_name in enumerate(objects_name_list):
		if (key_object_exf == object_name):
			object_exfil_list.append(objects_UUID_list[index])
			print("Exfil "+ object_name)
			print("Exfil " + objects_UUID_list[index])

#native processes
#for process_name in process_name_list:
#	if (process_name in InitComp_native_process):
#		InitComp_native_process_list.append(process_UUID_list[process_name_list.index(process_name)])
#		print("Native process "+ process_name)
#		print("Native process " + process_UUID_list[process_name_list.index(process_name)])


#with open('attack-initial-comp', 'w') as outfile:
with open('backwards.csv', 'w') as outfile2:
	with open('elevate.csv', 'w') as outfile:
		thewriter = csv.writer(outfile)
		thewriter2 = csv.writer(outfile2)				
		predicateObjectPath_index=0
		for log_file in fileList:
			print ("Working on:", log_file)
			start_time_slice = time.time()
			with open('./logs/' + log_file) as jsondata:		    
			    for line in reversed(list(jsondata)):
				cdm_record = json.loads(line.strip())			
				cdm_record_type = cdm_record['datum'].keys()[0]			
				cdm_record_values = cdm_record['datum'][cdm_record_type]	
				#print ("should print object list")
				#print (backward_object_list)
				flag = False
				if (cdm_record_type == "com.bbn.tc.schema.avro.cdm20.Event"):			
					event_type = cdm_record_values['type']					
					if not (event_type == "EVENT_CHANGE_PRINCIPAL"):
						continue
									
					
					if  (event_type == "EVENT_CHANGE_PRINCIPAL"):						
						timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
						col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
						#omit the path from predicateObjectPath, to make the subject executable same as in other EVENTS (no path there). 
						try: 

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"
						#col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']
						#col2 = cdm_record_values['properties']['map']['exec']  
						### JUST SPECAIL FOR EVENT_EXECUTE ### THE SUBJECT BECOMES THE OBJECT AFTER EXECUTING IT
						#col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['cmdLine']
						col3 = event_type[6:]
						col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
						try: 	
							col5 = process_name_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]	
						except :
							col5 ='null'
						if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
							col6 = 'ta1-trace-2'						
						else:
							col6 = 'null'
					
						#col5 = cdm_record_values['predicateObjectPath']['string'].split('/')[-1]
						thewriter.writerow([col1,col2,col3,col4,col5,col6])
						#try: 
						#	backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']) 
						#except ValueError :
						#	backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
						#	backward_object_path_length.append(0)
							
					#elif  (event_type == "EVENT_OPEN" and (predicate_object == key_object or predicate_object == backward_object or subject_UUID == backward_object)):
					#	timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
					#	col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])					
					#	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
					#	col3 = event_type[6:]
					#	col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
					#	col5 = cdm_record_values['predicateObjectPath']['string']
					#	if (cdm_record['hostId'] == 'A8370E61-8ECA-ACD4-5394-57E645AE3379'):
					#		col6 = 'ta1-trace-2'						
					#	else:
					#		col6 = 'null'
					#	thewriter.writerow([col1,col2,col3,col4,col5,col6])
					#	#backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
					#	#backward_object_path_length.append(0)
					#	predicateObjectUUIDLlist.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
					#	predicateObjectPathLlist.append(cdm_record_values['properties']['map']['exec'])
												
					elif  (event_type == "EVENT_READ" and (predicate_object == key_object or predicate_object == backward_object or subject_UUID == backward_object)):
						timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
						col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])					
						try: 

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"
						col3 = event_type[6:]
						col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
						try:
							col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col5 = "null"
						if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
							col6 = 'ta1-trace-2'						
						else:
							col6 = 'null'

						thewriter.writerow([col1,col2,col3,col4,col5,col6])
						try: 
							backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']) 
						except ValueError :
							backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							backward_object_path_length.append(0)
						
	
					elif  (event_type == "EVENT_FORK" and (predicate_object == key_object or predicate_object == backward_object or subject_UUID == backward_object)):
						# EVENT_FORK format: timestampNanos:sequence,subject_UUID:exec,type,predicateObject_UUID,predicateObjectPath
						timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
						col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
						try: 

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"
						col3 = event_type[6:]
						col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
						try:
							col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col5 = "null"
						if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
							col6 = 'ta1-trace-2'						
						else:
							col6 = 'null'

									
						thewriter.writerow([col1,col2,col3,col4,col5,col6])	
						try: 
							backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']) 
						except ValueError :
							backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							backward_object_path_length.append(0)					
					elif  (event_type == "EVENT_WRITE" and (predicate_object == key_object or predicate_object == backward_object or subject_UUID == backward_object)):
						timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
						col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])					
						try: 

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"
						col3 = event_type[6:]
						col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
						try:
							col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col5 = "null"
						if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
							col6 = 'ta1-trace-2'						
						else:
							col6 = 'null'

						thewriter2.writerow([col1,col2,col3,col4,col5,col6])
						try: 
							backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']) 
						except ValueError :
							backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							backward_object_path_length.append(0)	
					
					#elif  ((event_type == "EVENT_CLOSE" or event_type == "EVENT_EXIT") and (predicate_object == key_object or predicate_object == backward_object)):
					#	# EVENT_CLOSE format: timestampNanos:sequence,subject_UUID:exec,type,predicateObject_UUID,predicateObjectPath
					#	timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
					#	col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
					#	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
					#	#col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']
					#	col3 = event_type[6:]
					#	col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
					#	#print(predicateObjectPathList)
					#	# predicateObjectPath is missing in the READ and WRITE events, so fill in them from OPEN events
					#	col5 = 'null'
					#	for predicateObject_UUID in predicateObjectUUIDLlist:
					#		if (predicateObject_UUID == col4):
					#			col5 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']  + ':' + predicateObjectPathLlist[predicateObjectUUIDLlist.index(predicateObject_UUID)]
					#			break							
					#	thewriter2.writerow([col1,col2,col3,col4,col5])	
					#	backward_object = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']
					elif  (event_type == "EVENT_ACCEPT"):							
						timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
						col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])					
						try: 

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"
						col3 = event_type[6:]
						col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
						try:
							col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col5 = "null"
						if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
							col6 = 'ta1-trace-2'						
						else:
							col6 = 'null'

						thewriter.writerow([col1,col2,col3,col4,col5,col6])
						try: 
							backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']) 
						except ValueError :
							backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							backward_object_path_length.append(0)
					elif  (event_type == "EVENT_CONNECT"):							
						timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
						col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])					
						try: 

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"
						col3 = event_type[6:]
						col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
						try:
							col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col5 = "null"
						if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
							col6 = 'ta1-trace-2'						
						else:
							col6 = 'null'

						thewriter.writerow([col1,col2,col3,col4,col5,col6])
						try: 
							backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']) 
						except ValueError :
							backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							backward_object_path_length.append(0)
					elif  (event_type == "EVENT_MODIFY_PROCESS" and (predicate_object == key_object or predicate_object == backward_object or subject_UUID == backward_object)):
						timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
						col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])					
						try: 

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"
						col3 = event_type[6:]
						col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
						try:
							col5 = process_name_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							col5 = "null"
						if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
							col6 = 'ta1-trace-2'						
						else:
							col6 = 'null'

						thewriter.writerow([col1,col2,col3,col4,col5,col6])
						try: 
							backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']) 
						except ValueError :
							backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							backward_object_path_length.append(0)
															
					#elif  (event_type == "EVENT_SENDTO" and (predicate_object == key_object or predicate_object == backward_object)):
					#	timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
					#	col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])					
					#	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
					#	col3 = event_type[6:]
					#	col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
					#	#print(predicateObjectPathList)
					#	# predicateObjectPath is missing in the READ and WRITE events, so fill in them from OPEN events
					#	col5 = 'null'				
					#	for predicateObject_UUID in predicateObjectUUIDLlist:
					#		if (predicateObject_UUID == col4):
					#			col5 = predicateObjectPathLlist[predicateObjectUUIDLlist.index(predicateObject_UUID)]
					#			break					
					#	if (cdm_record['hostId'] == 'A3702F4C-5A0C-11E9-B8B9-D4AE52C1DBD3'):
					#		col6 = 'ta1-cadets-1'
					#	elif (cdm_record['hostId'] == '3A541941-5B04-11E9-B2DB-D4AE52C1DBD3'):
					#		col6 = 'ta1-cadets-2'
					#	elif (cdm_record['hostId'] == 'CB02303B-654E-11E9-A80C-6C2B597E484C'):
					#		col6 = 'ta1-cadets-3'
					#	else:
					#		col6 = 'null'
					#	thewriter.writerow([col1,col2,col3,col4,col5,col6])
					#	backward_object = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']
					#	path_len +=1
			print("backwardObjectPathLengths:")
			print(backward_object_path_length)
			elapsed_time = time.time() - start_time_slice						
			print("")
			print ("Time taken (in munites) for processing ", log_file , "is:" , elapsed_time/60)
			


print("backwardlist_at_end:")
print(backward_object_list)

print("backwardObjectPathLengths:")
print(backward_object_path_length)

elapsed_time = time.time() - start_time
print("")
print ("Total Time taken (min):", elapsed_time/60)



# now filling in the missing predicateObjectPath
#print ("Whoami analysis is ready. Starting filling Null values")
#outfile.close()
#outfile2.close()


#with open('whoami_forward.csv') as csv_file1:
#	csv_reader1 = csv.reader(csv_file1, delimiter=',')	
#	with open('whoami_forward_final.csv', 'w') as outfile_final:
#		thewriter_final = csv.writer(outfile_final)
 #  		
#		for row in csv_reader1:
#			if row[4] <> "null":
#				thewriter_final.writerow([row[0], row[1], row[2], row[3], row[4]])
#				print ("not null")				
#			else :
#				for predicateObject_UUID in predicateObjectUUIDLlist:
#					print ("Comparison predicateObject_UUID:", predicateObject_UUID, "and row 3:" , row[3])
#					if (predicateObject_UUID == row[3]):
#						col5 = row[3] + ':' + predicateObjectPathLlist[predicateObjectUUIDLlist.index(predicateObject_UUID)]
#						print ("match found in case of null", col5)
#						break
#					else:
#						col5 = row[3] + ':' + "null"
#				thewriter_final.writerow([row[0], row[1], row[2], row[3], col5])		
			




				#if (col5 == "null" and (event_type == "EVENT_CLOSE" or event_type == "EVENT_EXIT" or event_type == "EVENT_WRITE" or event_type == "EVENT_FORK" or event_type == "EVENT_READ")):
				#	with open('ta1-cadets-1-e5-official-2.bin.100.json.1') as jsondata1:
				#	    for line1 in jsondata1:
				#		cdm_record1 = json.loads(line1.strip())
				#		cdm_record_type1 = cdm_record1['datum'].keys()[0]
				#		cdm_record_values1 = cdm_record1['datum'][cdm_record_type1]						
				#		if (cdm_record_type1 == "com.bbn.tc.schema.avro.cdm20.Event" and cdm_record_values1['type'] == "EVENT_OPEN"):
				#			if (cdm_record_values1['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'] == col4):
				#				col5 = cdm_record_values1['predicateObjectPath']['string']
				#	thewriter.writerow([col1,col2,col3,col4,col5])		
#			if (cdm_record_values["timestampNanos"] >= DateFrom and cdm_record_values["timestampNanos"] <= DateTo):
#				#   print("Record ", i,"is", cdm_record_values)
#				#    i = i + 1;
#				json.dump(cdm_record_values, outfile)
#				outfile.write(",\n")
#				print("Record ", i,"is", cdm_record_values)
#				i =i +1
#
#print ("total number of records:", i)
#print ("Attack stage extracted successfuly")
# Search data based on key and value using filter and list method
#print(list(filter(lambda x:x["timestampNanos"]=="1522949718807923603",data)))

# Input the key value that you want to search
#Val = input("Enter value: \n")

# load the json data
#event = json.loads(eventData)
# Search the key value using 'in' operator
#if cdm_record["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["timestampNanos"] == Val:
    # Print the success message and the value of the key
#    print("%s is found in JSON data" %Val)
#    print("The record of", Val,"is", cdm_record)
#else:
    # Print the message if the value does not exist
#    print("%s is not found in JSON data" %Val)









