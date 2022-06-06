#!/usr/bin/env python3


###################################
######   DARPA Parser  ############
## This script extracts    ########
# attack data events    ###########
###    based on      ##############
# the Events from Darpa     #######
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
import os
import time
import socket

start_time = time.time()
start_time_slice = time.time()
i =1
# Open the existing JSON file for loading into a variable
#Val = input("Enter value: \n")
#DateFrom = 1523028060000000000
DateFrom  = 1557498480000000000	    	    
#DateTo   = 1523031000000000000
DateTo    = 1557498840000000000
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
PrivEscal_process = ["sudo", "su"]
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
PrivEscal_process_list = []

backward_object = "null"
backward_object_list = []
backward_object_path_length = []

process_UUID_list = []
process_name_list = []
process_cmd_list = []
objects_UUID_list = []
objects_name_list = []

process_UUID = []
process_name = []
process_cmd = ""
object_UUID = []
object_name = []

#fileList = [
#'ta1-trace-2-e5-official-1.bin.132.json.1','ta1-trace-2-e5-official-1.bin.132.json',
#'ta1-trace-2-e5-official-1.bin.131.json.1','ta1-trace-2-e5-official-1.bin.131.json',
#'ta1-trace-2-e5-official-1.bin.130.json.1','ta1-trace-2-e5-official-1.bin.130.json',
#'ta1-trace-2-e5-official-1.bin.129.json.1','ta1-trace-2-e5-official-1.bin.129.json']
#fileList = ['ta1-trace-2-e5-official-1.bin.129.json.1']

#prepare file list
fileList = []
#for i in range(126,141):
#	fileList.append('ta1-trace-2-e5-official-1.bin.' + str(i) + '.json')
#	fileList.append('ta1-trace-2-e5-official-1.bin.' + str(i) + '.json' + '.1')

## Log files are ready: from 120 t0 140

fileList = ['ta1-trace-2-e5-official-1.bin.55.json.1']
fileListBase = ['ta1-trace-2-e5-official-1.bin.json', 'ta1-trace-2-e5-official-1.bin.55.json']


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

### clearing Output files
with open('backwards.csv', 'w') as outfile2:
	with open('forward.csv', 'w') as outfile:
		print("Starting processing ...")

### 1- Read Subjects and Objects per log file#######
###################################################
#with open('attack-initial-comp', 'w') as outfile:
for log_file in fileList:
	if(log_file.endswith('.json')):	
		while not os.path.exists('/home/elasticsearch/TC-DAS/ta3-java-consumer/tc-bbn-kafka/' + log_file + '.1'):
			print(log_file + " is not ready yet ..., check back in 1 minute ...")
			time.sleep(60)
	elif(log_file.endswith('.json.1')):	
		while not os.path.exists('/home/elasticsearch/TC-DAS/ta3-java-consumer/tc-bbn-kafka/' + log_file.replace('.json.1','.json.2')):
			print(log_file + " is not ready yet ..., check back in 1 minute ...")
			time.sleep(60)
		
	print ("Working on:", log_file)
	
	start_time_slice = time.time()
	if not os.path.exists('./subjects_and_objects/' + log_file):
    		os.makedirs('./subjects_and_objects/' + log_file)	
	
	if os.path.isfile('./subjects_and_objects/' + log_file + '/' + 'subjects.csv'):
		print ("Subjects and Objects files exists...")
	else:
		print ("Subjects and Objects files not exist - creating the files...")
		with open('./subjects_and_objects/' + log_file + '/' + 'subjects.csv', 'w') as outfile:
			with open('./subjects_and_objects/' + log_file + '/' + 'objects.csv', 'w') as outfile2:
				thewriter = csv.writer(outfile)
				thewriter2 = csv.writer(outfile2)						
				with open('/home/elasticsearch/TC-DAS/ta3-java-consumer/tc-bbn-kafka/' + log_file) as jsondata:		    
					for line in (list(jsondata)):
						cdm_record = json.loads(line.strip())			
						cdm_record_type = cdm_record['datum'].keys()[0]			
						cdm_record_values = cdm_record['datum'][cdm_record_type]	
						#print ("should print object list")
						#print (backward_object_list)
						flag = False
						if (cdm_record_type == "com.bbn.tc.schema.avro.cdm20.Subject"):
							#process_UUID.append(cdm_record_values['uuid'])
							#process_name.append(cdm_record_values['properties']['map']['name'])
							try: 
								process_cmd = (cdm_record_values['cmdLine']['string']).encode('utf-8')	
							except:	
								process_cmd = "" 
							thewriter.writerow([cdm_record_values['uuid'],cdm_record_values['properties']['map']['name'],process_cmd])
							#print process_UUID
							#print process_name
							#raw_input("Press Enter to continue...")		

						elif (cdm_record_type == "com.bbn.tc.schema.avro.cdm20.FileObject"):
							#object_UUID.append(cdm_record_values['uuid'])
							#object_name.append(cdm_record_values['baseObject']['properties']['map']['path'])
							thewriter2.writerow([cdm_record_values['uuid'],cdm_record_values['baseObject']['properties']['map']['path']])	
							#print object_UUID
							#print object_name
							#raw_input("Press Enter to continue...")		

						elif (cdm_record_type == "com.bbn.tc.schema.avro.cdm20.NetFlowObject"):
							#object_UUID.append(cdm_record_values['uuid'])
							#object_name.append(cdm_record_values['remoteAddress']['string'] + ':' + str(cdm_record_values['remotePort']['int']))
							thewriter2.writerow([cdm_record_values['uuid'],cdm_record_values['remoteAddress']['string'] + ':' + str(cdm_record_values['remotePort']['int'])])
							#print object_UUID
							#print object_name
							#raw_input("Press Enter to continue...")		


						else:
							continue
	print("Subject and Objects are ready ...")

#### Read Subjects and Objects Files #####################
### Clear lists	
	process_UUID_list = []
	process_name_list = []
	process_cmd_list = []
	objects_UUID_list = []
	objects_name_list = []

#### 1- Read subjects and objects extracted from the base file: ta1-trace-2-e5-official-1.bin.json
	for log_file_base in fileListBase:	
		print("Read Subject and Objects from: ", log_file_base)	
		with open('./subjects_and_objects/' + log_file_base + '/' + 'subjects.csv') as csv_file1:
			csv_reader1 = csv.reader(csv_file1, delimiter=',')	  		
			for row in csv_reader1:
				process_UUID_list.append(row[0])
				process_name_list.append(row[1])
				# corection to Darpa Dataset
				if (row[2] =="-bash"):	
					process_cmd_list.append(row[1])
				else:
					process_cmd_list.append(row[2])
		
		with open('./subjects_and_objects/' + log_file_base + '/' + 'objects.csv') as csv_file2:
			csv_reader2 = csv.reader(csv_file2, delimiter=',')	  		
			for row in csv_reader2:
				objects_UUID_list.append(row[0])
				objects_name_list.append(row[1])

#### 2- Read subjects and objects extracted from the target file ###
	with open('./subjects_and_objects/' + log_file + '/' + 'subjects.csv') as csv_file1:
		csv_reader1 = csv.reader(csv_file1, delimiter=',')	  		
		for row in csv_reader1:
			process_UUID_list.append(row[0])
			process_name_list.append(row[1])
			# corection to Darpa Dataset
			if (row[2] =="-bash"):	
				process_cmd_list.append(row[1])
			else:
				process_cmd_list.append(row[2])
		
	with open('./subjects_and_objects/' + log_file + '/' + 'objects.csv') as csv_file2:
		csv_reader2 = csv.reader(csv_file2, delimiter=',')	  		
		for row in csv_reader2:
			objects_UUID_list.append(row[0])
			objects_name_list.append(row[1])
###### Search in subjects and objects for interesting objects
	print("Extract list of interesting subjects and objects ...")
### Clear lists
#	object_recon_list = []
#	object_exfil_list = []
#	InitComp_native_process_list = []
#	PrivEscal_process_list = []
#	#Find key recon objects
#	for key_object_recon in Recon:
#		for index, process_name in enumerate(process_name_list):
#			if (process_name.startswith(key_object_recon)):
#				object_recon_list.append(process_UUID_list[index])			
#				#print("recon "+ process_name)
#				#print("recon " + process_UUID_list[index])
#	#find key exfiltrate 
#	for key_object_exf in Exfil:
#		for index, object_name in enumerate(objects_name_list):
#			if (key_object_exf == object_name):
#				object_exfil_list.append(objects_UUID_list[index])
#				#print("Exfil "+ object_name)
#				#print("Exfil " + objects_UUID_list[index])
#
#	#native processes
#	#for process_name in process_name_list:
#	#	if (process_name in InitComp_native_process):
#	#		InitComp_native_process_list.append(process_UUID_list[process_name_list.index(process_name)])
	#		print("Native process "+ process_name)
	#		print("Native process " + process_UUID_list[process_name_list.index(process_name)])

	#Privilage escalation processes
#	for index, process_name in enumerate(process_name_list):
#		if (process_name in PrivEscal_process):
#			PrivEscal_process_list.append(process_UUID_list[index])
			#print("Priv Escal process "+ process_name)
			#print("Priv Escal process " + process_UUID_list[index])

######### Extracte Interesting Events ##########
	if not os.path.exists('./extracted_events/' + log_file):
		os.makedirs('./extracted_events/' + log_file)	
	
	if os.path.isfile('./extracted_events/' + log_file + '/' + 'forward.csv'):
		print ("Events extracted before, overwirite them...")
	else:
		print ("Extracting events ...")
	with open('./extracted_events/' + log_file + '/' + 'backwards.csv', 'w') as outfile2:
		with open('./extracted_events/' + log_file + '/' + 'forward.csv', 'w') as outfile:	
			thewriter = csv.writer(outfile)
			thewriter2 = csv.writer(outfile2)
			# clear lists							
			backward_object = "null"
			backward_object_list = []
			backward_object_path_length = []

			print ("Extracting Events from:", log_file)
			start_time_slice = time.time()
			with open('/home/elasticsearch/TC-DAS/ta3-java-consumer/tc-bbn-kafka/' + log_file) as jsondata:		    
				for line in reversed(list(jsondata)):
					cdm_record = json.loads(line.strip())			
					cdm_record_type = cdm_record['datum'].keys()[0]			
					cdm_record_values = cdm_record['datum'][cdm_record_type]	
					#print ("should print object list")
					#print (backward_object_list)
					flag = False
					if (cdm_record_type == "com.bbn.tc.schema.avro.cdm20.Event"):	
						if (cdm_record_values["timestampNanos"] > DateTo):
							continue
						if (cdm_record_values["timestampNanos"] < DateFrom):
							continue		
						event_type = cdm_record_values['type']					
						
						if  (event_type == "EVENT_CONNECT" or event_type == "EVENT_ACCEPT"):							
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
							#check if col5 is a valid ip address
							#try:
							#	socket.inet_aton(col5.split(':')[0])  
							#except socket.error:
							#	col5 = "null"
							if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
								col6 = 'ta1-trace-2'						
							else:
								col6 = 'null'
							#if (col5 != "null"):
							thewriter.writerow([col1,col2,col3,col4,col5,col6])
						
			print("backwardObjectPathLengths:")
			print(backward_object_path_length)
			elapsed_time = time.time() - start_time_slice						
			print("")
			print ("Time taken (in munites) for processing ", log_file , "is:" , elapsed_time/60)
			open('./extraction_proof/' + log_file, 'a').close()

		


#print("backwardlist_at_end:")
#print(backward_object_list)

#print("backwardObjectPathLengths:")
#print(backward_object_path_length)
print ("Done...")
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









