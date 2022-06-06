#!/usr/bin/env python3


###################################
######   DARPA Parser  ############
## This script extracts    ########
# Darpa Ubuntu events     #########
###      filling in missing #######
# subjects and obejcts      #######
## Author: Moustafa Mahmoud #######
## Concordia University ###########
###################################
##### Version Details    ##########
#####     V0.1          ###########
#                             #####
#                              ####
#                              ####
#                              ####
#   			       ####
# 		   	       ####
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

backward_object = "null"
backward_object_list = []
backward_object_path_length = []
predicateObjectUUIDLlist = []
predicateObjectPathLlist = []
process_UUID = []
process_name = []
objects_UUID = []
objects_name = []
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


with open('subjects.csv') as csv_file1:
	csv_reader1 = csv.reader(csv_file1, delimiter=',')	  		
	for row in csv_reader1:
		process_UUID.append(row[0])
		process_name.append(row[1])
		
with open('objects.csv') as csv_file2:
	csv_reader2 = csv.reader(csv_file2, delimiter=',')	  		
	for row in csv_reader2:
		objects_UUID.append(row[0])
		objects_name.append(row[1])

print len(process_UUID)
print len(objects_UUID)
print("search now")
print("44BF5749-4E6F-3D41-5D8E-904D4186DD62:" + process_name[process_UUID.index("44BF5749-4E6F-3D41-5D8E-904D4186DD62")])
for row in process_UUID:
	if (process_UUID.index(row) == len(process_UUID) -1):
		print ("Process UUID:" + row + "  " + "Process name" + process_name[process_UUID.index(row)])


for row in objects_UUID:
	if (objects_UUID.index(row) == len(objects_UUID) -1):	
		print ("Object UUID:" + row + "  " + "object name" + objects_name[objects_UUID.index(row)])


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









