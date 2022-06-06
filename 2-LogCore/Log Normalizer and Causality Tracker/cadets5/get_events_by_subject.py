#!/usr/bin/env python3


###################################
######   DARPA Parser  ############
## This script extracts    #######
# attack data events    ##########
###    in stages     #############
# based on the ground truth ######
## Author: Moustafa Mahmoud ######
## Concordia University #########
#################################

# Import json module
import json
import csv

i =1
# Open the existing JSON file for loading into a variable
#Val = input("Enter value: \n")
#DateFrom = 1523028060000000000
DateFrom  = 1558015140000000000
#DateTo   = 1523031000000000000
DateTo    = 1558015860000000000
# UUID list for nginx subject
UUIDList = ["B3BE35BB-7042-11E9-A28B-D4AE52C1DBD3", "4215BB8B-77E4-11E9-B41B-D4AE52C1DBD3", "00F2FDB9-7043-11E9-B41B-D4AE52C1DBD3", "444547A2-77E4-11E9-B41B-D4AE52C1DBD3", "4449CB39-77E4-11E9-B41B-D4AE52C1DBD3", "444EC430-77E4-11E9-B41B-D4AE52C1DBD3", "444E016E-77E4-11E9-B41B-D4AE52C1DBD3", "444EDBB8-77E4-11E9-B41B-D4AE52C1DBD3", 
"1DBC0417-77E5-11E9-A28B-D4AE52C1DBD3", "B3BE01B1-7042-11E9-A28B-D4AE52C1DBD3", "B3BE28D2-7042-11E9-A28B-D4AE52C1DBD3", "1E249536-77E5-11E9-A28B-D4AE52C1DBD3", "1E29175C-77E5-11E9-A28B-D4AE52C1DBD3", "1E2DCD0D-77E5-11E9-A28B-D4AE52C1DBD3", "1E2E24A6-77E5-11E9-A28B-D4AE52C1DBD3", "1E2E3C6D-77E5-11E9-A28B-D4AE52C1DBD3"]

with open('nginx.json', 'w') as outfile:
#with open('subject_ids_nginx.csv', 'w') as outfile:
	#thewriter = csv.writer(outfile)
	#subjectUUIDList = []
	#subjectUUIDList_index=0
	with open('ta1-cadets-1-e5-official-2.bin.100.json.1') as jsondata:
	    for line in jsondata:
		cdm_record = json.loads(line.strip())
		cdm_record_type = cdm_record['datum'].keys()[0]
		cdm_record_values = cdm_record['datum'][cdm_record_type]
		if (cdm_record_type == "com.bbn.tc.schema.avro.cdm20.Event" and cdm_record_values['type'] <> "EVENT_MPROTECT" and cdm_record_values['type'] <> "EVENT_FCNTL" and cdm_record_values['type'] <> "EVENT_LOGIN" and cdm_record_values['type'] <> "EVENT_ADD_OBJECT_ATTRIBUTE" and cdm_record_values['type'] <> "EVENT_OTHER" and  cdm_record_values['type'] <> "EVENT_SIGNAL"):
			#print cdm_record
			#json.dump(cdm_record, outfile)
			#outfile.write("\n")
			#event_type = cdm_record_values['type']			
			for UUID in UUIDList:
				#print cdm_record_values['type']
				if (UUID == cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] or UUID == cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']):
					print cdm_record
					json.dump(cdm_record, outfile)
					outfile.write("\n")
					
#			if  (event_type == "EVENT_OPEN" or event_type == "EVENT_READ" or event_type == "EVENT_EXECUTE" or event_type == "EVENT_ACCEPT" or event_type == "EVENT_WRITE"):
#				if (cdm_record_values['properties']['map']['exec'] == "nginx"):
#					print cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']
				



				#for subjectUUIDList_UUID in subjectUUIDList:
				#	if (predicateObject_UUID == col2):						
				#		break
				#	else:
				#		continue					
				#	subjectUUIDList.append(col2)

#			if  (event_type == "EVENT_OPEN"):
#				# EVENT_OPEN format: timestampNanos:sequence,subject_UUID:exec,type,predicateObject_UUID,predicateObjectPath
#				timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
#				col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
#				col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
#				col3 = event_type[6:]
#				col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
#				col5 = cdm_record_values['predicateObjectPath']['string']
#				thewriter.writerow([col1,col2,col3,col4,col5])
#				predicateObjectUUIDLlist.append(col4)
#				predicateObjectPathLlist.append(col5)
#	#			print(cdm_record_values)
	#			print(predicateObjectPathList)
#			elif  (event_type == "EVENT_READ"):
#				# EVENT_READ format: timestampNanos:sequence,subject_UUID:exec,type,predicateObject_UUID,predicateObjectPath
#				timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
#				col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
#				col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
#				col3 = event_type[6:]
#				col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
#				#print(predicateObjectPathList)
#				# predicateObjectPath is missing in the READ and WRITE events, so fill in them from OPEN events
#				col5 = 'null'				
#				for predicateObject_UUID in predicateObjectUUIDLlist:
#					if (predicateObject_UUID == col4):
#						col5 = predicateObjectPathLlist[predicateObjectUUIDLlist.index(predicateObject_UUID)]
#						break
#				thewriter.writerow([col1,col2,col3,col4,col5])

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









