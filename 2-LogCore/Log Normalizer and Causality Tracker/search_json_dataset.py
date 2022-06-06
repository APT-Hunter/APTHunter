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

i =1
# Open the existing JSON file for loading into a variable
#Val = input("Enter value: \n")
DateFrom = 1523028060000000000
DateTo   = 1523031000000000000
with open('attack-initial-comp.json', 'w') as outfile:
	with open('ta1-cadets-e3-official.json.2') as jsondata:
	    for line in jsondata:
		cdm_record = json.loads(line.strip())
		cdm_record_type = cdm_record['datum'].keys()[0]
		if  (cdm_record_type == "com.bbn.tc.schema.avro.cdm18.Event"):
			cdm_record_values = cdm_record['datum'][cdm_record_type]
			if (cdm_record_values["timestampNanos"] >= DateFrom and cdm_record_values["timestampNanos"] <= DateTo):
				#   print("Record ", i,"is", cdm_record_values)
				#    i = i + 1;
				json.dump(cdm_record_values, outfile)
				outfile.write(",\n")
				print("Record ", i,"is", cdm_record_values)
				i =i +1

print ("total number of records:", i)
print ("Attack stage extracted successfuly")
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









