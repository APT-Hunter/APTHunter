#!/bin/bash

if [[ "$#" -ne 1 ]]; then
    echo "usage: ./neo4j-load-csv.sh data/csv-folder &> out"
    exit 2
fi

if [[ `id -u` -ne 0 ]]; then
    echo "Need to be root"
    exit 1
fi

# Get parameter
root=$1
#IMPORT_DIR="/data/neo4j-csvs"
IMPORT_DIR="/var/lib/neo4j/import"
CYPHER_BIN="cypher-shell"
NEO4J_SERVER="127.0.0.1"
USER="neo4j"
CYPHER_ARGS="-a $NEO4J_SERVER -u neo4j -p neo4jchanged"

# QUERY="\"CREATE CONSTRAINT ON (n:NODE) ASSERT n.uuid IS UNIQUE\""
#eval "${CYPHER_BIN}" "${CYPHER_ARGS}" "${QUERY}"

for ((i=125;i<=125;i++)); 
do 
	for ((k=1;k<=1;k++)); 
	do
		if [ $k -eq 0 ]
		then
			j=""
		fi
		if [ $k -eq 1 ]
		then
			j=".1"
		fi
##### Working on backwards.csv ##############
		INPUT_FILE='/home/x10/APTHUNT/PoC/parsers-master/cdm/json/trace/extracted_events/ta1-trace-2-e5-official-1.bin.'$i'.json'$j'/backwards.csv'
		PROOF_FILE='/home/x10/APTHUNT/PoC/parsers-master/cdm/json/trace/extraction_proof/ta1-trace-2-e5-official-1.bin.'$i'.json'$j
		echo "working on " $INPUT_FILE
		while [ ! -f $PROOF_FILE ];
		do
			echo "Event not yet extracted, check back after 5 minute"
			sleep 300
		done
					
		#rm /data/neo4j-csvs/*.csv
		rm /var/lib/neo4j/import/*.csv

		# Get list of CSV files
		#for file in $root/backward-edge-*; do
		#    if [[ -f $file ]]; then
		#        echo $file
		#
		#	# Copy file
		cp $INPUT_FILE $IMPORT_DIR/backward-edge.csv

		QUERY="\"
		USING PERIODIC COMMIT 500
		LOAD CSV FROM 'file:///backward-edge.csv' as line
		MERGE (n1:SUBJECT {name: (split(line[1], ':'))[0] , caption: split(line[1], (split(line[1], ':'))[0] + ':')[1], host:line[5]})
		MERGE (n2:SUBJECT {name: line[3] , caption: line[4] , host: line[5]})
		WITH line,n1,n2
		CREATE (n1)<-[:SYSCALL {type : line[2], seq: (split(line[0], ':'))[1], timestamp: DateTime({ epochSeconds: toInteger((split(line[0], '.'))[0]), timezone:'AMERICA/NEW_YORK'}) }]-(n2)

		\""

		#WITH line,n1,n3
		#DELETE="MATCH (n) DETACH DELETE n;"
		#eval "${CYPHER_BIN}" "${CYPHER_ARGS}" "${DELETE}"
		eval "${CYPHER_BIN}" "${CYPHER_ARGS}" "${QUERY}"
	
	##### Working on forward.csv ##############
		INPUT_FILE='/home/x10/APTHUNT/PoC/parsers-master/cdm/json/trace/extracted_events/ta1-trace-2-e5-official-1.bin.'$i'.json'$j'/forward.csv'
		PROOF_FILE='/home/x10/APTHUNT/PoC/parsers-master/cdm/json/trace/extraction_proof/ta1-trace-2-e5-official-1.bin.'$i'.json'$j
		echo "working on " $INPUT_FILE
		while [ ! -f $PROOF_FILE ] ;
		do
			echo "Event not yet extracted, check back after 5 minute"
			sleep 300
		done

		cp $INPUT_FILE $IMPORT_DIR/forward-edge.csv

		#MERGE (n1:SUBJECT {name: line[1]})
		#MERGE (n2:RESOURCE {name: line[4], inode: line[3]})


		#MERGE (n1:SUBJECT {name: (split(line[1], ':'))[0] , caption: (split(line[1], ':'))[1]})
		#MERGE (n2:SUBJECT {name: (split(line[4], ':'))[0] , caption: (split(line[4], ':'))[1] })


		QUERY="\"
		USING PERIODIC COMMIT 500
		LOAD CSV FROM 'file:///forward-edge.csv' as line
		MERGE (n1:SUBJECT {name: (split(line[1], ':'))[0] , caption: split(line[1], (split(line[1], ':'))[0] + ':')[1], host:line[5]})
		MERGE (n2:SUBJECT {name: line[3] , caption: line[4] , host: line[5]})
		WITH line,n1,n2
		CREATE (n1)-[:SYSCALL {type : line[2], seq: (split(line[0], ':'))[1], timestamp: DateTime({ epochSeconds: toInteger((split(line[0], '.'))[0]), timezone:'AMERICA/NEW_YORK'}) }]->(n2)
		\""

		#, timestamp: datetime({ epochMillis: (split(line[0], '.'))[0] })
		#WITH line,n1,n3
		#DELETE="MATCH (n) DETACH DELETE n;"
		#eval "${CYPHER_BIN}" "${CYPHER_ARGS}" "${DELETE}"
		eval "${CYPHER_BIN}" "${CYPHER_ARGS}" "${QUERY}"

	#### confirming consuming the events
		echo "Done: ta1-trace-2-e5-official-1.bin."$i".json"
		touch ./consumed_events/ta1-trace-2-e5-official-1.bin.$i.json$j

	done
done 








