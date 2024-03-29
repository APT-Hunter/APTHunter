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

INPUT_FILE='backwards.csv'


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
CREATE (n1)-[:SYSCALL {type : line[2], seq: (split(line[0], ':'))[1], timestamp: DateTime({ epochSeconds: toInteger((split(line[0], '.'))[0]), timezone:'AMERICA/NEW_YORK'}) }]->(n2)

\""

#WITH line,n1,n3
#DELETE="MATCH (n) DETACH DELETE n;"
#eval "${CYPHER_BIN}" "${CYPHER_ARGS}" "${DELETE}"
eval "${CYPHER_BIN}" "${CYPHER_ARGS}" "${QUERY}"


INPUT_FILE='forward.csv'

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
CREATE (n1)<-[:SYSCALL {type : line[2], seq: (split(line[0], ':'))[1], timestamp: DateTime({ epochSeconds: toInteger((split(line[0], '.'))[0]), timezone:'AMERICA/NEW_YORK'}) }]-(n2)
\""

#, timestamp: datetime({ epochMillis: (split(line[0], '.'))[0] })
#WITH line,n1,n3
#DELETE="MATCH (n) DETACH DELETE n;"
#eval "${CYPHER_BIN}" "${CYPHER_ARGS}" "${DELETE}"
eval "${CYPHER_BIN}" "${CYPHER_ARGS}" "${QUERY}"

#	QUERY2="\"
#	USING PERIODIC COMMIT 500
#	LOAD CSV FROM 'file:///backward-edge.csv' as line
#	MERGE (n1:NODE {uuid: line[3]})
#	MERGE (n2:NODE {uuid: line[4]})
#	MERGE (n3:NODE {uuid: line[5]})
#	WITH line,n1,n2,n3
#	#WHERE n1.uuid <> '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0' AND n2.uuid <> '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0'
#	CREATE (n1)<-[:NODE {uuid:line[3], nodeType:line[0], type:line[2], ts:line[6], size:line[7], name:line[8]}]-(n2)
#	WITH line,n1,n3
#	WHERE n1.uuid <> '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0' AND n3.uuid <> '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0'
#	CREATE (n1)<-[:NODE {uuid:line[3], nodeType:line[0], type:line[2], ts:line[6], size:line[7], name:line[8]}]-(n3);
#	\""

	# Load CSV file into Neo4j
#	time eval "${CYPHER_BIN}" "${CYPHER_ARGS}" "${QUERY}"
#    fi
# done
