#!/bin/bash


# Get parameter
#IMPORT_DIR="/data/neo4j-csvs"
IMPORT_DIR="/var/lib/neo4j/import"
CYPHER_BIN="cypher-shell"
NEO4J_SERVER="127.0.0.1:7687"
USER="neo4j"
CYPHER_ARGS="-a $NEO4J_SERVER -u neo4j -p neo4jchanged"



QUERY="\"
MATCH p=(n1)-[r]->(n2) RETURN p
\""

QUERY2="\"
MATCH p=(n1)<-[r:SYSCALL*2..]-(n2)<-[r2:SYSCALL]-(n3) 
WHERE n1.host = 'ta1-cadets-1' AND n1.caption = 'sshd' AND (n2.caption = 'sshd' OR n2.caption = 'bash') AND n3.caption contains 'scp'
RETURN n1,length(p)
\""

eval "${CYPHER_BIN}" "${CYPHER_ARGS}" "${QUERY2}"

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
