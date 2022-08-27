#!/bin/bash
cd tracer
make trace
cd ..

sudo service neo4j stop # Stops neo4j service
sudo rm -rf /var/lib/neo4j/data/databases/graph.db # deletes content of existing database
sudo service neo4j start # starts neo4j service again

# If you want to run the audit system and generate some logs (in this case, for c_tests), uncomment:
# cd ../c_tests/
#./run_tests_c.sh

# This code will generate CSVs:
#cd ../parser/
#python parser.py ../c_tests/testCase.audit

sleep 10 # wait while neo4j service is loading

sudo ./neo4j-load-csv.sh .