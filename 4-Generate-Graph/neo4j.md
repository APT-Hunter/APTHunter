#### Install neo4j  
To install Neo4j on Debian you need to make sure of the following:
   - An OpenJDK Java 11 runtime is installed or available through your package manager.
   - The repository containing the Neo4j Debian package is known to the package manager.

###### Intall Java 11 on Ubuntu 16.04

Add the official OpenJDK package repository to apt:

```shell
sudo add-apt-repository -y ppa:openjdk-r/ppa
sudo apt-get update
```
It is ready now to install neo4j
###### Install neo4j

-Add the neo4j repository
```shell
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4.1' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
```
- test that the repository added:
```shell
apt list -a neo4j
```
- Install neo4j:
```shell
sudo apt-get install neo4j=1:4.1.1
```
- Now test JAVA version (should be 1-11-0) and check the neo4j is running
```shell
update-java-alternatives --list
# output may be like:
java-1.11.0-openjdk-amd64      1111       /usr/lib/jvm/java-1.11.0-openjdk-amd64
java-1.8.0-openjdk-amd64       1081       /usr/lib/jvm/java-1.8.0-openjdk-amd64

# if many version are installed as above, then select the java 11 as the default by:
sudo update-java-alternatives --jre --set java-1.11.0-openjdk-amd64

#start neo4j and then check its status 
sudo service neo4j start
sudo service neo4j status
#sudo ls -al /var/lib/neo4j/data/databases/graph.db

```
- by first use of neo4j db connection (port 7687), it will request change the default password (neo4j). Many changes done in the neo4j-load-csv.sh script including ip address, import DIR, ...
```shell
# To insert the data into Neo4j, run the following command:
sudo ./neo4j-load-csv.sh .
# For forward tracing
sudo ./neo4j-load-forward-tracing-csv.sh .
# To view the graph visually: go to http://127.0.0.1:7474/browser/ in a browser. User: neo4j  Password: neo4jchanged
# if receive error: graph.db not found: do the following 
sudo service neo4j stop
sudo rm -rf /var/lib/neo4j/data/databases/graph.db
sudo service neo4j start
# to restart neo4j
sudo service neo4j restart

```

- To run the reduction:
```shell
cd reduction
python reduction.py <folder_name>
# folder_name: containts copy of forward.csv and backwards.csv by naming them as: backward-edge-0.csv  forward-edge-0.csv
```
- To insert the data into Neo4j, run the following command:
```shell
cd parser/
$ sudo ./neo4j-load-reduced-csv.sh .
```

- To create and drop indexes
```shell
CREATE INDEX FOR (r:SYSCALL) ON (r.timestampq)
DROP INDEX ON :SUBJECT(caption)

# to check the created indexes
:schema
```

- To create and remove labels
```shell
MATCH p=(n1)-[r1:SYSCALL]->(n2) 
WHERE r1.type =~ 'MODIFY_PROCESS'
SET n2:Compromised:test
RETURN n1.host as host, n1.name as caption

MATCH p = (n1:SUBJECT:Compromised)-[r1:SYSCALL]->(n2:SUBJECT)
REMOVE n1:test
RETURN p limit 10
```


- Neo4j LOAD CSV file in parts
 ```shell
add the following line after: LOAD CSV FROM 'file:///forward-edge.csv' as line
WITH line WHERE linenumber() >=10 AND linenumber() <12
```
