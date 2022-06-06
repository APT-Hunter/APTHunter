
###### Neo4j queries



```shell
MATCH (n1)-[r]->(n2) WHERE n1.name = "2008:\"/bin/cat\"" RETURN r, n1, n2
# match on syscall:
MATCH (n1)-[r]->(n2) WHERE r.type = "EXECUTE" RETURN r, n1, n2 LIMIT 50

// Get the whole graph
MATCH p=(n1)-[r]->(n2) RETURN p

# scan for occurence of multiple relations 
MATCH p=(n1)<-[r:SYSCALL*2..]-(n2) 
WHERE n1.caption = 'sshd' AND (n2.caption = 'sshd' OR n2.caption = 'bash') 
RETURN p

# Stage Exfiltrate (remote scp) (DRAKON APT)
MATCH p=(n1)<-[r:SYSCALL*2..]-(n2)<-[r2:SYSCALL]-(n3) 
WHERE n1.caption = 'sshd' AND (n2.caption = 'sshd' OR n2.caption = 'bash') AND n3.caption contains 'scp'
RETURN p


// Stage Exfiltrate (remote scp) (DRAKON APT) (search for connections to IP addresses)
MATCH p=(n1)<-[r:SYSCALL*1..]-(n2)<-[r2:SYSCALL]-(n3) 
WHERE n1.caption = 'sshd' AND (n2.caption = 'sshd' OR n2.caption = 'bash') AND n3.caption contains 'scp'
MATCH p2=(n1)-[r3:SYSCALL]-(n5) WHERE r3.type ="CONNECT" and n5.caption =~ '^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}.*'
RETURN p1,p2

# Recon stage (remote whoami, hostname) (DRAKON APT)
MATCH p=(n1)<-[r:SYSCALL*2..]-(n2)<-[r2:SYSCALL]-(n3) 
WHERE n1.caption = 'sshd' AND (n2.caption = 'sshd' OR n2.caption = 'bash') AND n3.caption =~ 'whoami|hostname'
RETURN p

# Recon stage (remote whoami, hostname) (DRAKON APT) (search for connections to IP addresses)
MATCH p1=(n1)<-[r:SYSCALL*1..]-(n2)<-[r2:SYSCALL]-(n3) 
WHERE n3.caption =~ 'whoami|hostname|ps.*' 
MATCH p2=(n1)-[r3:SYSCALL]-(n5) WHERE r3.type ="CONNECT" and n5.caption =~ '^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}.*'
RETURN p1,p2

MATCH p=(n1)-[r:SYSCALL*1..]->(n2)-[r2:SYSCALL]->(n3) 
WHERE n1.name = 'DEF8FC47-7A9A-FBED-6B2A-08B2189BECCD' AND r2.type =~'EXECUTE|FORK' AND n3.caption =~ 'bash|sshd' AND r2.timestamp >=DateTime("2019-05-14T10:28:28[America/New_York]")

```
