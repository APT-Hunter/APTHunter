#!/bin/bash
ausyscall --dump > /tmp/sys; python -c "import json; infile=open(\"/tmp/sys\", 'r'); print json.dumps({k:v.strip() for (k,v) in [l.split(\"\t\") for l in infile.readlines()[1:]]})"
