#!/usr/bin/env python3

# Import json module
import json

# Define json data
eventData ="""{"datum":{"com.bbn.tc.schema.avro.cdm18.Event":{"uuid":"E2717054-5C35-51B5-9638-04A28A46F4F4","sequence":{"long":9253185},"type":"EVENT_FCNTL","threadId":{"int":100117},"hostId":"83C8ED1F-5045-DBCD-B39F-918F0DF4F851","subject":{"com.bbn.tc.schema.avro.cdm18.UUID":"72FB0406-3678-11E8-BF66-D9AA8AFF4A69"},"predicateObject":null,"predicateObjectPath":null,"predicateObject2":null,"predicateObject2Path":null,"timestampNanos":1522949718807923603,"name":{"string":"aue_fcntl"},"parameters":{"array":[{"size":-1,"type":"VALUE_TYPE_CONTROL","valueDataType":"VALUE_DATA_TYPE_INT","isNull":false,"name":{"string":"cmd"},"runtimeDataType":null,"valueBytes":{"bytes":"04"},"provenance":null,"tag":null,"components":null}]},"location":null,"size":null,"programPoint":null,"properties":{"map":{"host":"83c8ed1f-5045-dbcd-b39f-918f0df4f851","return_value":"0","fd":"4","exec":"python2.7","ppid":"1"}}}},"CDMVersion":"18","source":"SOURCE_FREEBSD_DTRACE_CADETS"}{"datum":{"com.bbn.tc.schema.avro.cdm18.Event":{"uuid":"E2717054-5C35-51B5-9638-04A28A46F4F4","sequence":{"long":9253185},"type":"EVENT_FCNTL","threadId":{"int":100117},"hostId":"83C8ED1F-5045-DBCD-B39F-918F0DF4F851","subject":{"com.bbn.tc.schema.avro.cdm18.UUID":"72FB0406-3678-11E8-BF66-D9AA8AFF4A69"},"predicateObject":null,"predicateObjectPath":null,"predicateObject2":null,"predicateObject2Path":null,"timestampNanos":1522949718807923603,"name":{"string":"aue_fcntl"},"parameters":{"array":[{"size":-1,"type":"VALUE_TYPE_CONTROL","valueDataType":"VALUE_DATA_TYPE_INT","isNull":false,"name":{"string":"cmd"},"runtimeDataType":null,"valueBytes":{"bytes":"04"},"provenance":null,"tag":null,"components":null}]},"location":null,"size":null,"programPoint":null,"properties":{"map":{"host":"83c8ed1f-5045-dbcd-b39f-918f0df4f851","return_value":"0","fd":"4","exec":"python2.7","ppid":"1"}}}},"CDMVersion":"18","source":"SOURCE_FREEBSD_DTRACE_CADETS"}"""

eventData1 ="""{"uuid":"E2717054-5C35-51B5-9638-04A28A46F4F4","sequence":{"long":9253185},"type":"EVENT_FCNTL","threadId":{"int":100117},"hostId":"83C8ED1F-5045-DBCD-B39F-918F0DF4F851","subject":{"com.bbn.tc.schema.avro.cdm18.UUID":"72FB0406-3678-11E8-BF66-D9AA8AFF4A69"},"predicateObject":null,"predicateObjectPath":null,"predicateObject2":null,"predicateObject2Path":null,"timestampNanos":1522949718807923603,"name":{"string":"aue_fcntl"},"parameters":{"array":[{"size":-1,"type":"VALUE_TYPE_CONTROL","valueDataType":"VALUE_DATA_TYPE_INT","isNull":false,"name":{"string":"cmd"},"runtimeDataType":null,"valueBytes":{"bytes":"04"},"provenance":null,"tag":null,"components":null}]},"location":null,"size":null,"programPoint":null,"properties":{"map":{"host":"83c8ed1f-5045-dbcd-b39f-918f0df4f851","return_value":"0","fd":"4","exec":"python2.7","ppid":"1"}}}"""

# Input the key value that you want to search
Val = input("Enter value: \n")

# load the json data
event = json.loads(eventData)
# Search the key value using 'in' operator
if event["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["timestampNanos"] == Val:
    # Print the success message and the value of the key
    print("%s is found in JSON data" %Val)
    print("The record of", Val,"is", event)
else:
    # Print the message if the value does not exist
    print("%s is not found in JSON data" %Val)




