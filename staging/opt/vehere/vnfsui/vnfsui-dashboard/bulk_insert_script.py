# requirement
# "sudo pip install elasticsearch"


import json
import pdb
from elasticsearch5 import Elasticsearch

file_path="dashboards/all-dashboard.json"
host = "http://127.0.0.1:9200"
es = Elasticsearch([host])

with open(file_path, 'r') as f:
	data=f.read()
	json_d=json.loads(data)
	for x in json_d:
		index = ".kibana"
		type = x["_type"]
		id = x["_id"]
		body = x["_source"]
		try:
			es.index(index=index,doc_type=type,id=id,body=body)
		except Exception as e:
			print(e.message)

