#!/bin/bash
set -e
set -x

cd $(dirname $0)

function get_name()
{
	basename "$1" .json | sed -e 's/ /%20/g'
}

if [ -z "$1" ]; then
    ELASTICSEARCH=http://127.0.0.1:9200
else
    ELASTICSEARCH=$1
fi

if [ -z "$2" ]; then
    CURL=curl
else
    CURL="curl --user $2"
fi

echo $CURL
DIR=dashboards
INDEX_NAME="logvehere-alert-status"

curl -X PUT "http://localhost:9200/_template/vaddress-book" -d '{
     "template": "logvehere-address-book",
     "settings": {
        "number_of_shards": "5",
        "number_of_replicas": "0"
     }
}'

curl -X PUT "http://localhost:9200/logvehere-address-book/" -H 'Content-Type: application/json' -d '{    
  "mappings": {
      "INDVGRP": {
        "properties": {
          "extension": {
            "type": "keyword"
          },
          "identity": {
            "type": "keyword"
          },
          "identitytype": {
            "type": "keyword"
          },
          "mobile": {
            "type": "keyword"
          },
          "name": {
            "type": "keyword"
          },
          "phone": {
            "type": "keyword"
          }
        }
      },
      "HOSTS": {
        "properties": {
          "classification": {
            "type": "keyword"
          },
          "custodian": {
            "type": "keyword"
          },
          "ipAddressNRanges": {
            "type": "keyword"
          },
          "ipRanges": {
            "properties": {
              "from": {
                "type": "ip"
              },
              "to": {
                "type": "ip"
              }
            }
          },
          "name": {
            "type": "keyword"
          },
          "owner": {
            "type": "keyword"
          },
          "user": {
            "type": "keyword"
          },
          "value": {
            "type": "double"
          }
        }
      },
      "HOST": {
        "properties": {
          "classification": {
            "type": "keyword"
          },
          "custodian": {
            "type": "keyword"
          },
          "ipAddresses": {
            "type": "ip"
          },
          "macAddresses": {
            "type": "keyword"
          },
          "name": {
            "type": "keyword"
          },
           "nmapData" : {
            "properties" : {
              "host" : {
                "type" : "text",
                "fields" : {
                  "keyword" : {
                    "type" : "keyword",
                    "ignore_above" : 256
                  }
                }
              },
              "ip" : {
                "type" : "text",
                "fields" : {
                  "keyword" : {
                    "type" : "keyword",
                    "ignore_above" : 256
                  }
                }
              },
              "mac" : {
                "type" : "text",
                "fields" : {
                  "keyword" : {
                    "type" : "keyword",
                    "ignore_above" : 256
                  }
                }
              },
              "openPorts" : {
                "properties" : {
                  "method" : {
                    "type" : "text",
                    "fields" : {
                      "keyword" : {
                        "type" : "keyword",
                        "ignore_above" : 256
                      }
                    }
                  },
                  "port" : {
                    "type" : "long"
                  },
                  "protocol" : {
                    "type" : "text",
                    "fields" : {
		       "keyword" : {
                         "type" : "keyword",
                        "ignore_above" : 256
                      }
                    }
                  },
                  "service" : {
                    "type" : "text",
                    "fields" : {
                      "keyword" : {
                        "type" : "keyword",
                        "ignore_above" : 256
                      }
                    }
                  }
                }
              },
	       "os" : {
                "type" : "text",
                "fields" : {
                  "keyword" : {
                    "type" : "keyword",
                    "ignore_above" : 256
                  }
                }
              }
            }
          },
          "owner": {
            "type": "keyword"
          },
          "user": {
            "type": "keyword"
          },
          "value": {
            "type": "double"
          }
        }
      }
    }
}'

curl -X PUT "http://localhost:9200/_template/valert-status" -d '{
     "template": "logvehere-alert-status",
     "settings": {
        "number_of_shards": "5",
        "number_of_replicas": "0"
     }
}'

curl -X PUT "http://localhost:9200/$INDEX_NAME/" -d '{
    "mappings": {
      "elastalert_error": {
        "properties": {
          "@timestamp": {
            "type": "date",
            "format": "dateOptionalTime"
          },
          "data": {
            "type": "object",
            "enabled": false
          },
          "message": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "traceback": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          }
        }
      },
      "elastalert": {
        "properties": {
          "@timestamp": {
            "type": "date",
            "format": "dateOptionalTime"
          },
          "aggregate_id": {
            "type": "keyword"
          },
          "alert_info": {
            "properties": {
              "output_file": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "type": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              }
            }
          },
          "alert_sent": {
            "type": "boolean"
          },
          "alert_time": {
            "type": "date",
            "format": "dateOptionalTime"
          },
          "match_body": {
            "type": "object",
            "enabled": false
          },
          "match_time": {
            "type": "date",
            "format": "dateOptionalTime"
          },
          "rule_name": {
            "type": "keyword"
          }
        }
      },
      "silence": {
        "properties": {
          "@timestamp": {
            "type": "date",
            "format": "dateOptionalTime"
          },
          "exponent": {
            "type": "long"
          },
          "rule_name": {
            "type": "keyword"
          },
          "until": {
            "type": "date",
            "format": "dateOptionalTime"
          }
        }
      },
      "past_elastalert": {
        "properties": {
          "@timestamp": {
            "type": "date",
            "format": "dateOptionalTime"
          },
          "aggregate_id": {
            "type": "keyword"
          },
          "match_body": {
            "type": "object",
            "enabled": false
          },
          "rule_name": {
            "type": "keyword"
          }
        }
      },
      "elastalert_status": {
        "properties": {
          "@timestamp": {
            "type": "date",
            "format": "dateOptionalTime"
          },
          "endtime": {
            "type": "date"
          },
          "hits": {
            "type": "long"
          },
          "matches": {
            "type": "long"
          },
          "rule_name": {
            "type": "keyword"
          },
          "starttime": {
            "type": "date"
          },
          "time_taken": {
            "type": "float"
          }
        }
      }
    }
}'

python bulk_insert_script.py

curl -XPUT http://localhost:9200/.kibana/config/5.5.2 -d '{"defaultIndex" : "logvehere-probe-*"}'

cd /usr/lib/x86_64-linux-gnu
sudo cp /usr/local/lib/libpcap.a /usr/lib/x86_64-linux-gnu/
sudo ln -s libpcap.so.0.8 libpcap.so

sed -i -e 's|\[Service\]|\[Service\]\'$'\nEnvironmentFile\=\/etc\/default\/metricbeat|' /lib/systemd/system/metricbeat.service
sudo /bin/systemctl daemon-reload

sudo /usr/local/bin/pf_ringctl start

vnfsalert-create-index --config /usr/local/etc/ruleengine_config.yaml
sudo reboot
