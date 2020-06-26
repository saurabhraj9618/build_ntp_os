#!/bin/bash

rotation_days=$(cat /usr/local/etc/vnfs.json| jq  -r .var_vnfs_metadata_rotation_days)

/opt/elasticsearch-curator/curator_cli delete_indices --filter_list '
[
  {
    "filtertype": "age",
    "source": "creation_date",
    "direction": "older",
    "unit": "days",
    "unit_count": '$rotation_days'
  },
  {
    "filtertype": "pattern",
    "kind": "prefix",
    "value": "logvehere"
  },
  {
    "filtertype": "pattern",
    "kind": "prefix",
    "value": "logvehere-alert-status",
    "exclude": "True"
  },
  {
    "filtertype": "pattern",
    "kind": "prefix",
    "value": "logvehere-address-book",
    "exclude": "True"
  }
]
'

