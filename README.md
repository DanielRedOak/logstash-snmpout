logstash-snmpout
================

SNMP Trap v2c Output for Logstash

#Synopsis
```
output {
  snmpwalk {
    codec => ... # codec (optional), default: "line"
    host => ... # string (optional), default: "0.0.0.0"
    port => ... # number (optional), default: "162"
    community => ... # string (optional), default: "public"
    oid => ... # string (required)
    yamilmibdir => ... # string (optional)
  }
}
```
