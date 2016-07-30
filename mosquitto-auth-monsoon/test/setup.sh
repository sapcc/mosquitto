#!/bin/bash

cat << EOCA | cfssl genkey -initca - |cfssljson -bare ca
{
    "CN": "Test CA",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [ ]
}
EOCA

cat << EOBROKER | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=server - |cfssljson -bare broker
{
    "CN": "broker",
    "hosts": ["broker", "localhost"],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [ ]
}
EOBROKER

cat << EOCLIENT1 | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client - |cfssljson -bare client1
{
    "CN": "client1",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [{
      "O": "org1",
      "OU": "project1"
    }]
}
EOCLIENT1

cat << EOCLIENT2 | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client - |cfssljson -bare client2
{
    "CN": "client2",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [{
      "O": "org1",
      "OU": "project2"
    }]
}
EOCLIENT2
