#!/bin/bash
#
# Used to deploy verifypushcreds to kubernetes
#

PODNAME=mds3server

# Modify the environment variables here
PORT=3000
LOCAL_SSL_SERVER=false
LOCAL_SSL_PORT=9443
MDSSIGNER_KEY=mds3server.key.pem
MDSSIGNER_CRT=mds3server.crt.pem
METADATA_DIR=./metadata

# Allow override of above variables from a local .env file (which is in .gitignore)
# Basically you can create a .env file with those variables above defined in it with your
# own values, then you do not have to ever modify this script.
if [ -f ../.env ]
then
. ../.env
fi




SNAME=$(kubectl get secrets -o "jsonpath={range .items[?(.metadata.name==\"$PODNAME\")]}{.metadata.name}{end}" 2>/dev/null)
if [ ! -z "$SNAME" ]
then
	echo "Removing existing secret: $SNAME"
	kubectl delete secret $SNAME
fi

kubectl create secret generic $PODNAME \
  --from-literal=PORT=$PORT \
  --from-literal=LOCAL_SSL_SERVER=$LOCAL_SSL_SERVER \
  --from-literal=LOCAL_SSL_PORT=$LOCAL_SSL_PORT \
  --from-literal=MDSSIGNER_KEY=$MDSSIGNER_KEY \
  --from-literal=MDSSIGNER_CRT=$MDSSIGNER_CRT \
  --from-literal=METADATA_DIR=$METADATA_DIR

POD=$(kubectl get pod -o json | jq -r ".items[] | select(.metadata.labels.app==\"$PODNAME\") | .metadata.name")

if [ ! -z "$POD" ]
then 
  echo "Deleting existing pod: $PODNAME"
  kubectl delete pod $PODNAME
fi

PODSVC=$(kubectl get svc -o json | jq -r ".items[] | select(.metadata.name==\"$PODNAME\") | .metadata.name")
if [ ! -z "$PODSVC" ]
then 
  echo "Deleting existing service: $PODSVC"
  kubectl delete service $PODSVC
fi

kubectl create -f "$PODNAME.yaml"
