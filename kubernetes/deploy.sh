#!/bin/bash
#
# Used to deploy verifypushcreds to kubernetes
#

DEPLOYNAME=mds3server

# Modify the environment variables here
PORT=3000
LOCAL_SSL_SERVER=false
LOCAL_SSL_PORT=9443
MDSSIGNER_KEY=mds3server.key.pem
MDSSIGNER_CRT=mds3server.crt.pem
METADATA_DIR=./metadata
MDSPROXY_REFRESH_INTERVAL=3600000
MDSPROXY_MDS_SERVERS='[{"url": "https://mds.fidoalliance.org", "signerPEMFile": "fido_mds_production_jws_signer"}]'
MDSPROXY_ADVANCED='{"removeStatusReportsFIPSFields": true}'

# Allow override of above variables from a local .env file (which is in .gitignore)
# Basically you can create a .env file with those variables above defined in it with your
# own values, then you do not have to ever modify this script.
if [ -f ../.env ]
then
. ../.env
fi




SNAME=$(kubectl get secrets -o "jsonpath={range .items[?(.metadata.name==\"$DEPLOYNAME\")]}{.metadata.name}{end}" 2>/dev/null)
if [ ! -z "$SNAME" ]
then
	echo "Removing existing secret: $SNAME"
	kubectl delete secret "$SNAME"
fi

kubectl create secret generic "$DEPLOYNAME" \
  --from-literal=PORT="$PORT" \
  --from-literal=LOCAL_SSL_SERVER="$LOCAL_SSL_SERVER" \
  --from-literal=LOCAL_SSL_PORT="$LOCAL_SSL_PORT" \
  --from-literal=MDSSIGNER_KEY="$MDSSIGNER_KEY" \
  --from-literal=MDSSIGNER_CRT="$MDSSIGNER_CRT" \
  --from-literal=METADATA_DIR="$METADATA_DIR" \
  --from-literal=MDSPROXY_REFRESH_INTERVAL="$MDSPROXY_REFRESH_INTERVAL" \
  --from-literal=MDSPROXY_MDS_SERVERS="$MDSPROXY_MDS_SERVERS" \
  --from-literal=MDSPROXY_ADVANCED="$MDSPROXY_ADVANCED"


DEPLOYMENT=$(kubectl get deployment -o json | jq -r ".items[] | select(.metadata.labels.app==\"$DEPLOYNAME\") | .metadata.name")
if [ ! -z "$DEPLOYMENT" ]
then 
  echo "Deleting deployment: $DEPLOYMENT"
  kubectl delete deployment "$DEPLOYMENT"
fi

SVC=$(kubectl get svc -o json | jq -r ".items[] | select(.metadata.name==\"$DEPLOYNAME\") | .metadata.name")
if [ ! -z "$SVC" ]
then 
  echo "Deleting existing service: $SVC"
  kubectl delete service "$SVC"
fi

kubectl create -f "$DEPLOYNAME.yaml"
