#!/bin/bash
#
# Used to cleanup kubernetes artifacts for the mds3server
#

DEPLOYNAME=mds3server

SNAME=$(kubectl get secrets -o "jsonpath={range .items[?(.metadata.name==\"$DEPLOYNAME\")]}{.metadata.name}{end}" 2>/dev/null)
if [ ! -z "$SNAME" ]
then
	echo "Removing secret: $SNAME"
	kubectl delete secret "$SNAME"
fi

DEPLOYMENT=$(kubectl get deployment -o json | jq -r ".items[] | select(.metadata.labels.app==\"$DEPLOYNAME\") | .metadata.name")
if [ ! -z "$DEPLOYMENT" ]
then 
  echo "Deleting deployment: $DEPLOYMENT"
  kubectl delete deployment "$DEPLOYMENT"
fi

SVC=$(kubectl get svc -o json | jq -r ".items[] | select(.metadata.name==\"$DEPLOYNAME\") | .metadata.name")
if [ ! -z "$SVC" ]
then 
  echo "Deleting service: $SVC"
  kubectl delete service "$SVC"
fi


