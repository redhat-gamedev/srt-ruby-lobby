#!/bin/bash
oc create -f project.yaml
oc apply -f operatorgroup.yaml

# create subscriptions
oc apply -f rhsso-operator-subscription.yaml
oc apply -f amq-operator-subscription.yaml
oc apply -f jdg-operator-subscription.yaml

# create the jdg secrets
oc apply -f jdg-credentials-secret.yaml
oc apply -f jdg-playerdata-credentials.yaml

sleep 15

# need to wait for the crds to exist
oc apply -f rhsso-keycloak-cr.yaml
oc apply -f amq-broker-cr.yaml
oc apply -f amq-chat-address-cr.yaml
oc apply -f jdg-cluster-cr.yaml
oc apply -f jdg-playerdata-cache.yaml
