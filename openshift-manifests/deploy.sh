#!/bin/bash
oc create -f auth-project.yaml
oc create -f rhsso-operatorgroup.yaml
oc create -f rhsso-operator-subscription.yaml
oc create -f rhsso-keycloak-cr.yaml