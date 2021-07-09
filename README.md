# Space Ring Things Game Lobby
This is a Ruby app that will serve as the game lobby. It will make use of the
[OpenID Connect gem](https://github.com/nov/openid_connect) It also takes
insights from this [Identity OIDC
Sinatra](https://github.com/18F/identity-oidc-sinatra) example application.

The game lobby will also connect to the data grid that stores the player's
details. If the player doesn't yet exist (in game terms), this app initializes
their in-game object/account. The lobby makes use of the HTTP/REST API for Red
Hat Datagrid / Infinispan.

## OpenShift / Kubernetes Assets
The lobby relies on RHSSO (Red Hat Single Sign On) and RHDG (Red Hat Data Grid)
being installed into the cluster through the use of operators. There is a
rudimentary deployment script in the `openshift-manifests` folder that will
install the operators into the cluster using OpenShift Operator Lifecycle
Manager (OLM). It then deploys the various Custom Resources (CRs) that will
cause the operators to deploy RHSSO and RHDG.

These manifests are very rudimentary and hackish and should not be considered to
be creating production deployments of anything.

## Environment Variables
There are various environment variables that the lobby will use to determine how
to talk to SSO and the data grid. Their usage is documented in the code
comments.
## Running the Lobby locally
* `bundle install`
* set the ENV vars as required, noting that your app is outside the cluster and
  you must have routes for all endpoints
* `bundle exec rackup`

## Running SSO and Data Grid locally
TODO