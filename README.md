# Space Ring Things Game Lobby
This is a Ruby app that will serve as the game lobby. It will make use of the
[OpenID Connect gem](https://github.com/nov/openid_connect) It also takes
insights from this [Identity OIDC
Sinatra](https://github.com/18F/identity-oidc-sinatra) example application.

## Authentication
It uses OIDC to connect to Red Hat Single Sign-On (RHSSO). The following are some quick steps
to installing RHSSO on OpenShift 4:

* Use the OperatorHub to install the RHSSO Operator
* Create an `auth` project
* Create a `Keycloak` instance which deploys RHSSO and its database:

      apiVersion: keycloak.org/v1alpha1
      kind: Keycloak
      metadata:
        name: srt-sso
        namespace: auth
        labels:
          app: srt-sso
      spec:
        externalAccess:
          enabled: true
        instances: 1
* Get the admin password by looking at the `credential-srt-sso` secret
* Login to RHSSO as the admin
* Create a realm
* Add GitHub authentication to the realm

## Running the Lobby locally
* `bundle install`
* set `host`, `secret` and `lobby` ENV vars as required
* `bundle exec rackup`