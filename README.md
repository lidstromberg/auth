# Auth - Go user account management for Google Cloud Datastore/Google Cloud SQL Postgres

A Go bundle for user account management, authentication & authorisation, utilising Google Cloud Platform Datastore or PostgresSQL.

## What?
This is Go code which bundles some common authentication and authorisation workflows:
* User account registration workflow
* User account login workflow
* Change user account profile workflow
* Change password workflow
* Forgotten password workflow
* Confirmation email workflows (via [Sendgrid])

## Why?
I switched from using dotnet core which has identity core built-in, to using Go (for various reasons). I couldn't find an equivalent user management package for Go, and I didn't want to buy a service because I didn't have a revenue stream to pay with. I work mainly with Google Cloud Platform, so I wanted something which would use a GCP backend. So this started as a learning exercise to see if I could create something which would work using either GCP Datastore or Cloud SQL (Postgres).

## How?
There are three ways to use the package:
* Write your own service to wrap the auth package
* Use the example grpc service
* Use the example http service (written for appengine standard 2nd gen, but also works as a standalone)
The best place to start is probably with the examples and tests.

## Examples
See [examples] for grpc and http/appengine implementations which use auth.

## Dependencies and services
This utilises the following fine pieces of work:
* [Dave Grijalva]'s [jwt-go] Go implementation of JSON Web Tokens (JWT)
* [Paul Querna]'s [otp] Go implementation for one time passwords (2FA)
* [Pq] Pure Go Postgres driver for database/sql
* [Segment]'s [ksuid] - K-Sortable Globally Unique IDs
* [Sendgrid]'s [sendgrid-go] - Official SendGrid Led, Community Driven Golang API Library
* [GCP]'s [Datastore Go client] and [Storage Go client]

## Installation
Install using go get.

```sh
$ go get -u github.com/lidstromberg/auth
```
#### Environment Variables
You will also need to export (linux/macOS) or create (Windows) some environment variables.
The mandatory environment variables must be set, with the following possible exception: the Cloud SQL vars are only required if you want to use a postgres backend. Ignore the Cloud SQL vars if you want to use a GCP Datastore backend.

The static environment variables can be changed but don't need to be.

```sh
################START OF MANDATORY ENV VARS################

################################
# GCP DETAILS
################################
export LBAUTH_GCP_PROJECT="{{PROJECTNAME}}"
export LBAUTH_GCP_BUCKET="{{BUCKETNAME}}"
```
```sh
################################
# GCP CREDENTIALS
################################
export GOOGLE_APPLICATION_CREDENTIALS="/PATH/TO/GCPCREDENTIALS.JSON"
```
(See [Google Application Credentials])
```sh
################################
# SENDGRID CREDENTIALS
################################
export SENDGRID_API_KEY="{{SENDGRID_API_KEY}}"
```
(See [Sendgrid Trial])
```sh
################################
# CLOUD SQL
################################
export LBAUTH_SQLDST="cloudsqlpostgres"
export LBAUTH_SQLCNX="host=127.0.0.1:5432 dbname={{DBNAME}} user={{USER}} password={{PASSWORD}} sslmode=disable"
```
(See [Cloud SQL Postgres])

```sh
################################
# AUTH DEBUG FLAG
# switch LB_DEBUGON to true to start verbose logging
################################
export LB_DEBUGON="false"


################################
# AUTH BACKEND TYPE
# datastore or postgres
################################
export LBAUTH_DSTYPE="datastore"

################END OF MANDATORY ENV VARS################
```

The following environment variables can be changed, but don't need to be.
```sh
################START OF STATIC ENV VARS#################

################################
# AUTH GLOBAL
################################
export LBAUTH_APPROLEDELIM=":"
export LBAUTH_MAILERTYPE="bucket"

# edit/copy mailerdata.json from github.com/lidstromberg/auth to your GCP bucket
export LBAUTH_MAILERFILE="mailerdata.json"

################################
# AUTH DATASTORE NAMESPACE
################################
export LBAUTH_ACCNAMESP="auth"

################################
# DATASTORE CONFIRMATION ENTITY
# This entity tracks registration/password reset email requests
################################
export LBAUTH_KD_ACCCNF="useraccountconfirmation"

################################
# DATASTORE ACCOUNT ENTITY
# This entity contains the user accounts
################################
export LBAUTH_KD_ACC="useraccount"

################################
# DATASTORE CLIENT POOL SIZE
# This controls the Google Cloud GRPC Datastore client pool size
################################
export LBAUTH_CLIPOOL="5"

################END OF STATIC ENV VARS#################
```

#### Private/Public Certs for JWT
You will also require RSA certs for the [jwt-go] JWT tokens. The following will generate them (assuming you have openssl installed). You should place a password on the private key when prompted.

```sh
$ ssh-keygen -t rsa -b 4096 -f jwt.key
$ openssl rsa -in jwt.key -pubout -outform PEM -pubout -out jwt.key.pub
```

#### Google Cloud Platform Requirements
If you intend to use GCP datastore as your backend, then you will require:
* A GCP project
* A GCP storage bucket (private) to store the jwt private/public keys and the mailerdata.json file (in the root of the bucket)
* GCP Datastore enabled (which means your GCP Project's AppEngine must be enabled)
* Your GOOGLE_APPLICATION_CREDENTIALS json credentials key should be created with the following IAM scopes: 'Cloud SQL Client' (If you want to the use Cloud SQL Postgres); 'Cloud Datastore User'; 'Storage Object Viewer' and 'Storage Object Creator', or 'Storage Object Admin'.


   [Dave Grijalva]: <https://github.com/dgrijalva>
   [jwt-go]: <https://github.com/dgrijalva/jwt-go>
   [Paul Querna]: <https://github.com/pquerna>
   [otp]: <https://github.com/pquerna/otp>
   [Pq]: <https://github.com/lib/pq>
   [Segment]: <https://github.com/segmentio>
   [ksuid]: <https://github.com/segmentio/ksuid>
   [GCP]: <https://cloud.google.com/>
   [Datastore Go client]: <https://cloud.google.com/datastore/docs/reference/libraries#client-libraries-install-go>
   [Storage Go client]: <https://cloud.google.com/storage/docs/reference/libraries#client-libraries-install-go>
   [Sendgrid]: <https://github.com/sendgrid>
   [sendgrid-go]: <https://github.com/sendgrid/sendgrid-go>
   [Sendgrid Trial]: <https://signup.sendgrid.com>
   [Google Application Credentials]: <https://cloud.google.com/docs/authentication/production#auth-cloud-implicit-go>
   [Cloud SQL Postgres]: <https://cloud.google.com/sql/docs/postgres/sql-proxy>
   [examples]: <https://github.com/lidstromberg/examples>
