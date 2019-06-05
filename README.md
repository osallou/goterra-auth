# GoTerra Authentication service

## Requirements

mongodb

## License

Apache 2.0

## Add users

Users are added in database via goterra-auth-cli

## Supported authentications

* local:  users are stored in local database

## Run

    GOT_CONFIG=goterra-auth.yml goterra-auth

## Docker

Use provided Dockerfile.

At runtime, a goterra.yml should be set in /root/goterra.yml

    docker run -v xx/goterra.yml:/root/goterra.yml -p 8000:8000 xx/goterra-auth
