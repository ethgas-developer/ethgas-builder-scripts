## Overview
Builders can use this repo for on-boarding their BLS public keys to ETHGas Exchange

## Get Started
* clone one of `.env.example.<env>` as `.env` and fill in the values
    * `BLS_PUBKEY` and `BLS_SECRET_KEY` should be from the same key pair
    * `EOA_SIGNING_KEY` is your registered or to-be-registered account on ETHGas Exchange
    * `ENTITY_NAME` is your company/entity name
    * set `ENABLE_REGISTRATION` as `true` or `false` to register or deregister the BLS key respectively
* Run `./scripts/build.sh` to build the docker image
* Run `docker-compose -f docker-compose.yml up`

## If you need help...
* [ETHGas Doc](https://docs.ethgas.com/)
* [ETHGas X / Twitter](https://x.com/ETHGASofficial)