-- Creates the separate database for the login app alongside Hydra's database.
-- Postgres entrypoint runs this as the superuser on first start.
CREATE USER lnurl WITH PASSWORD 'lnurl';
CREATE DATABASE lnurl_hydra_login OWNER lnurl;
