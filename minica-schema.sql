CREATE TABLE cacert (
    id text primary key unique,
    serial int,
    subject text,
    begindate text,
    expiredate text,
    revokedate text,
    revokereason text,
    cert text,
    key text
);
CREATE TABLE cert (
    id text primary key unique,
    issuer_id text,
    serial int,
    subject text,
    begindate text,
    expiredate text,
    revokedate text,
    revokereason text,
    cert text,
    secret text,
    key text
);
CREATE TABLE crl (
    id text primary key unique,
    issuer_id text,
    serial int,
    begindate text,
    expiredate text,
    crl text
);
