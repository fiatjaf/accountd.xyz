CREATE TABLE users (
  id text PRIMARY KEY
);

CREATE TABLE accounts (
  type text,
  account text PRIMARY KEY,
  user_id text REFERENCES users (id)
);
