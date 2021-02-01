
lorem ipsum wip

Heavily based off the work by sander-io at: https://github.com/sander-io/hasura-jwt-auth

- Added access_tokens and refresh_token implementation
- Added reset password token with restricted user permissions implementation
  - Added Python mailer for sending the token

Using:
- Hasura Migrations
- PG JWT - https://github.com/michelp/pgjwt
- PL/Python
- py_pgmail - https://github.com/lcalisto/py_pgmail

Inspo:
- https://changelog.com/podcast/417 - having logic *inside* the DB
- Using Hasura migrations to manage that > upcoming volatile functions

# Setup Checklist
```
clone repo
```

- Set Hasura secret
- Set PG secret
- set SMTP server, username and password
  - Optional (don't want, delete)

```
docker-compose up
```

# User Reset

## Register User
Header Required: None - `anonymous` group.

Emails are not saved as cleartext in the DB, the field is used as a placeholder. See `hasura_user_encrypt_password()` in `/hasura/migrations/1611950151181_install_jwt/up.sql` which triggers encrypting the password to `crypt_password` and then saving `null` to `cleartext_password`.

```graphql
mutation registerUser {
  insert_hasura_user(objects: {email: "<Your Email>", cleartext_password: "<Your Password>"}) {
    affected_rows
  }
}
```

## Login User
Header Required: None - `anonymous` group.
```graphql
query loginGetTokenPair {
  hasura_auth(args: {_email: "<Your Email>", _cleartext_password: "<Your Password>"}) {
    access_token
    refresh_token
  }
}
```

## Refresh Token
Header Required: `refresh_token` from `loginGetTokenPair`
```graphql
query refreshTokenGetAccess {
  hasura_refresh {
    access_token
  }
}
```

# Password Reset

## Reset User
Header Required: None - `anonymous` group.

Sends `reset_token` by email (if email exists in user group).

```graphql
mutation resetUserSendResetToken {
  insert_hasura_reset_token(objects: {email: "<Your Email>"}) {
    affected_rows
  }
}
```

## Reset User Access
Header Required: None - `anonymous` group.

Uses `reset_token` sent via email.

Creates `access_token` with hardcoded `user` permissions (can only edit own user's password).

```graphql
query resetUserGetAccessToken {
  hasura_reset_password(args: {_email: "<Your Email>", _reset_token: "<reset_token from above>"}) {
    access_token
  }
}
```

## Reset User
Header Required: `access_token` from `resetUserGetAccessToken`
```graphql
mutation updateUserPassword {
  update_hasura_user(where: {email: {_eq: "<Your Email>"}}, _set: {cleartext_password: "<New Password>"}) {
    affected_rows
  }
}
```