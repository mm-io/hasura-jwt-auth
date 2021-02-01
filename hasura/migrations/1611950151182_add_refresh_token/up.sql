-- Add refresh_token column
alter table hasura_user
  add refresh_token text;

-- Update user encrypt to make sure refresh_token is blank as well
create or replace function hasura_user_encrypt_password() returns trigger as $$
begin
    if new.cleartext_password is not null and trim(new.cleartext_password) <> '' then
        new.crypt_password := (hasura_encrypt_password(new.cleartext_password, gen_salt('bf')));
    end if;
    new.cleartext_password = null;
    new.access_token = null;
    new.refresh_token = null;
    return new;
end;
$$ language 'plpgsql';

-- Update token to generate refresh + then create refresh function for the access_token
-- Same implementation as found here > https://github.com/sander-io/hasura-jwt-auth/issues/7#issuecomment-770232907
create or replace function hasura_auth(_email text, _cleartext_password text) returns setof hasura_user as $$
    select
        id,
        email,
        crypt_password,
        cleartext_password,
        default_role,
        allowed_roles,
        enabled,
        sign(
            json_build_object(
                'sub', id::text,
                'iss', 'Hasura-JWT-Auth',
                'iat', round(extract(epoch from now())),
                'exp', round(extract(epoch from now() + interval '5 minutes')),
                'https://hasura.io/jwt/claims', json_build_object(
                    'x-hasura-user-id', id::text,
                    'x-hasura-default-role', default_role,
                    'x-hasura-allowed-roles', allowed_roles
                )
            ), current_setting('hasura.jwt_secret_key')) as access_token,
        created_at,
        updated_at,
        sign(
            json_build_object(
                'sub', id::text,
                'iss', 'Hasura-JWT-Auth',
                'iat', round(extract(epoch from now())),
                'exp', round(extract(epoch from now() + interval '168 hours')),
                'https://hasura.io/jwt/claims', json_build_object(
                    'x-hasura-user-id', id::text,
                    'x-hasura-default-role', 'anonymous',
                    'x-hasura-allowed-roles', ('["anonymous"]')::jsonb
                )
            ), current_setting('hasura.jwt_secret_key')) as refresh_token
    from hasura_user h
    where h.email = hasura_auth._email
    and h.enabled
    and h.crypt_password = hasura_encrypt_password(hasura_auth._cleartext_password, h.crypt_password);
$$ language 'sql' stable;

create or replace function hasura_refresh(hasura_session json) returns setof hasura_user as $$
    select
        id,
        email,
        crypt_password,
        cleartext_password,
        default_role,
        allowed_roles,
        enabled,
        sign(
            json_build_object(
                'sub', id::text,
                'iss', 'Hasura-JWT-Auth',
                'iat', round(extract(epoch from now())),
                'exp', round(extract(epoch from now() + interval '5 minute')),
                'https://hasura.io/jwt/claims', json_build_object(
                    'x-hasura-user-id', id::text,
                    'x-hasura-default-role', default_role,
                    'x-hasura-allowed-roles', allowed_roles
                )
            ), current_setting('hasura.jwt_secret_key')) as access_token,
        created_at,
        updated_at,
        '' as refresh_token
    from hasura_user h
    where h.id = (hasura_session ->> 'x-hasura-user-id')::int
    and h.enabled
$$ language 'sql' stable;