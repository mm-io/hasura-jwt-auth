-- Create token
-- User would insert new - creating UUID
create table if not exists hasura_reset_token(
    id serial primary key,
    email text,
    reset_token uuid not null default gen_random_uuid(), 
    created_at timestamptz not null default now(),
    mail_sent boolean default False
);

-- Lookup token + respond with short lived, anonymous access_token
create or replace function hasura_reset_password(_email text, _reset_token uuid) returns setof hasura_user as $$
    begin
        if exists (
            select  
            from hasura_reset_token hrt  
            where hrt.email = hasura_reset_password._email 
            and hrt.reset_token = hasura_reset_password._reset_token
            and hrt.created_at > now() - INTERVAL '15 minutes'
        ) then
            return query(
                select id,
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
                        'exp', round(extract(epoch from now() + interval '15 minutes')),
                        'https://hasura.io/jwt/claims', json_build_object(
                            'x-hasura-user-id', id::text,
                            'x-hasura-default-role', 'user',
                            'x-hasura-allowed-roles', ('["user"]')::jsonb
                        )
                    ), current_setting('hasura.jwt_secret_key')) as access_token,
                created_at,
                updated_at,
                '' as refresh_token
                from hasura_user h
                where h.email = hasura_reset_password._email
                and h.enabled
            );
        else
            -- Do nothing
        end if;
    end;
$$ language 'plpgsql' stable;