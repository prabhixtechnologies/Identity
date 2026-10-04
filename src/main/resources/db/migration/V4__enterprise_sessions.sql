-- Sliding browser sessions. Existing rows keep working: the absolute cap is backfilled from
-- created_at so a session that is already open is not cut off on deploy, and the previous-cookie
-- columns stay empty until the next exchange rotates the credential.

ALTER TABLE public.device_sessions
    ADD COLUMN absolute_expires_at timestamp with time zone,
    ADD COLUMN cookie_previous_hash character varying(64),
    ADD COLUMN cookie_previous_expires_at timestamp with time zone,
    ADD COLUMN mfa_verified_at timestamp with time zone,
    ADD COLUMN authenticated_at timestamp with time zone;

UPDATE public.device_sessions
   SET authenticated_at = created_at
 WHERE authenticated_at IS NULL;

UPDATE public.device_sessions
   SET absolute_expires_at = created_at + interval '365 days'
 WHERE absolute_expires_at IS NULL;

ALTER TABLE public.device_sessions
    ALTER COLUMN absolute_expires_at SET NOT NULL;

CREATE UNIQUE INDEX uq_device_sessions_cookie_previous
    ON public.device_sessions USING btree (cookie_previous_hash)
    WHERE (cookie_previous_hash IS NOT NULL);
