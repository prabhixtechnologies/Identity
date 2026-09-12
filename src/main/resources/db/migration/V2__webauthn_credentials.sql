-- Passkey credentials for WebAuthn assertion.
--
-- One row per authenticator credential. credential_id is the handle the browser returns on get();
-- public_key is the COSE key used to verify the assertion signature. signature_count detects cloned
-- authenticators: a counter that goes backwards is refused.

CREATE TABLE public.webauthn_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    user_id uuid NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    signature_count bigint DEFAULT 0 NOT NULL,
    aaguid uuid,
    label character varying(120),
    transports jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_by uuid,
    CONSTRAINT webauthn_credentials_pkey PRIMARY KEY (id),
    CONSTRAINT webauthn_credentials_credential_id_key UNIQUE (credential_id),
    CONSTRAINT webauthn_credentials_user_id_fkey FOREIGN KEY (user_id)
        REFERENCES public.users(id) ON DELETE CASCADE
);

CREATE INDEX webauthn_credentials_user_id_idx ON public.webauthn_credentials (user_id);
