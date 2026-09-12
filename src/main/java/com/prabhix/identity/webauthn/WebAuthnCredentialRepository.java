package com.prabhix.identity.webauthn;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface WebAuthnCredentialRepository extends JpaRepository<WebAuthnCredential, UUID> {

    List<WebAuthnCredential> findByUserId(UUID userId);

    Optional<WebAuthnCredential> findByCredentialId(byte[] credentialId);

    boolean existsByUserId(UUID userId);
}
