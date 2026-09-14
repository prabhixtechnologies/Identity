package com.prabhix.identity.webauthn;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface WebAuthnCredentialRepository extends JpaRepository<WebAuthnCredential, UUID> {

    List<WebAuthnCredential> findByUserId(UUID userId);

    List<WebAuthnCredential> findByUserIdIn(Collection<UUID> userIds);

    Optional<WebAuthnCredential> findByIdAndUserId(UUID id, UUID userId);

    Optional<WebAuthnCredential> findByCredentialId(byte[] credentialId);

    boolean existsByUserId(UUID userId);

    long countByUserId(UUID userId);
}
