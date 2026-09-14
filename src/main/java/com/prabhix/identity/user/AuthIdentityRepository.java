package com.prabhix.identity.user;

import com.prabhix.identity.user.AuthIdentity.AuthProvider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuthIdentityRepository extends JpaRepository<AuthIdentity, UUID> {

    Optional<AuthIdentity> findByProviderAndProviderSubject(AuthProvider provider, String providerSubject);

    List<AuthIdentity> findByUserId(UUID userId);

    List<AuthIdentity> findByUserIdIn(Collection<UUID> userIds);

    Optional<AuthIdentity> findByUserIdAndProvider(UUID userId, AuthProvider provider);

    boolean existsByUserIdAndProvider(UUID userId, AuthProvider provider);
}
