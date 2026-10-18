package com.prabhix.identity.provisioning;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.Emails;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.config.IdentityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.regex.Pattern;

/**
 * Holds a signup in Redis until the emailed code is entered.
 *
 * <p>The database row is created by the caller after {@link #match}. The Redis value keeps the
 * bcrypt password hash and the OTP hash. The raw password and the raw code are never written.
 * The session stores only the random token; the address index is a hash, so a key listing does
 * not show who is signing up.
 */
@Service
class PendingSignupStore {

    static final String PREFIX = "signup:";
    static final String EMAIL_PREFIX = "signup-email:";
    private static final Duration RESEND_COOLDOWN = Duration.ofSeconds(45);
    private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9_-]{20,128}");
    private static final char SEP = '\u001e';

    private final SignupCache cache;
    private final Duration ttl;
    private final int otpLength;
    private final int maxAttempts;
    private final Clock clock;

    @Autowired
    PendingSignupStore(SignupCache cache, IdentityProperties properties) {
        this(cache, properties.challenge().ttl(), properties.challenge().otpLength(),
                properties.challenge().maxAttempts(), Clock.systemUTC());
    }

    PendingSignupStore(SignupCache cache, Duration ttl, int otpLength, int maxAttempts, Clock clock) {
        this.cache = cache;
        this.ttl = ttl;
        this.otpLength = otpLength;
        this.maxAttempts = maxAttempts;
        this.clock = clock;
    }

    Issued begin(String email, String name, String organization, String passwordHash) {
        String normalized = requireEmail(email);
        String displayName = requireName(name);
        String workspace = blankToNull(organization);
        replaceExisting(normalized);
        String code = Secrets.numericCode(otpLength);
        String token = Secrets.token();
        write(token, new Draft(normalized, displayName, workspace, passwordHash, Secrets.sha256(code), 0,
                clock.instant().toEpochMilli()), ttl);
        return new Issued(token, normalized, displayName, code);
    }

    /** The address this token is waiting on, or null when the hold has expired. */
    String address(String token) {
        Draft draft = read(token);
        return draft == null ? null : draft.email();
    }

    Issued resend(String token) {
        Draft draft = require(token);
        long sentAt = draft.sentAtEpochMs();
        if (sentAt > 0 && clock.instant().isBefore(Instant.ofEpochMilli(sentAt).plus(RESEND_COOLDOWN))) {
            throw ApiException.of(ErrorCode.RATE_LIMITED, "Wait a moment before requesting another code.");
        }
        String code = Secrets.numericCode(otpLength);
        write(token, new Draft(draft.email(), draft.name(), draft.organization(), draft.passwordHash(),
                Secrets.sha256(code), 0, clock.instant().toEpochMilli()), ttl);
        return new Issued(token, draft.email(), draft.name(), code);
    }

    /**
     * Checks the code. A match returns the held signup and leaves it in Redis until
     * {@link #discard}. A mismatch keeps the same hold and the same expiry.
     */
    Draft match(String token, String code) {
        Draft draft = require(token);
        if (code == null || !Secrets.constantTimeEquals(draft.otpHash(), Secrets.sha256(code.trim()))) {
            int attempts = draft.attempts() + 1;
            if (attempts >= maxAttempts) {
                discard(token);
                throw ApiException.of(ErrorCode.OTP_ATTEMPTS_EXCEEDED,
                        "Too many attempts. Start again.");
            }
            long left = cache.secondsLeft(key(token));
            if (left <= 0) {
                discard(token);
                throw expired();
            }
            write(token, new Draft(draft.email(), draft.name(), draft.organization(), draft.passwordHash(),
                    draft.otpHash(), attempts, draft.sentAtEpochMs()), Duration.ofSeconds(left));
            throw ApiException.of(ErrorCode.OTP_INVALID, "That code is not correct");
        }
        return draft;
    }

    void discard(String token) {
        if (token == null || !TOKEN.matcher(token).matches()) {
            return;
        }
        Draft draft = read(token);
        if (draft == null) {
            cache.delete(key(token));
            return;
        }
        cache.delete(key(token), emailKey(draft.email()));
    }

    private void replaceExisting(String email) {
        String previous = cache.get(emailKey(email));
        if (previous != null && TOKEN.matcher(previous).matches()) {
            cache.delete(key(previous), emailKey(email));
        }
    }

    private void write(String token, Draft draft, Duration life) {
        Duration bounded = life.isZero() || life.isNegative() ? Duration.ofSeconds(1) : life;
        cache.put(key(token), encode(draft), bounded);
        cache.put(emailKey(draft.email()), token, bounded);
    }

    private Draft require(String token) {
        Draft draft = read(token);
        if (draft == null) {
            throw expired();
        }
        return draft;
    }

    private Draft read(String token) {
        if (token == null || !TOKEN.matcher(token).matches()) {
            return null;
        }
        String raw = cache.get(key(token));
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return decode(raw);
        } catch (IllegalArgumentException ex) {
            cache.delete(key(token));
            return null;
        }
    }

    private static String key(String token) {
        return PREFIX + token;
    }

    private static String emailKey(String email) {
        return EMAIL_PREFIX + Secrets.sha256(email);
    }

    private static ApiException expired() {
        return ApiException.of(ErrorCode.OTP_EXPIRED, "That code has expired. Start again.");
    }

    private static String requireEmail(String email) {
        String normalized = Emails.normalize(email);
        if (normalized == null || normalized.isBlank() || !normalized.contains("@")) {
            throw ApiException.of(ErrorCode.VALIDATION_FAILED, "Enter an email address.");
        }
        return normalized;
    }

    private static String requireName(String name) {
        if (name == null || name.isBlank()) {
            throw ApiException.of(ErrorCode.VALIDATION_FAILED, "Enter your name.");
        }
        String trimmed = name.trim().replace(SEP, ' ');
        if (trimmed.length() > 160) {
            throw ApiException.of(ErrorCode.VALIDATION_FAILED, "Name must be at most 160 characters.");
        }
        return trimmed;
    }

    private static String blankToNull(String organization) {
        if (organization == null || organization.isBlank()) {
            return null;
        }
        String trimmed = organization.trim().replace(SEP, ' ');
        if (trimmed.length() > 200) {
            throw ApiException.of(ErrorCode.VALIDATION_FAILED, "Workspace name must be at most 200 characters.");
        }
        return trimmed;
    }

    private static String encode(Draft draft) {
        return String.join(String.valueOf(SEP),
                draft.email(),
                draft.name(),
                draft.organization() == null ? "" : draft.organization(),
                draft.passwordHash(),
                draft.otpHash(),
                Integer.toString(draft.attempts()),
                Long.toString(draft.sentAtEpochMs()));
    }

    private static Draft decode(String raw) {
        String[] parts = raw.split(String.valueOf(SEP), -1);
        if (parts.length != 7) {
            throw new IllegalArgumentException("signup record is incomplete");
        }
        String organization = parts[2].isEmpty() ? null : parts[2];
        return new Draft(parts[0], parts[1], organization, parts[3], parts[4],
                Integer.parseInt(parts[5]), Long.parseLong(parts[6]));
    }

    record Draft(String email, String name, String organization, String passwordHash, String otpHash,
                 int attempts, long sentAtEpochMs) {
    }

    record Issued(String token, String email, String name, String code) {
    }
}
