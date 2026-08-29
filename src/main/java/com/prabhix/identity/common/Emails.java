package com.prabhix.identity.common;

import java.util.Locale;

/**
 * The one place an email address is folded to its canonical form.
 *
 * <p>Every address is stored and compared lowercase. That has to be enforced in Java rather than
 * left to the {@code citext} columns, because {@code citext} does not survive the JDBC round trip:
 * pgjdbc binds a {@code String} as {@code varchar}, and PostgreSQL resolves {@code citext = varchar}
 * to {@code text = text} — {@code text} being the preferred type in the string category — so the
 * comparison comes back case-sensitive. Uniqueness still behaves, because the unique index compares
 * two {@code citext} values with no parameter involved. The result is the worst possible split:
 * {@code Owner@x.com} cannot be registered twice, but looking it up finds nothing.
 *
 * <p>So {@code citext} stays as a database-level guard against two rows differing only by case —
 * worth having for the import scripts and psql sessions that bypass this code — and everything
 * inside the service normalizes first, which also keeps lookups on the unique index instead of
 * pushing them onto {@code lower(email)}.
 */
public final class Emails {

    private Emails() {
    }

    /**
     * Trims and lowercases, null in and null out.
     *
     * <p>{@link Locale#ROOT} is not incidental: under a Turkish default locale
     * {@code "I".toLowerCase()} is {@code "ı"}, so a server started with {@code -Duser.language=tr}
     * would quietly stop finding any address containing a capital I.
     */
    public static String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
