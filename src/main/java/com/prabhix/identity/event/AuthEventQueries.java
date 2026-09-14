package com.prabhix.identity.event;

import com.prabhix.identity.web.KeysetCursor;
import com.prabhix.identity.web.KeysetCursor.Position;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Paged reads of {@code auth_events} that a derived query cannot express.
 *
 * <p>The admin console walks newest-first with optional filters, and the cursor is a keyset of
 * {@code (occurred_at, id)} rather than an offset so a row written during the walk cannot shift the
 * next page.
 */
@Component
public class AuthEventQueries {

    private final EntityManager em;

    public AuthEventQueries(EntityManager em) {
        this.em = em;
    }

    public Result search(UUID userId, AuthEventType type, Instant since, String cursor, int limit) {
        CriteriaBuilder cb = em.getCriteriaBuilder();

        CriteriaQuery<AuthEventRecord> query = cb.createQuery(AuthEventRecord.class);
        Root<AuthEventRecord> root = query.from(AuthEventRecord.class);
        query.where(predicates(cb, root, userId, type, since, cursor).toArray(Predicate[]::new));
        query.orderBy(cb.desc(root.get("occurredAt")), cb.desc(root.get("id")));

        TypedQuery<AuthEventRecord> typed = em.createQuery(query);
        typed.setMaxResults(limit + 1);
        List<AuthEventRecord> fetched = typed.getResultList();

        boolean more = fetched.size() > limit;
        List<AuthEventRecord> page = more ? fetched.subList(0, limit) : fetched;
        String next = null;
        if (more && !page.isEmpty()) {
            AuthEventRecord last = page.get(page.size() - 1);
            next = KeysetCursor.encode(last.getOccurredAt(), last.getId());
        }
        return new Result(page, next, count(userId, type, since));
    }

    private long count(UUID userId, AuthEventType type, Instant since) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Long> query = cb.createQuery(Long.class);
        Root<AuthEventRecord> root = query.from(AuthEventRecord.class);
        query.select(cb.count(root));
        query.where(predicates(cb, root, userId, type, since, null).toArray(Predicate[]::new));
        return em.createQuery(query).getSingleResult();
    }

    private static List<Predicate> predicates(CriteriaBuilder cb,
                                              Root<AuthEventRecord> root,
                                              UUID userId,
                                              AuthEventType type,
                                              Instant since,
                                              String cursor) {
        List<Predicate> predicates = new ArrayList<>();
        if (userId != null) {
            predicates.add(cb.equal(root.get("userId"), userId));
        }
        if (type != null) {
            predicates.add(cb.equal(root.get("type"), type));
        }
        if (since != null) {
            predicates.add(cb.greaterThanOrEqualTo(root.get("occurredAt"), since));
        }
        if (cursor != null && !cursor.isBlank()) {
            Position position = KeysetCursor.decode(cursor);
            predicates.add(cb.or(
                    cb.lessThan(root.get("occurredAt"), position.time()),
                    cb.and(
                            cb.equal(root.get("occurredAt"), position.time()),
                            cb.lessThan(root.get("id"), position.id()))));
        }
        return predicates;
    }

    public record Result(List<AuthEventRecord> items, String nextCursor, long total) {
    }
}
