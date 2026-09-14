package com.prabhix.identity.user;

import com.prabhix.identity.user.IdentityUser.UserStatus;
import com.prabhix.identity.web.KeysetCursor;
import com.prabhix.identity.web.KeysetCursor.Position;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Admin search over {@code users}: text, status, keyset cursor.
 *
 * <p>Soft-deleted rows are excluded. Disabled ones are not — an operator looking for the account
 * they just turned off has to be able to find it.
 */
@Component
public class UserAdminQueries {

    private final EntityManager em;

    public UserAdminQueries(EntityManager em) {
        this.em = em;
    }

    public Result search(String query, UserStatus status, String cursor, int limit) {
        CriteriaBuilder cb = em.getCriteriaBuilder();

        CriteriaQuery<IdentityUser> select = cb.createQuery(IdentityUser.class);
        Root<IdentityUser> root = select.from(IdentityUser.class);
        select.where(predicates(cb, root, query, status, cursor).toArray(Predicate[]::new));
        select.orderBy(cb.desc(root.get("createdAt")), cb.desc(root.get("id")));

        TypedQuery<IdentityUser> typed = em.createQuery(select);
        typed.setMaxResults(limit + 1);
        List<IdentityUser> fetched = typed.getResultList();

        boolean more = fetched.size() > limit;
        List<IdentityUser> page = more ? fetched.subList(0, limit) : fetched;
        String next = null;
        if (more && !page.isEmpty()) {
            IdentityUser last = page.get(page.size() - 1);
            next = KeysetCursor.encode(last.getCreatedAt(), last.getId());
        }
        return new Result(page, next, count(query, status));
    }

    private long count(String query, UserStatus status) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Long> select = cb.createQuery(Long.class);
        Root<IdentityUser> root = select.from(IdentityUser.class);
        select.select(cb.count(root));
        select.where(predicates(cb, root, query, status, null).toArray(Predicate[]::new));
        return em.createQuery(select).getSingleResult();
    }

    private static List<Predicate> predicates(CriteriaBuilder cb,
                                              Root<IdentityUser> root,
                                              String query,
                                              UserStatus status,
                                              String cursor) {
        List<Predicate> predicates = new ArrayList<>();
        predicates.add(cb.isNull(root.get("deletedAt")));
        if (status != null) {
            predicates.add(cb.equal(root.get("status"), status));
        }
        if (query != null && !query.isBlank()) {
            String pattern = "%" + query.trim().toLowerCase(Locale.ROOT) + "%";
            predicates.add(cb.or(
                    cb.like(root.get("email"), pattern),
                    cb.like(cb.lower(root.get("fullName")), pattern)));
        }
        if (cursor != null && !cursor.isBlank()) {
            Position position = KeysetCursor.decode(cursor);
            predicates.add(cb.or(
                    cb.lessThan(root.get("createdAt"), position.time()),
                    cb.and(
                            cb.equal(root.get("createdAt"), position.time()),
                            cb.lessThan(root.get("id"), position.id()))));
        }
        return predicates;
    }

    public record Result(List<IdentityUser> items, String nextCursor, long total) {
    }
}
