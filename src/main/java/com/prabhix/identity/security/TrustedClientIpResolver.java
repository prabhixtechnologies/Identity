package com.prabhix.identity.security;

import com.prabhix.identity.config.IdentityProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * Resolves the client IP for rate limiting and audit rows.
 *
 * <p>{@code X-Forwarded-For} is honoured only when the immediate peer is a configured trusted proxy.
 * Otherwise {@code getRemoteAddr()} is used, so a client cannot pick its own address by forging the
 * header.
 */
@Component
public class TrustedClientIpResolver {

    private static final int IP_MAX = 45;

    private final List<Cidr> trusted;

    public TrustedClientIpResolver(IdentityProperties properties) {
        this.trusted = parse(properties.trustedProxy().trustedCidrs());
    }

    public String resolve(HttpServletRequest request) {
        String peer = request.getRemoteAddr();
        if (peer != null && isTrustedPeer(peer)) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                return truncate(forwarded.split(",")[0].trim(), IP_MAX);
            }
        }
        return truncate(peer, IP_MAX);
    }

    private boolean isTrustedPeer(String address) {
        byte[] bytes = toBytes(address);
        if (bytes == null) {
            return false;
        }
        for (Cidr cidr : trusted) {
            if (cidr.contains(bytes)) {
                return true;
            }
        }
        return false;
    }

    private static List<Cidr> parse(List<String> cidrs) {
        if (cidrs == null || cidrs.isEmpty()) {
            return List.of();
        }
        List<Cidr> parsed = new ArrayList<>();
        for (String raw : cidrs) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            parsed.add(Cidr.parse(raw.trim()));
        }
        return List.copyOf(parsed);
    }

    private static byte[] toBytes(String host) {
        try {
            return InetAddress.getByName(host).getAddress();
        } catch (UnknownHostException ex) {
            return null;
        }
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

    private record Cidr(byte[] network, int prefixLength) {

        static Cidr parse(String value) {
            String[] parts = value.split("/");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid CIDR: " + value);
            }
            byte[] network = toBytes(parts[0]);
            if (network == null) {
                throw new IllegalArgumentException("Invalid CIDR address: " + value);
            }
            int prefix = Integer.parseInt(parts[1]);
            if (prefix < 0 || prefix > network.length * 8) {
                throw new IllegalArgumentException("Invalid CIDR prefix: " + value);
            }
            return new Cidr(network, prefix);
        }

        boolean contains(byte[] address) {
            if (address.length != network.length) {
                return false;
            }
            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;
            for (int i = 0; i < fullBytes; i++) {
                if (address[i] != network[i]) {
                    return false;
                }
            }
            if (remainingBits == 0) {
                return true;
            }
            int mask = 0xFF << (8 - remainingBits);
            return (address[fullBytes] & mask) == (network[fullBytes] & mask);
        }
    }
}
