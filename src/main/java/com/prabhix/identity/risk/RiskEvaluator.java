package com.prabhix.identity.risk;

import org.springframework.stereotype.Component;

/**
 * Built-in risk rules. No external scorer.
 *
 * <p>A move onto a different network on a staff session asks for a fresh passkey or one-time code.
 * Addresses in the same IPv4 /24 or IPv6 /64 are the same network: a home router or a phone that
 * only changes the host part must not interrupt a working sign-in. The same change for everyone
 * else is allowed either way. Mobile networks renumber too often to make that a sign-out.
 */
@Component
public class RiskEvaluator {

    /**
     * A device this account has not used before. The sign-in that opened it is the proof, so the
     * session is allowed. Callers still record it: that record is how a new laptop shows up later.
     */
    public Decision newDevice() {
        return Decision.ALLOW;
    }

    public Decision networkChange(boolean staff, String previousIp, String currentIp) {
        if (previousIp == null || previousIp.isBlank()
                || currentIp == null || currentIp.isBlank()
                || sameNetwork(previousIp, currentIp)) {
            return Decision.ALLOW;
        }
        return staff ? Decision.STEP_UP : Decision.ALLOW;
    }

    /**
     * Two literals share a network when their stable prefix matches. An address that is not a
     * literal is a different network, so a staff session still asks for a fresh proof.
     */
    static boolean sameNetwork(String previousIp, String currentIp) {
        if (previousIp.equals(currentIp)) {
            return true;
        }
        byte[] previous = literal(previousIp);
        byte[] current = literal(currentIp);
        if (previous == null || current == null || previous.length != current.length) {
            return false;
        }
        int prefixBytes = previous.length == 4 ? 3 : 8;
        for (int i = 0; i < prefixBytes; i++) {
            if (previous[i] != current[i]) {
                return false;
            }
        }
        return true;
    }

    private static byte[] literal(String value) {
        String ip = value.trim();
        int zone = ip.indexOf('%');
        if (zone >= 0) {
            ip = ip.substring(0, zone);
        }
        if (ip.startsWith("[") && ip.endsWith("]") && ip.length() > 2) {
            ip = ip.substring(1, ip.length() - 1);
        }
        byte[] parsed = ip.indexOf(':') >= 0 ? ipv6(ip) : ipv4(ip);
        return parsed == null ? null : unmap(parsed);
    }

    /** IPv4-mapped IPv6 ({@code ::ffff:a.b.c.d}) is the same address as the dotted form. */
    private static byte[] unmap(byte[] address) {
        if (address.length != 16) {
            return address;
        }
        for (int i = 0; i < 10; i++) {
            if (address[i] != 0) {
                return address;
            }
        }
        if (address[10] != (byte) 0xff || address[11] != (byte) 0xff) {
            return address;
        }
        byte[] v4 = new byte[4];
        System.arraycopy(address, 12, v4, 0, 4);
        return v4;
    }

    private static byte[] ipv4(String ip) {
        String[] parts = ip.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            String part = parts[i];
            if (part.isEmpty() || part.length() > 3) {
                return null;
            }
            int value = 0;
            for (int c = 0; c < part.length(); c++) {
                char ch = part.charAt(c);
                if (ch < '0' || ch > '9') {
                    return null;
                }
                value = value * 10 + (ch - '0');
            }
            if (value > 255) {
                return null;
            }
            out[i] = (byte) value;
        }
        return out;
    }

    private static byte[] ipv6(String ip) {
        int lastColon = ip.lastIndexOf(':');
        if (lastColon >= 0 && ip.indexOf('.', lastColon) > lastColon) {
            byte[] tail = ipv4(ip.substring(lastColon + 1));
            if (tail == null) {
                return null;
            }
            ip = ip.substring(0, lastColon + 1) + String.format("%02x%02x:%02x%02x",
                    tail[0] & 0xff, tail[1] & 0xff, tail[2] & 0xff, tail[3] & 0xff);
        }
        if (ip.indexOf(":::") >= 0) {
            return null;
        }
        String[] halves = ip.split("::", -1);
        if (halves.length > 2) {
            return null;
        }
        int[] head = groups(halves[0]);
        int[] tail = halves.length == 2 ? groups(halves[1]) : new int[0];
        if (head == null || tail == null) {
            return null;
        }
        int present = head.length + tail.length;
        if (halves.length == 1) {
            if (present != 8) {
                return null;
            }
        } else if (present > 7) {
            return null;
        }
        byte[] out = new byte[16];
        int index = writeGroups(out, 0, head);
        index += (8 - present) * 2;
        writeGroups(out, index, tail);
        return out;
    }

    private static int[] groups(String side) {
        if (side.isEmpty()) {
            return new int[0];
        }
        String[] parts = side.split(":", -1);
        int[] out = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            if (part.isEmpty() || part.length() > 4) {
                return null;
            }
            int value = 0;
            for (int c = 0; c < part.length(); c++) {
                int digit = Character.digit(part.charAt(c), 16);
                if (digit < 0) {
                    return null;
                }
                value = (value << 4) | digit;
            }
            out[i] = value;
        }
        return out;
    }

    private static int writeGroups(byte[] out, int index, int[] groups) {
        for (int group : groups) {
            out[index++] = (byte) (group >> 8);
            out[index++] = (byte) group;
        }
        return index;
    }

    public enum Decision {
        ALLOW, STEP_UP
    }
}
