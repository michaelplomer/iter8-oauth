package de.iter8.oauth.cimd;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;

/**
 * Recognises the addresses an authorization server must refuse to fetch a client's metadata document from.
 *
 * <p>An authorization server that fetches a URL supplied by an unauthenticated caller is a request forgery
 * engine aimed at whatever it can reach: cloud instance metadata services, admin ports bound to localhost,
 * anything on the private network behind it. The specification therefore forbids fetching addresses in the
 * special-use registries, and this is the check that enforces it.
 *
 * <p>{@link InetAddress}'s own predicates cover most of the ground but not all of it: they do not know about
 * carrier-grade NAT, IETF protocol assignments, or the cloud metadata address that sits inside link-local
 * and is the single most valuable target of the class.
 */
public final class SpecialUseAddresses {

    private SpecialUseAddresses() {
    }

    /**
     * @param address a resolved address
     * @return whether fetching from it is forbidden
     */
    public static boolean isSpecialUse(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        if (address instanceof Inet4Address) {
            return isSpecialUseIpv4(address.getAddress());
        }
        if (address instanceof Inet6Address ipv6) {
            return isSpecialUseIpv6(ipv6);
        }
        return true;
    }

    private static boolean isSpecialUseIpv4(byte[] octets) {
        int first = octets[0] & 0xFF;
        int second = octets[1] & 0xFF;
        int third = octets[2] & 0xFF;

        // 100.64.0.0/10, carrier-grade NAT.
        if (first == 100 && second >= 64 && second <= 127) {
            return true;
        }
        // 192.0.0.0/24, IETF protocol assignments.
        if (first == 192 && second == 0 && third == 0) {
            return true;
        }
        // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24: documentation ranges.
        if (first == 192 && second == 0 && third == 2) {
            return true;
        }
        if (first == 198 && second == 51 && third == 100) {
            return true;
        }
        if (first == 203 && second == 0 && third == 113) {
            return true;
        }
        // 198.18.0.0/15, benchmarking.
        if (first == 198 && (second == 18 || second == 19)) {
            return true;
        }
        // 240.0.0.0/4, reserved, and 255.255.255.255.
        return first >= 240;
    }

    private static boolean isSpecialUseIpv6(Inet6Address address) {
        byte[] octets = address.getAddress();
        // fc00::/7, unique local addresses. Java does not treat these as site-local.
        if ((octets[0] & 0xFE) == 0xFC) {
            return true;
        }
        // 2001:db8::/32, documentation.
        if ((octets[0] & 0xFF) == 0x20 && (octets[1] & 0xFF) == 0x01
                && (octets[2] & 0xFF) == 0x0D && (octets[3] & 0xFF) == 0xB8) {
            return true;
        }
        // 64:ff9b::/96 and ::ffff:0:0/96 embed IPv4; judge the embedded address instead of the wrapper.
        if (address.isIPv4CompatibleAddress()) {
            return true;
        }
        return false;
    }
}
