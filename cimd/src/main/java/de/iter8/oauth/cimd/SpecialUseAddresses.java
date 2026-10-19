package de.iter8.oauth.cimd;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

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
 *
 * <p>Several IPv6 forms carry an IPv4 address inside them, and on a network that translates them they reach
 * that IPv4 address. Those are judged by the address they carry, or refused outright where it cannot be
 * recovered.
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

        // 0.0.0.0/8, "this network". Only 0.0.0.0 itself counts as the any-local address.
        if (first == 0) {
            return true;
        }
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
        // 64:ff9b::/96, the well-known NAT64 prefix: the last four bytes are the IPv4 address it reaches.
        if (startsWith(octets, 0x00, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0)) {
            return isSpecialUse(ipv4(octets, 12));
        }
        // 64:ff9b:1::/48, local-use NAT64, whose mapping is chosen by the network operator.
        if (startsWith(octets, 0x00, 0x64, 0xFF, 0x9B, 0x00, 0x01)) {
            return true;
        }
        // 2002::/16, 6to4: bytes 2 to 5 are the IPv4 address of the relay it tunnels to.
        if (startsWith(octets, 0x20, 0x02)) {
            return isSpecialUse(ipv4(octets, 2));
        }
        // 2001::/32, Teredo, which tunnels through IPv4 to an address that is obfuscated in the suffix.
        if (startsWith(octets, 0x20, 0x01, 0x00, 0x00)) {
            return true;
        }
        // 100::/64, discard-only.
        if (startsWith(octets, 0x01, 0x00, 0, 0, 0, 0, 0, 0)) {
            return true;
        }
        // ::/96, the deprecated IPv4-compatible form. (IPv4-mapped ::ffff:0:0/96 never gets here: Java
        // resolves it to an Inet4Address, which is judged as IPv4.)
        return address.isIPv4CompatibleAddress();
    }

    private static boolean startsWith(byte[] octets, int... prefix) {
        for (int i = 0; i < prefix.length; i++) {
            if ((octets[i] & 0xFF) != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static InetAddress ipv4(byte[] octets, int offset) {
        byte[] embedded = {octets[offset], octets[offset + 1], octets[offset + 2], octets[offset + 3]};
        try {
            return InetAddress.getByAddress(embedded);
        }
        catch (UnknownHostException impossible) {
            throw new IllegalStateException("Four bytes are always a valid IPv4 address", impossible);
        }
    }
}
