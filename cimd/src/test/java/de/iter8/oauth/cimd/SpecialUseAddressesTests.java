package de.iter8.oauth.cimd;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SpecialUseAddressesTests {

    @ParameterizedTest
    @ValueSource(strings = {
            "0.0.0.0", "0.1.2.3",                        // "this network"
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1",
            "169.254.169.254",                           // cloud instance metadata
            "100.64.0.1", "192.0.0.8", "192.0.2.1", "198.18.0.1", "240.0.0.1", "255.255.255.255",
            "::1", "fd00::1", "fe80::1", "2001:db8::1",
            "::ffff:169.254.169.254",                    // IPv4-mapped
            "64:ff9b::a9fe:a9fe",                        // NAT64 to 169.254.169.254
            "64:ff9b::a00:1",                            // NAT64 to 10.0.0.1
            "64:ff9b:1::1",                              // local-use NAT64
            "2002:a9fe:a9fe::1",                         // 6to4 via 169.254.169.254
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",      // Teredo
            "100::1",                                    // discard-only
    })
    void refusesSpecialUseAddresses(String address) throws UnknownHostException {
        assertThat(SpecialUseAddresses.isSpecialUse(InetAddress.getByName(address))).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "93.184.215.14",                             // a public IPv4 address
            "2606:4700:4700::1111",                      // a public IPv6 address
            "64:ff9b::5db8:d70e",                        // NAT64 to the public 93.184.215.14
            "2002:5db8:d70e::1",                         // 6to4 via the public 93.184.215.14
    })
    void allowsPublicAddresses(String address) throws UnknownHostException {
        assertThat(SpecialUseAddresses.isSpecialUse(InetAddress.getByName(address))).isFalse();
    }
}
