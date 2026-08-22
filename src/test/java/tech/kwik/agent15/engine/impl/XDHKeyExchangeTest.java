/*
 * Copyright © 2026 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.engine.impl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.util.ByteUtils;

import java.math.BigInteger;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class XDHKeyExchangeTest {

    // RFC 7748 section 6.1, Alice's public key (little endian, as sent on the wire).
    private static final String X25519_KEY_EXCHANGE_DATA =
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

    private XDHKeyExchange xdhKeyExchange;

    @BeforeEach
    void initObjectUnderTest() {
        xdhKeyExchange = new XDHKeyExchange(TlsConstants.NamedGroup.x25519);
    }

    @Test
    void parseClientKeyShareInterpretsDataAsLittleEndian() throws Exception {
        byte[] data = ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA);

        // When
        XECPublicKey publicKey = xdhKeyExchange.parseClientKeyShare(data);

        // Then: u is the big endian value of the reversed byte string.
        assertThat(publicKey.getU())
                .isEqualTo(new BigInteger("6a4e9baa8ea9a4ebf41a38260d3abf0d5af73eb4dc7d8b7454a7308909f02085", 16));
    }

    @Test
    void parsedKeyUsesX25519DomainParameters() throws Exception {
        byte[] data = ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA);

        // When
        XECPublicKey publicKey = xdhKeyExchange.parseClientKeyShare(data);

        // Then: the named group is mapped to its uppercase JCA name.
        assertThat(((NamedParameterSpec) publicKey.getParams()).getName()).isEqualTo("X25519");
    }

    @Test
    void parseX448ClientKeyShare() throws Exception {
        // 56 bytes, little endian: u = 5
        byte[] data = ByteUtils.hexToBytes("05" + "00".repeat(55));

        // When
        XECPublicKey publicKey = new XDHKeyExchange(TlsConstants.NamedGroup.x448).parseClientKeyShare(data);

        // Then
        assertThat(publicKey.getU()).isEqualTo(BigInteger.valueOf(5));
        assertThat(((NamedParameterSpec) publicKey.getParams()).getName()).isEqualTo("X448");
    }

    @Test
    void parseClientKeyShareReversesTheGivenArray() throws Exception {
        byte[] data = ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA);

        // When
        xdhKeyExchange.parseClientKeyShare(data);

        // Then: note that the given array is reversed in place.
        assertThat(data).isEqualTo(ByteUtils.hexToBytes("6a4e9baa8ea9a4ebf41a38260d3abf0d5af73eb4dc7d8b7454a7308909f02085"));
    }

    @Test
    void creatingKeyExchangeForNonXdhGroupThrows() {
        assertThatThrownBy(() -> new XDHKeyExchange(TlsConstants.NamedGroup.secp256r1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void serializeCreatesLittleEndianRepresentation() throws Exception {
        XECPublicKey publicKey = xdhKeyExchange.parseClientKeyShare(ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA));

        // When
        byte[] serialized = xdhKeyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA));
    }

    @Test
    void serializePadsX25519KeyToKeyLength() {
        // u = 1, which is only one byte when represented as (big endian) integer.
        XECPublicKey publicKey = keyWithU(BigInteger.ONE);

        // When
        byte[] serialized = xdhKeyExchange.serialize(publicKey);

        // Then: little endian, padded with (trailing) zeros up to the key length.
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes("01" + "00".repeat(31)));
    }

    @Test
    void serializePadsX448KeyToKeyLength() {
        XECPublicKey publicKey = keyWithU(BigInteger.valueOf(5));

        // When
        byte[] serialized = new XDHKeyExchange(TlsConstants.NamedGroup.x448).serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes("05" + "00".repeat(55)));
    }

    @Test
    void serializeKeyThatDoesNotFitInKeyLengthThrows() {
        XECPublicKey publicKey = keyWithU(BigInteger.ONE.shiftLeft(256));

        assertThatThrownBy(() -> xdhKeyExchange.serialize(publicKey))
                .isInstanceOf(RuntimeException.class);
    }

    private XECPublicKey keyWithU(BigInteger u) {
        XECPublicKey publicKey = mock(XECPublicKey.class);
        when(publicKey.getU()).thenReturn(u);
        return publicKey;
    }
}
