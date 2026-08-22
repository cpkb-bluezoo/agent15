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
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.util.ByteUtils;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ECKeyExchangeTest {

    private static final String CLIENT_KEY_EXCHANGE_DATA =
            "04"
            + "5d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d40439"
            + "9d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda";

    private static final String SERVER_KEY_EXCHANGE_DATA =
            "04"
            + "ace3b035eba5dd75860925b2c9b206656f2d1590f8c596d96a2a91adb442b378"
            + "240002c8ef8360ba6104033c02eb3ab9ebcce036c735892697dda158f91c786e";

    private ECKeyExchange ecKeyExchange;

    @BeforeEach
    void initObjectUnderTest() {
        ecKeyExchange = new ECKeyExchange(TlsConstants.NamedGroup.secp256r1);
    }

    @Test
    void parseClientKeyShareExtractsAffineCoordinates() throws Exception {
        byte[] data = ByteUtils.hexToBytes(CLIENT_KEY_EXCHANGE_DATA);

        // When
        ECPublicKey ecPublicKey = ecKeyExchange.parseClientKeyShare(data);

        // Then: the X coordinate is the first half and the Y coordinate the second half of the point representation.
        assertThat(ecPublicKey.getW().getAffineX())
                .isEqualTo(new BigInteger("5d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d40439", 16));
        assertThat(ecPublicKey.getW().getAffineY())
                .isEqualTo(new BigInteger("9d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda", 16));
    }

    @Test
    void parsedKeyUsesSecp256r1DomainParameters() throws Exception {
        byte[] data = ByteUtils.hexToBytes(CLIENT_KEY_EXCHANGE_DATA);

        // When
        ECPublicKey ecPublicKey = ecKeyExchange.parseClientKeyShare(data);

        // Then
        assertThat(ecPublicKey.getParams().getCurve())
                .isEqualTo(ECKeyExchange.ecParameterSpecForCurve("secp256r1").getCurve());
        assertThat(ecPublicKey.getParams().getCurve().getField().getFieldSize()).isEqualTo(256);
    }

    @Test
    void parseKeyShareThatIsNotInLegacyFormThrows() {
        // Replace the legacy_form header byte (4) by the header byte of a compressed point.
        byte[] data = ByteUtils.hexToBytes(CLIENT_KEY_EXCHANGE_DATA);
        data[0] = 3;

        ECKeyExchange keyExchange = ecKeyExchange;

        assertThatThrownBy(() -> keyExchange.parseClientKeyShare(data))
                .hasMessageContaining("legacy form");
    }

    @Test
    void parseKeyShareThatIsTooShortThrows() {
        // One byte short of a complete uncompressed point representation.
        byte[] data = Arrays.copyOf(ByteUtils.hexToBytes(CLIENT_KEY_EXCHANGE_DATA), 64);

        assertThatThrownBy(() -> ecKeyExchange.parseClientKeyShare(data))
                .isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseEmptyKeyShareThrows() {
        assertThatThrownBy(() -> ecKeyExchange.parseClientKeyShare(new byte[0]))
                .isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseKeyShareThatIsTooLongThrows() {
        byte[] data = Arrays.copyOf(ByteUtils.hexToBytes(CLIENT_KEY_EXCHANGE_DATA), 66);

        assertThatThrownBy(() -> ecKeyExchange.parseClientKeyShare(data))
                .isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void creatingKeyExchangeForNonEcGroupThrows() {
        assertThatThrownBy(() -> new ECKeyExchange(TlsConstants.NamedGroup.x25519))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ECKeyExchange(TlsConstants.NamedGroup.ffdhe2048))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void serializeCreatesUncompressedPointRepresentation() throws Exception {
        ECPublicKey publicKey = ecKeyExchange.parseClientKeyShare(ByteUtils.hexToBytes(SERVER_KEY_EXCHANGE_DATA));

        // When
        byte[] serialized = ecKeyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(SERVER_KEY_EXCHANGE_DATA));
    }

    @Test
    void serializeLeftPadsAffineCoordinatesThatAreLessThan32Bytes() {
        ECPublicKey publicKey = keyWithCoordinates(BigInteger.ONE, BigInteger.valueOf(2));

        // When
        byte[] serialized = ecKeyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(
                "04" + "00".repeat(31) + "01" + "00".repeat(31) + "02"));
    }

    @Test
    void serializeStripsLeadingZeroFromAffineCoordinatesOf33Bytes() {
        // A coordinate with the most significant bit set leads to a 33 byte two's complement representation.
        ECPublicKey publicKey = keyWithCoordinates(BigInteger.ONE.shiftLeft(255), BigInteger.ONE);

        // When
        byte[] serialized = ecKeyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(
                "04" + "80" + "00".repeat(31) + "00".repeat(31) + "01"));
    }

    @Test
    void serializeAffineCoordinateThatDoesNotFitIn32BytesThrows() {
        ECPublicKey publicKey = keyWithCoordinates(BigInteger.ONE.shiftLeft(256), BigInteger.ONE);

        assertThatThrownBy(() -> ecKeyExchange.serialize(publicKey))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void serializeForUnsupportedGroupThrows() {
        ECKeyExchange keyExchange = new ECKeyExchange(TlsConstants.NamedGroup.secp384r1);

        assertThatThrownBy(() -> keyExchange.serialize(mock(ECPublicKey.class)))
                .hasMessageContaining("unsupported group");
    }

    @Test
    void ecParameterSpecIsAvailableForAllSupportedCurves() {
        assertThat(ECKeyExchange.ecParameterSpecForCurve("secp256r1").getCurve().getField().getFieldSize()).isEqualTo(256);
        assertThat(ECKeyExchange.ecParameterSpecForCurve("secp384r1").getCurve().getField().getFieldSize()).isEqualTo(384);
        assertThat(ECKeyExchange.ecParameterSpecForCurve("secp521r1").getCurve().getField().getFieldSize()).isEqualTo(521);
    }

    /**
     * Creates a public key with the given affine coordinates; a mock is used because coordinates that are not on the
     * curve cannot be turned into a real key.
     */
    private ECPublicKey keyWithCoordinates(BigInteger x, BigInteger y) {
        ECPublicKey publicKey = mock(ECPublicKey.class);
        when(publicKey.getW()).thenReturn(new ECPoint(x, y));
        return publicKey;
    }
}
