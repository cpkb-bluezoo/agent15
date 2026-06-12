/*
 * Copyright © 2023, 2024, 2025, 2026 Peter Doornbosch
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

import at.favre.lib.hkdf.HKDF;
import org.junit.jupiter.api.Test;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.util.ByteUtils;
import tech.kwik.agent15.util.FieldGetter;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class TlsStateTest {

    @Test
    void testHdkfExtractUsedByTlsStateForRegression() {
        // Given
        TlsState tlsState = new TlsState(mock(TranscriptHash.class), 16, 32);
        HKDF hkdf = (HKDF) FieldGetter.getField(tlsState, "hkdf");

        // When
        byte[] result = hkdf.extract(new byte[32], ByteUtils.hexToBytes("9dec754406f9f8e7f301ebe9760c8086535470a1bac71f6204131c0dc7510d6f"));

        // Then
        assertThat(result).isEqualTo(ByteUtils.hexToBytes("e3f46a201b376e967810653508d1a41d3b37340221a193188d1fd81f9819ac98"));
    }

    @Test
    void testHdkfExpandUsedByTlsStateForRegression() {
        // Given
        TlsState tlsState = new TlsState(mock(TranscriptHash.class), 16, 32);
        HKDF hkdf = (HKDF) FieldGetter.getField(tlsState, "hkdf");

        // When
        byte[] result = hkdf.expand(ByteUtils.hexToBytes("9dec754406f9f8e7f301ebe9760c8086535470a1bac71f6204131c0dc7510d6f"), "some derivation".getBytes(StandardCharsets.UTF_8), 32);

        // Then
        assertThat(result).isEqualTo(ByteUtils.hexToBytes("0bd79c1626379ee8b7704a25406f03202cb6dff67e6236ce2308711d83539530"));
    }

    @Test
    void x25519LowOrderPointShouldNotProduceAllZeroSharedSecret() throws Exception {
        // Given
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        kpg.initialize(new NamedParameterSpec("X25519"));
        KeyPair clientKeyPair = kpg.generateKeyPair();

        // u=325606... is a torsion point of order 4: X25519(k, u) = 0 for any scalar k
        KeyFactory kf = KeyFactory.getInstance("XDH");
        BigInteger torsionU = new BigInteger("39382357235489614581723060781553021112529911719440698176882885853963445705823");
        PublicKey lowOrderPoint = kf.generatePublic(new XECPublicKeySpec(new NamedParameterSpec("X25519"), torsionU));

        TlsState tlsState = new TlsState(new TranscriptHash(32), null, 16, 32);
        tlsState.setOwnKey(clientKeyPair.getPrivate());
        tlsState.setPeerKey(lowOrderPoint);

        assertThatThrownBy(() ->
                // When
                tlsState.computeSharedSecret()
                // Then
        ).isInstanceOf(IllegalParameterAlert.class);
    }
}