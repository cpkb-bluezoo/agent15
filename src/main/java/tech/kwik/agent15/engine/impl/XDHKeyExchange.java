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

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.engine.KeyExchange;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.Map;

import static tech.kwik.agent15.TlsConstants.NamedGroup.x25519;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x448;

/**
 * Implementation of the X25519 and X448 key exchange algorithms.
 */
public class XDHKeyExchange implements KeyExchange {

    /**
     * The length of the key exchange data, see https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8.2
     */
    private static final Map<TlsConstants.NamedGroup, Integer> CURVE_KEY_LENGTHS = Map.of(
            x25519, 32,
            x448, 56
    );

    private TlsConstants.NamedGroup namedGroup;

    public XDHKeyExchange(TlsConstants.NamedGroup namedGroup) {
        if (namedGroup == x25519 || namedGroup == x448) {
            this.namedGroup = namedGroup;
        }
        else {
            throw new IllegalArgumentException("unsupported group " + namedGroup);
        }
    }

    @Override
    public void generateClientKeyPair() {
    }

    @Override
    public byte[] getClientKeyShare() {
        return new byte[0];
    }

    @Override
    public byte[] clientComputeSharedSecret(byte[] serverKeyShare) throws IllegalParameterAlert {
        return new byte[0];
    }

    @Override
    public byte[] serverProcessClientKeyShare(byte[] clientKeyShare) throws IllegalParameterAlert {
        return new byte[0];
    }

    XECPublicKey parseClientKeyShare(byte[] keyExchangeData) throws IllegalParameterAlert {
        return rawToEncodedXDHPublicKey(namedGroup, keyExchangeData);
    }

    @Override
    public byte[] getServerKeyShare() {
        return new byte[0];
    }

    byte[] serialize(XECPublicKey key) {
        byte[] raw = key.getU().toByteArray();
        if (raw.length > CURVE_KEY_LENGTHS.get(namedGroup)) {
            throw new RuntimeException("Invalid " + namedGroup + " key length: " + raw.length);
        }
        if (raw.length < CURVE_KEY_LENGTHS.get(namedGroup)) {
            // Must pad with leading zeros, but as the encoding is little endian, it is easier to first reverse...
            reverse(raw);
            // ... and than pad with zeroes up to the required ledngth
            byte[] padded = Arrays.copyOf(raw, CURVE_KEY_LENGTHS.get(namedGroup));
            raw = padded;
        }
        else {
            // Encoding is little endian, so reverse the bytes.
            reverse(raw);
        }
        return raw;
    }

    static private XECPublicKey rawToEncodedXDHPublicKey(TlsConstants.NamedGroup curve, byte[] keyData) {
        try {
            // Encoding is little endian, so reverse the bytes.
            reverse(keyData);
            BigInteger u = new BigInteger(1, keyData);
            KeyFactory kf = KeyFactory.getInstance("XDH");
            NamedParameterSpec paramSpec = new NamedParameterSpec(curve.name().toUpperCase());
            XECPublicKeySpec pubSpec = new XECPublicKeySpec(paramSpec, u);
            return (XECPublicKey) kf.generatePublic(pubSpec);
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing support for EC algorithm");
        }
        catch (InvalidKeySpecException e) {
            throw new RuntimeException("Inappropriate parameter specification");
        }
    }

    private static void reverse(byte[] array) {
        if (array == null) {
            return;
        }
        int i = 0;
        int j = array.length - 1;
        byte tmp;
        while (j > i) {
            tmp = array[j];
            array[j] = array[i];
            array[i] = tmp;
            j--;
            i++;
        }
    }
}
