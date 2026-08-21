/*
 * Copyright © 2026 Peter Doornbosch, Chris Burdess
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
package tech.kwik.agent15.engine;

import tech.kwik.agent15.alert.IllegalParameterAlert;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * ML-KEM-768 key exchange (FIPS 203), using the JDK's own KEM API
 * (java.security.KEM), whose ML-KEM implementation was finalized in JDK 25.
 * Used both standalone (should a pure ML-KEM group ever be needed) and as
 * the post-quantum half of the hybrid groups defined in RFC 10024.
 *
 * <p>The JDK only exposes ML-KEM keys as X.509/PKCS#8-encoded PublicKey/
 * PrivateKey objects; there is no supported API to obtain or reconstruct
 * the raw encapsulation-key bytes the TLS key_share extension actually
 * carries (the concrete implementation class does have a getRawBytes()
 * method, but it is on the internal sun.security.x509.NamedX509Key, not
 * on any exported interface, so it is not used here). Instead, the fixed
 * DER envelope around the raw key is stripped/rebuilt using only the
 * standard PublicKey/KeyFactory/X509EncodedKeySpec API. The envelope
 * bytes are derived once from a throwaway key pair rather than
 * hardcoded, so they can't silently drift from whatever this JVM's
 * provider actually produces.
 *
 * <p>The ciphertext (KEM.Encapsulated#encapsulation()) and shared secret
 * (KEM.Encapsulated#key()/KEM.Decapsulator's result, both symmetric
 * SecretKeys) need no such handling: their getEncoded() already returns
 * raw bytes with no ASN.1 wrapping.
 */
public class MLKEM768KeyExchange implements KeyExchange {

    public static final String ALGORITHM = "ML-KEM-768";
    public static final int ENCAPSULATION_KEY_LENGTH = 1184;
    public static final int CIPHERTEXT_LENGTH = 1088;
    public static final int SHARED_SECRET_LENGTH = 32;

    private static final byte[] PUBLIC_KEY_DER_PREFIX = computePublicKeyDerPrefix();

    private static byte[] computePublicKeyDerPrefix() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            byte[] encoded = keyPairGenerator.generateKeyPair().getPublic().getEncoded();
            return Arrays.copyOfRange(encoded, 0, encoded.length - ENCAPSULATION_KEY_LENGTH);
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("missing " + ALGORITHM + " support", e);
        }
    }

    private PrivateKey decapsulationKey;
    private PublicKey encapsulationKey;
    private byte[] serverKeyShare;

    @Override
    public void generateClientKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            decapsulationKey = keyPair.getPrivate();
            encapsulationKey = keyPair.getPublic();
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("missing " + ALGORITHM + " support", e);
        }
    }

    @Override
    public byte[] getClientKeyShare() {
        byte[] encoded = encapsulationKey.getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - ENCAPSULATION_KEY_LENGTH, encoded.length);
    }

    @Override
    public byte[] clientComputeSharedSecret(byte[] serverKeyShare) throws IllegalParameterAlert {
        if (serverKeyShare.length != CIPHERTEXT_LENGTH) {
            throw new IllegalParameterAlert("invalid " + ALGORITHM + " ciphertext length: " + serverKeyShare.length);
        }
        try {
            KEM kem = KEM.getInstance(ALGORITHM);
            KEM.Decapsulator decapsulator = kem.newDecapsulator(decapsulationKey);
            return decapsulator.decapsulate(serverKeyShare).getEncoded();
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("missing " + ALGORITHM + " support", e);
        }
        catch (InvalidKeyException e) {
            // decapsulationKey is our own, freshly generated key, not peer-controlled.
            throw new RuntimeException("invalid own " + ALGORITHM + " decapsulation key", e);
        }
        catch (DecapsulateException e) {
            throw new IllegalParameterAlert("invalid " + ALGORITHM + " ciphertext: " + e.getMessage());
        }
    }

    @Override
    public byte[] serverProcessClientKeyShare(byte[] clientKeyShare) throws IllegalParameterAlert {
        if (clientKeyShare.length != ENCAPSULATION_KEY_LENGTH) {
            throw new IllegalParameterAlert("invalid " + ALGORITHM + " encapsulation key length: " + clientKeyShare.length);
        }
        try {
            byte[] encoded = new byte[PUBLIC_KEY_DER_PREFIX.length + clientKeyShare.length];
            System.arraycopy(PUBLIC_KEY_DER_PREFIX, 0, encoded, 0, PUBLIC_KEY_DER_PREFIX.length);
            System.arraycopy(clientKeyShare, 0, encoded, PUBLIC_KEY_DER_PREFIX.length, clientKeyShare.length);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            PublicKey peerEncapsulationKey = keyFactory.generatePublic(new X509EncodedKeySpec(encoded));

            KEM kem = KEM.getInstance(ALGORITHM);
            KEM.Encapsulator encapsulator = kem.newEncapsulator(peerEncapsulationKey);
            KEM.Encapsulated encapsulated = encapsulator.encapsulate();
            serverKeyShare = encapsulated.encapsulation();
            return encapsulated.key().getEncoded();
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("missing " + ALGORITHM + " support", e);
        }
        catch (InvalidKeySpecException e) {
            throw new IllegalParameterAlert("invalid " + ALGORITHM + " encapsulation key encoding: " + e.getMessage());
        }
        catch (InvalidKeyException e) {
            throw new IllegalParameterAlert("invalid " + ALGORITHM + " encapsulation key: " + e.getMessage());
        }
    }

    @Override
    public byte[] getServerKeyShare() {
        if (serverKeyShare == null) {
            throw new IllegalStateException("serverProcessClientKeyShare() must be called before getServerKeyShare()");
        }
        return serverKeyShare;
    }
}
