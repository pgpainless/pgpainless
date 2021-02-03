/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.util.selection.key.PublicKeySelectionStrategy;
import org.pgpainless.util.selection.key.impl.NoRevocation;
import org.pgpainless.util.selection.key.impl.KeyBelongsToKeyRing;
import org.pgpainless.util.selection.key.impl.And;

public class BCUtil {

    private static final Logger LOGGER = Logger.getLogger(BCUtil.class.getName());

    /*
    PGPXxxKeyRing -> PGPXxxKeyRingCollection
     */
    public static PGPPublicKeyRingCollection keyRingsToKeyRingCollection(@Nonnull PGPPublicKeyRing... rings)
            throws IOException, PGPException {
        return new PGPPublicKeyRingCollection(Arrays.asList(rings));
    }

    public static PGPSecretKeyRingCollection keyRingsToKeyRingCollection(@Nonnull PGPSecretKeyRing... rings)
            throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(Arrays.asList(rings));
    }

    /*
    PGPXxxKeyRingCollection -> PGPXxxKeyRing
     */

    public static PGPSecretKeyRing getKeyRingFromCollection(@Nonnull PGPSecretKeyRingCollection collection,
                                                            @Nonnull Long id)
            throws PGPException {
        PGPSecretKeyRing uncleanedRing = collection.getSecretKeyRing(id);

        // Determine ids of signed keys
        Set<Long> signedKeyIds = new HashSet<>();
        signedKeyIds.add(id); // Add the signing key itself
        Iterator<PGPPublicKey> signedPubKeys = uncleanedRing.getKeysWithSignaturesBy(id);
        while (signedPubKeys.hasNext()) {
            signedKeyIds.add(signedPubKeys.next().getKeyID());
        }

        PGPSecretKeyRing cleanedRing = uncleanedRing;
        Iterator<PGPSecretKey> secretKeys = uncleanedRing.getSecretKeys();
        while (secretKeys.hasNext()) {
            PGPSecretKey secretKey = secretKeys.next();
            if (!signedKeyIds.contains(secretKey.getKeyID())) {
                cleanedRing = PGPSecretKeyRing.removeSecretKey(cleanedRing, secretKey);
            }
        }
        return cleanedRing;
    }

    public static PGPPublicKeyRing getKeyRingFromCollection(@Nonnull PGPPublicKeyRingCollection collection,
                                                            @Nonnull Long id)
            throws PGPException {
        PGPPublicKey key = collection.getPublicKey(id);
        return removeUnassociatedKeysFromKeyRing(collection.getPublicKeyRing(id), key);
    }

    public static InputStream getPgpDecoderInputStream(@Nonnull byte[] bytes)
            throws IOException {
        return getPgpDecoderInputStream(new ByteArrayInputStream(bytes));
    }

    public static InputStream getPgpDecoderInputStream(@Nonnull InputStream inputStream)
            throws IOException {
        return PGPUtil.getDecoderStream(inputStream);
    }

    public static byte[] getDecodedBytes(@Nonnull byte[] bytes)
            throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Streams.pipeAll(getPgpDecoderInputStream(bytes), buffer);
        return buffer.toByteArray();
    }

    public static byte[] getDecodedBytes(@Nonnull InputStream inputStream)
            throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Streams.pipeAll(inputStream, buffer);
        return getDecodedBytes(buffer.toByteArray());
    }

    /**
     * Remove all keys from the key ring, are either not having a subkey signature from the master key
     * (identified by {@code masterKeyId}), or are revoked ("normal" key revocation, as well as subkey revocation).
     *
     * @param ring key ring
     * @param masterKey master key
     * @return "cleaned" key ring
     */
    public static PGPPublicKeyRing removeUnassociatedKeysFromKeyRing(@Nonnull PGPPublicKeyRing ring,
                                                                     @Nonnull PGPPublicKey masterKey) {
        if (!masterKey.isMasterKey()) {
            throw new IllegalArgumentException("Given key is not a master key.");
        }
        // Only select keys which are signed by the master key and not revoked.
        PublicKeySelectionStrategy selector = new And.PubKeySelectionStrategy(
                new KeyBelongsToKeyRing.PubkeySelectionStrategy(masterKey),
                new NoRevocation.PubKeySelectionStrategy());

        PGPPublicKeyRing cleaned = ring;

        Iterator<PGPPublicKey> publicKeys = ring.getPublicKeys();
        while (publicKeys.hasNext()) {
            PGPPublicKey publicKey = publicKeys.next();
            if (!selector.accept(publicKey)) {
                cleaned = PGPPublicKeyRing.removePublicKey(cleaned, publicKey);
            }
        }

        return cleaned;
    }

    /**
     * Remove all keys from the key ring, are either not having a subkey signature from the master key
     * (identified by {@code masterKeyId}), or are revoked ("normal" key revocation, as well as subkey revocation).
     *
     * @param ring key ring
     * @param masterKey master key
     * @return "cleaned" key ring
     */
    public static PGPSecretKeyRing removeUnassociatedKeysFromKeyRing(@Nonnull PGPSecretKeyRing ring,
                                                                     @Nonnull PGPPublicKey masterKey) {
        if (!masterKey.isMasterKey()) {
            throw new IllegalArgumentException("Given key is not a master key.");
        }
        // Only select keys which are signed by the master key and not revoked.
        PublicKeySelectionStrategy selector = new And.PubKeySelectionStrategy(
                new KeyBelongsToKeyRing.PubkeySelectionStrategy(masterKey),
                new NoRevocation.PubKeySelectionStrategy());

        PGPSecretKeyRing cleaned = ring;

        Iterator<PGPSecretKey> secretKeys = ring.getSecretKeys();
        while (secretKeys.hasNext()) {
            PGPSecretKey secretKey = secretKeys.next();
            if (!selector.accept(secretKey.getPublicKey())) {
                cleaned = PGPSecretKeyRing.removeSecretKey(cleaned, secretKey);
            }
        }

        return cleaned;
    }

    public static PGPPublicKey getMasterKeyFrom(@Nonnull PGPKeyRing ring) {
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        while (it.hasNext()) {
            PGPPublicKey k = it.next();
            if (k.isMasterKey()) {
                // There can only be one master key, so we can immediately return
                return k;
            }
        }
        return null;
    }

    public static Set<Long> signingKeyIds(@Nonnull PGPSecretKeyRing ring) {
        Set<Long> ids = new HashSet<>();
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        while (it.hasNext()) {
            PGPPublicKey k = it.next();

            boolean signingKey = false;

            Iterator<?> sit = k.getSignatures();
            while (sit.hasNext()) {
                Object n = sit.next();
                if (!(n instanceof PGPSignature)) {
                    continue;
                }

                PGPSignature s = (PGPSignature) n;
                if (!s.hasSubpackets()) {
                    continue;
                }

                try {
                    s.verifyCertification(ring.getPublicKey(s.getKeyID()));
                } catch (PGPException e) {
                    LOGGER.log(Level.WARNING, "Could not verify signature on " + Long.toHexString(k.getKeyID()) + " made by " + Long.toHexString(s.getKeyID()));
                    continue;
                }

                PGPSignatureSubpacketVector hashed = s.getHashedSubPackets();
                if (KeyFlag.fromBitmask(hashed.getKeyFlags()).contains(KeyFlag.SIGN_DATA)) {
                    signingKey = true;
                    break;
                }
            }

            if (signingKey) {
                ids.add(k.getKeyID());
            }
        }
        return ids;
    }

    public static boolean keyRingContainsKeyWithId(@Nonnull PGPPublicKeyRing ring,
                                                   long keyId) {
        return ring.getPublicKey(keyId) != null;
    }

    public static boolean keyRingContainsKeyWithId(@Nonnull PGPSecretKeyRing ring,
                                                   long keyId) {
        return ring.getSecretKey(keyId) != null;
    }
}
