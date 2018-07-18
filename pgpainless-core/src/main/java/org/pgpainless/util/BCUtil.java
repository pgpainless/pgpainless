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
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.selection.key.PublicKeySelectionStrategy;
import org.pgpainless.key.selection.key.impl.And;
import org.pgpainless.key.selection.key.impl.NoRevocation;
import org.pgpainless.key.selection.key.impl.SignedByMasterKey;

public class BCUtil {

    private static final Logger LOGGER = Logger.getLogger(BCUtil.class.getName());

    /*
    PGPXxxKeyRing -> PGPXxxKeyRingCollection
     */
    public static PGPPublicKeyRingCollection keyRingsToKeyRingCollection(PGPPublicKeyRing... rings)
            throws IOException, PGPException {
        return new PGPPublicKeyRingCollection(Arrays.asList(rings));
    }

    public static PGPSecretKeyRingCollection keyRingsToKeyRingCollection(PGPSecretKeyRing... rings)
            throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(Arrays.asList(rings));
    }

    public static PGPPublicKeyRing publicKeyRingFromSecretKeyRing(PGPSecretKeyRing secretKeys)
            throws PGPException, IOException {
        PGPSecretKeyRing fixedSecretKeys = KeyRingSubKeyFix.repairSubkeyPackets(secretKeys, null, null);

        ByteArrayOutputStream buffer = new ByteArrayOutputStream(512);
        for (PGPSecretKey secretKey : fixedSecretKeys) {
            PGPPublicKey publicKey = secretKey.getPublicKey();
            if (publicKey != null) {
                publicKey.encode(buffer, false);
            }
        }

        return new PGPPublicKeyRing(buffer.toByteArray(), new BcKeyFingerprintCalculator());
    }

    /*
    PGPXxxKeyRingCollection -> PGPXxxKeyRing
     */

    public static PGPSecretKeyRing getKeyRingFromCollection(PGPSecretKeyRingCollection collection, Long id)
            throws PGPException, IOException {
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

    public static PGPPublicKeyRing getKeyRingFromCollection(PGPPublicKeyRingCollection collection, Long id)
            throws PGPException {
        PGPPublicKey key = collection.getPublicKey(id);
        return removeUnassociatedKeysFromKeyRing(collection.getPublicKeyRing(id), key);
    }

    public static InputStream getPgpDecoderInputStream(byte[] bytes) throws IOException {
        return getPgpDecoderInputStream(new ByteArrayInputStream(bytes));
    }

    public static InputStream getPgpDecoderInputStream(InputStream inputStream) throws IOException {
        return PGPUtil.getDecoderStream(inputStream);
    }

    public static byte[] getDecodedBytes(byte[] bytes) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Streams.pipeAll(getPgpDecoderInputStream(bytes), buffer);
        return buffer.toByteArray();
    }

    public static byte[] getDecodedBytes(InputStream inputStream) throws IOException {
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
    public static PGPPublicKeyRing removeUnassociatedKeysFromKeyRing(PGPPublicKeyRing ring, PGPPublicKey masterKey) {
        if (!masterKey.isMasterKey()) {
            throw new IllegalArgumentException("Given key is not a master key.");
        }
        // Only select keys which are signed by the master key and not revoked.
        PublicKeySelectionStrategy<PGPPublicKey> selector = new And.PubKeySelectionStrategy<>(
                new SignedByMasterKey.PubkeySelectionStrategy(),
                new NoRevocation.PubKeySelectionStrategy<>());

        PGPPublicKeyRing cleaned = ring;

        Iterator<PGPPublicKey> publicKeys = ring.getPublicKeys();
        while (publicKeys.hasNext()) {
            PGPPublicKey publicKey = publicKeys.next();
            if (!selector.accept(masterKey, publicKey)) {
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
    public static PGPSecretKeyRing removeUnassociatedKeysFromKeyRing(PGPSecretKeyRing ring, PGPPublicKey masterKey) {
        if (!masterKey.isMasterKey()) {
            throw new IllegalArgumentException("Given key is not a master key.");
        }
        // Only select keys which are signed by the master key and not revoked.
        PublicKeySelectionStrategy<PGPPublicKey> selector = new And.PubKeySelectionStrategy<>(
                new SignedByMasterKey.PubkeySelectionStrategy(),
                new NoRevocation.PubKeySelectionStrategy<>());

        PGPSecretKeyRing cleaned = ring;

        Iterator<PGPSecretKey> secretKeys = ring.getSecretKeys();
        while (secretKeys.hasNext()) {
            PGPSecretKey secretKey = secretKeys.next();
            if (!selector.accept(masterKey, secretKey.getPublicKey())) {
                cleaned = PGPSecretKeyRing.removeSecretKey(cleaned, secretKey);
            }
        }

        return cleaned;
    }

    /**
     * Return the {@link PGPPublicKey} which is the master key of the key ring.
     *
     * @param ring key ring
     * @return master key
     */
    public static PGPPublicKey getMasterKeyFrom(PGPPublicKeyRing ring) {
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

    public static PGPPublicKey getMasterKeyFrom(PGPKeyRing ring) {
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

    public static Set<Long> signingKeyIds(PGPSecretKeyRing ring) {
        Set<Long> ids = new HashSet<>();
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        while (it.hasNext()) {
            PGPPublicKey k = it.next();

            boolean signingKey = false;

            Iterator sit = k.getSignatures();
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
                if (KeyFlag.fromInteger(hashed.getKeyFlags()).contains(KeyFlag.SIGN_DATA)) {
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

    public static boolean keyRingContainsKeyWithId(PGPPublicKeyRing ring, long keyId) {
        return ring.getPublicKey(keyId) != null;
    }

    public static boolean keyRingContainsKeyWithId(PGPSecretKeyRing ring, long keyId) {
        return ring.getSecretKey(keyId) != null;
    }

    /*
    public static PGPKeyRing merge(PGPKeyRing one, PGPKeyRing other) {

        PGPPublicKey masterOne = getMasterKeyFrom(one);
        if (masterOne == null) {
            throw new IllegalArgumentException("First PGPKeyRing has no master key");
        }

        PGPPublicKey masterOther = getMasterKeyFrom(other);
        if (masterOther == null) {
            throw new IllegalArgumentException("Other PGPKeyRing has no master key");
        }

        if (masterOne.getKeyID() != masterOther.getKeyID() ||
                Arrays.equals(masterOne.getFingerprint(), masterOther.getFingerprint())) {
            throw new IllegalArgumentException("Keys are not the same.");
        }

        PGPKeyRing merged = one;

        boolean mergedIsSecret = (merged instanceof PGPSecretKeyRing);
        boolean otherIsSecret = (other instanceof PGPSecretKeyRing);

        for (Iterator it = other.getPublicKeys(); it.hasNext(); ) {

            PGPPublicKey nextPublicKey = (PGPPublicKey) it.next();
            PGPPublicKey pendant = merged.getPublicKey(nextPublicKey.getKeyID());

            if (pendant == null) {
                if (mergedIsSecret && otherIsSecret) {
                    // Add secret key
                    PGPSecretKey secretKey = ((PGPSecretKeyRing) other).getSecretKey(nextPublicKey.getKeyID());
                    merged = PGPSecretKeyRing.insertSecretKey((PGPSecretKeyRing) merged, secretKey);
                } else {
                    if (mergedIsSecret) {
                        PGPSecretKeyRing mergedAsSecret = (PGPSecretKeyRing) merged;
                        PGPSecretKey secretKey = mergedAsSecret.getSecretKey(nextPublicKey.getKeyID());
                        if (secretKey == null) {
                            PGPPublicKeyRing mergedAsPublic = publicKeyRingFromSecretKeyRing((PGPSecretKeyRing) merged);
                            mergedAsPublic = PGPPublicKeyRing.insertPublicKey(mergedAsPublic, nextPublicKey);
                            mergedAsSecret = PGPSecretKeyRing.replacePublicKeys(mergedAsSecret, mergedAsPublic);
                            merged = mergedAsSecret;
                        }
                    }
                }
            }
        }
    }
    */
}
