// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.PGPainless;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;

public final class KeyRingUtils {

    private KeyRingUtils() {

    }

    /**
     * Return the primary {@link PGPSecretKey} from the provided {@link PGPSecretKeyRing}.
     * If it has no primary secret key, throw a {@link NoSuchElementException}.
     *
     * @param secretKeys secret keys
     * @return primary secret key
     */
    @Nonnull
    public static PGPSecretKey requirePrimarySecretKeyFrom(@Nonnull PGPSecretKeyRing secretKeys) {
        PGPSecretKey primarySecretKey = getPrimarySecretKeyFrom(secretKeys);
        if (primarySecretKey == null) {
            throw new NoSuchElementException("Provided PGPSecretKeyRing has no primary secret key.");
        }
        return primarySecretKey;
    }

    /**
     * Return the primary {@link PGPSecretKey} from the provided {@link PGPSecretKeyRing} or null if it has none.
     *
     * @param secretKeys secret key ring
     * @return primary secret key
     */
    @Nullable
    public static PGPSecretKey getPrimarySecretKeyFrom(@Nonnull PGPSecretKeyRing secretKeys) {
        PGPSecretKey secretKey = secretKeys.getSecretKey();
        if (secretKey.isMasterKey()) {
            return secretKey;
        }
        return null;
    }

    /**
     * Return the primary {@link PGPPublicKey} from the provided key ring.
     * Throws a {@link NoSuchElementException} if the key ring has no primary public key.
     *
     * @param keyRing key ring
     * @return primary public key
     */
    @Nonnull
    public static PGPPublicKey requirePrimaryPublicKeyFrom(@Nonnull PGPKeyRing keyRing) {
        PGPPublicKey primaryPublicKey = getPrimaryPublicKeyFrom(keyRing);
        if (primaryPublicKey == null) {
            throw new NoSuchElementException("Provided PGPKeyRing has no primary public key.");
        }
        return primaryPublicKey;
    }

    /**
     * Return the primary {@link PGPPublicKey} from the provided key ring or null if it has none.
     *
     * @param keyRing key ring
     * @return primary public key
     */
    @Nullable
    public static PGPPublicKey getPrimaryPublicKeyFrom(@Nonnull PGPKeyRing keyRing) {
        PGPPublicKey primaryPublicKey = keyRing.getPublicKey();
        if (primaryPublicKey.isMasterKey()) {
            return primaryPublicKey;
        }
        return null;
    }

    /**
     * Return the public key with the given subKeyId from the keyRing.
     * If no such subkey exists, return null.
     * @param keyRing key ring
     * @param subKeyId subkey id
     * @return subkey or null
     */
    @Nullable
    public static PGPPublicKey getPublicKeyFrom(@Nonnull PGPKeyRing keyRing, long subKeyId) {
        return keyRing.getPublicKey(subKeyId);
    }

    /**
     * Require the public key with the given subKeyId from the keyRing.
     * If no such subkey exists, throw an {@link NoSuchElementException}.
     *
     * @param keyRing key ring
     * @param subKeyId subkey id
     * @return subkey
     */
    @Nonnull
    public static PGPPublicKey requirePublicKeyFrom(@Nonnull PGPKeyRing keyRing, long subKeyId) {
        PGPPublicKey publicKey = getPublicKeyFrom(keyRing, subKeyId);
        if (publicKey == null) {
            throw new NoSuchElementException("KeyRing does not contain public key with keyID " + Long.toHexString(subKeyId));
        }
        return publicKey;
    }

    /**
     * Require the secret key with the given secret subKeyId from the secret keyRing.
     * If no such subkey exists, throw an {@link NoSuchElementException}.
     *
     * @param keyRing secret key ring
     * @param subKeyId subkey id
     * @return secret subkey
     */
    @Nonnull
    public static PGPSecretKey requireSecretKeyFrom(@Nonnull PGPSecretKeyRing keyRing, long subKeyId) {
        PGPSecretKey secretKey = keyRing.getSecretKey(subKeyId);
        if (secretKey == null) {
            throw new NoSuchElementException("KeyRing does not contain secret key with keyID " + Long.toHexString(subKeyId));
        }
        return secretKey;
    }

    @Nonnull
    public static PGPPublicKeyRing publicKeys(@Nonnull PGPKeyRing keys) {
        if (keys instanceof PGPPublicKeyRing) {
            return (PGPPublicKeyRing) keys;
        } else if (keys instanceof PGPSecretKeyRing) {
            return publicKeyRingFrom((PGPSecretKeyRing) keys);
        } else {
            throw new IllegalArgumentException("Unknown keys class: " + keys.getClass().getName());
        }
    }

    /**
     * Extract a {@link PGPPublicKeyRing} containing all public keys from the provided {@link PGPSecretKeyRing}.
     *
     * @param secretKeys secret key ring
     * @return public key ring
     */
    @Nonnull
    public static PGPPublicKeyRing publicKeyRingFrom(@Nonnull PGPSecretKeyRing secretKeys) {
        List<PGPPublicKey> publicKeyList = new ArrayList<>();
        Iterator<PGPPublicKey> publicKeyIterator = secretKeys.getPublicKeys();
        while (publicKeyIterator.hasNext()) {
            publicKeyList.add(publicKeyIterator.next());
        }
        PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(publicKeyList);
        return publicKeyRing;
    }

    /**
     * Extract {@link PGPPublicKeyRing PGPPublicKeyRings} from all {@link PGPSecretKeyRing PGPSecretKeyRings} in
     * the given {@link PGPSecretKeyRingCollection} and return them as a {@link PGPPublicKeyRingCollection}.
     *
     * @param secretKeyRings secret key ring collection
     * @return public key ring collection
     */
    @Nonnull
    public static PGPPublicKeyRingCollection publicKeyRingCollectionFrom(@Nonnull PGPSecretKeyRingCollection secretKeyRings) {
        List<PGPPublicKeyRing> certificates = new ArrayList<>();
        for (PGPSecretKeyRing secretKey : secretKeyRings) {
            certificates.add(PGPainless.extractCertificate(secretKey));
        }
        return new PGPPublicKeyRingCollection(certificates);
    }

    /**
     * Unlock a {@link PGPSecretKey} and return the resulting {@link PGPPrivateKey}.
     *
     * @param secretKey secret key
     * @param protector protector to unlock the secret key
     * @return private key
     *
     * @throws PGPException if something goes wrong (e.g. wrong passphrase)
     */
    @Nonnull
    public static PGPPrivateKey unlockSecretKey(@Nonnull PGPSecretKey secretKey, @Nonnull SecretKeyRingProtector protector)
            throws PGPException {
        return UnlockSecretKey.unlockSecretKey(secretKey, protector);
    }

    /**
     * Create a new {@link PGPPublicKeyRingCollection} from an array of {@link PGPPublicKeyRing PGPPublicKeyRings}.
     *
     * @param rings array of public key rings
     * @return key ring collection
     */
    @Nonnull
    public static PGPPublicKeyRingCollection keyRingsToKeyRingCollection(@Nonnull PGPPublicKeyRing... rings) {
        return new PGPPublicKeyRingCollection(Arrays.asList(rings));
    }

    /**
     * Create a new {@link PGPSecretKeyRingCollection} from an array of {@link PGPSecretKeyRing PGPSecretKeyRings}.
     *
     * @param rings array of secret key rings
     * @return secret key ring collection
     */
    @Nonnull
    public static PGPSecretKeyRingCollection keyRingsToKeyRingCollection(@Nonnull PGPSecretKeyRing... rings) {
        return new PGPSecretKeyRingCollection(Arrays.asList(rings));
    }

    /**
     * Return true, if the given {@link PGPPublicKeyRing} contains a {@link PGPPublicKey} for the given key id.
     *
     * @param ring public key ring
     * @param keyId id of the key in question
     * @return true if ring contains said key, false otherwise
     */
    public static boolean keyRingContainsKeyWithId(@Nonnull PGPPublicKeyRing ring,
                                                   long keyId) {
        return ring.getPublicKey(keyId) != null;
    }

    /**
     * Inject a key certification for the primary key into the given key ring.
     *
     * @param keyRing key ring
     * @param certification key signature
     * @return key ring with injected signature
     * @param <T> either {@link PGPPublicKeyRing} or {@link PGPSecretKeyRing}
     */
    @Nonnull
    public static <T extends PGPKeyRing> T injectCertification(@Nonnull T keyRing,
                                                               @Nonnull PGPSignature certification) {
        return injectCertification(keyRing, keyRing.getPublicKey(), certification);
    }

    /**
     * Inject a key certification for the given key into the given key ring.
     *
     * @param keyRing key ring
     * @param certifiedKey signed public key
     * @param certification key signature
     * @param <T> either {@link PGPPublicKeyRing} or {@link PGPSecretKeyRing}
     * @return key ring with injected signature
     *
     * @throws NoSuchElementException in case that the signed key is not part of the key ring
     */
    @Nonnull
    public static <T extends PGPKeyRing> T injectCertification(@Nonnull T keyRing,
                                                               @Nonnull PGPPublicKey certifiedKey,
                                                               @Nonnull PGPSignature certification) {
        PGPSecretKeyRing secretKeys = null;
        PGPPublicKeyRing publicKeys;
        if (keyRing instanceof PGPSecretKeyRing) {
            secretKeys = (PGPSecretKeyRing) keyRing;
            publicKeys = PGPainless.extractCertificate(secretKeys);
        } else {
            publicKeys = (PGPPublicKeyRing) keyRing;
        }

        certifiedKey = PGPPublicKey.addCertification(certifiedKey, certification);
        List<PGPPublicKey> publicKeyList = new ArrayList<>();
        Iterator<PGPPublicKey> publicKeyIterator = publicKeys.iterator();
        boolean added = false;
        while (publicKeyIterator.hasNext()) {
            PGPPublicKey key = publicKeyIterator.next();
            if (key.getKeyID() == certifiedKey.getKeyID()) {
                added = true;
                publicKeyList.add(certifiedKey);
            } else {
                publicKeyList.add(key);
            }
        }
        if (!added) {
            throw new NoSuchElementException("Cannot find public key with id " + Long.toHexString(certifiedKey.getKeyID()) + " in the provided key ring.");
        }

        publicKeys = new PGPPublicKeyRing(publicKeyList);
        if (secretKeys == null) {
            return (T) publicKeys;
        } else {
            secretKeys = PGPSecretKeyRing.replacePublicKeys(secretKeys, publicKeys);
            return (T) secretKeys;
        }
    }

    /**
     * Inject a user-id certification into the given key ring.
     *
     * @param keyRing key ring
     * @param userId signed user-id
     * @param certification signature
     * @param <T> either {@link PGPPublicKeyRing} or {@link PGPSecretKeyRing}
     * @return key ring with injected certification
     */
    @Nonnull
    public static <T extends PGPKeyRing> T injectCertification(@Nonnull T keyRing,
                                                               @Nonnull String userId,
                                                               @Nonnull PGPSignature certification) {
        PGPSecretKeyRing secretKeys = null;
        PGPPublicKeyRing publicKeys;
        if (keyRing instanceof PGPSecretKeyRing) {
            secretKeys = (PGPSecretKeyRing) keyRing;
            publicKeys = PGPainless.extractCertificate(secretKeys);
        } else {
            publicKeys = (PGPPublicKeyRing) keyRing;
        }

        Iterator<PGPPublicKey> publicKeyIterator = publicKeys.iterator();
        PGPPublicKey primaryKey = publicKeyIterator.next();
        primaryKey = PGPPublicKey.addCertification(primaryKey, userId, certification);

        List<PGPPublicKey> publicKeyList = new ArrayList<>();
        publicKeyList.add(primaryKey);
        while (publicKeyIterator.hasNext()) {
            publicKeyList.add(publicKeyIterator.next());
        }

        publicKeys = new PGPPublicKeyRing(publicKeyList);
        if (secretKeys == null) {
            return (T) publicKeys;
        } else {
            secretKeys = PGPSecretKeyRing.replacePublicKeys(secretKeys, publicKeys);
            return (T) secretKeys;
        }
    }

    /**
     * Inject a user-attribute vector certification into the given key ring.
     *
     * @param keyRing key ring
     * @param userAttributes certified user attributes
     * @param certification certification signature
     * @param <T> either {@link PGPPublicKeyRing} or {@link PGPSecretKeyRing}
     * @return key ring with injected user-attribute certification
     */
    @Nonnull
    public static <T extends PGPKeyRing> T injectCertification(@Nonnull T keyRing,
                                                               @Nonnull PGPUserAttributeSubpacketVector userAttributes,
                                                               @Nonnull PGPSignature certification) {
        PGPSecretKeyRing secretKeys = null;
        PGPPublicKeyRing publicKeys;
        if (keyRing instanceof PGPSecretKeyRing) {
            secretKeys = (PGPSecretKeyRing) keyRing;
            publicKeys = PGPainless.extractCertificate(secretKeys);
        } else {
            publicKeys = (PGPPublicKeyRing) keyRing;
        }

        Iterator<PGPPublicKey> publicKeyIterator = publicKeys.iterator();
        PGPPublicKey primaryKey = publicKeyIterator.next();
        primaryKey = PGPPublicKey.addCertification(primaryKey, userAttributes, certification);

        List<PGPPublicKey> publicKeyList = new ArrayList<>();
        publicKeyList.add(primaryKey);
        while (publicKeyIterator.hasNext()) {
            publicKeyList.add(publicKeyIterator.next());
        }

        publicKeys = new PGPPublicKeyRing(publicKeyList);
        if (secretKeys == null) {
            return (T) publicKeys;
        } else {
            secretKeys = PGPSecretKeyRing.replacePublicKeys(secretKeys, publicKeys);
            return (T) secretKeys;
        }
    }

    /**
     * Inject a {@link PGPPublicKey} into the given key ring.
     *
     * @param keyRing key ring
     * @param publicKey public key
     * @param <T> either {@link PGPPublicKeyRing} or {@link PGPSecretKeyRing}
     * @return key ring with injected public key
     */
    @Nonnull
    public static <T extends PGPKeyRing> T keysPlusPublicKey(@Nonnull T keyRing,
                                                             @Nonnull PGPPublicKey publicKey) {
        PGPSecretKeyRing secretKeys = null;
        PGPPublicKeyRing publicKeys;
        if (keyRing instanceof PGPSecretKeyRing) {
            secretKeys = (PGPSecretKeyRing) keyRing;
            publicKeys = PGPainless.extractCertificate(secretKeys);
        } else {
            publicKeys = (PGPPublicKeyRing) keyRing;
        }

        publicKeys = PGPPublicKeyRing.insertPublicKey(publicKeys, publicKey);
        if (secretKeys == null) {
            return (T) publicKeys;
        } else {
            secretKeys = PGPSecretKeyRing.insertOrReplacePublicKey(secretKeys, publicKey);
            return (T) secretKeys;
        }
    }

    /**
     * Inject a {@link PGPSecretKey} into a {@link PGPSecretKeyRing}.
     *
     * @param secretKeys secret key ring
     * @param secretKey secret key
     * @return secret key ring with injected secret key
     */
    @Nonnull
    public static PGPSecretKeyRing keysPlusSecretKey(@Nonnull PGPSecretKeyRing secretKeys,
                                                     @Nonnull PGPSecretKey secretKey) {
        return PGPSecretKeyRing.insertSecretKey(secretKeys, secretKey);
    }

    /**
     * Inject the given signature into the public part of the given secret key.
     * @param secretKey secret key
     * @param signature signature
     * @return secret key with the signature injected in its public key
     */
    @Nonnull
    public static PGPSecretKey secretKeyPlusSignature(@Nonnull PGPSecretKey secretKey,
                                                      @Nonnull PGPSignature signature) {
        PGPPublicKey publicKey = secretKey.getPublicKey();
        publicKey = PGPPublicKey.addCertification(publicKey, signature);
        PGPSecretKey newSecretKey = PGPSecretKey.replacePublicKey(secretKey, publicKey);
        return newSecretKey;
    }

    /**
     * Remove the secret key of the subkey identified by the given secret key id from the key ring.
     * The public part stays attached to the key ring, so that it can still be used for encryption / verification of signatures.
     *
     * This method is intended to be used to remove secret primary keys from live keys when those are kept in offline storage.
     *
     * @param secretKeys secret key ring
     * @param secretKeyId id of the secret key to remove
     * @return secret key ring with removed secret key
     *
     * @throws IOException in case of an error during serialization / deserialization of the key
     * @throws PGPException in case of a broken key
     */
    @Nonnull
    public static PGPSecretKeyRing stripSecretKey(@Nonnull PGPSecretKeyRing secretKeys,
                                                  long secretKeyId)
            throws IOException, PGPException {

        if (secretKeys.getPublicKey().getKeyID() == secretKeyId) {
            throw new IllegalArgumentException("Bouncy Castle currently cannot deal with stripped secret primary keys.");
        }

        if (secretKeys.getSecretKey(secretKeyId) == null) {
            throw new NoSuchElementException("PGPSecretKeyRing does not contain secret key " + Long.toHexString(secretKeyId));
        }

        // Since BCs constructors for secret key rings are mostly private, we need to encode the key ring how we want it
        //  and then parse it again.
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        for (PGPSecretKey secretKey : secretKeys) {
            if (secretKey.getKeyID() == secretKeyId) {
                // only encode the public part of the target key
                secretKey.getPublicKey().encode(encoded);
            } else {
                // otherwise, encode secret + public key
                secretKey.encode(encoded);
            }
        }
        for (Iterator<PGPPublicKey> it = secretKeys.getExtraPublicKeys(); it.hasNext(); ) {
            PGPPublicKey extra = it.next();
            extra.encode(encoded);
        }
        // Parse the key back into an object
        return new PGPSecretKeyRing(encoded.toByteArray(), ImplementationFactory.getInstance().getKeyFingerprintCalculator());
    }

    /**
     * Strip all user-ids, user-attributes and signatures from the given public key.
     * @param bloatedKey public key
     * @return stripped public key
     */
    public static PGPPublicKey getStrippedDownPublicKey(PGPPublicKey bloatedKey) throws PGPException {
        return new PGPPublicKey(bloatedKey.getPublicKeyPacket(), ImplementationFactory.getInstance().getKeyFingerprintCalculator());
    }
}
