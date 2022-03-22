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
import org.pgpainless.exception.NotYetImplementedException;
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
    public static PGPSecretKey requirePrimarySecretKeyFrom(PGPSecretKeyRing secretKeys) {
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
    public static PGPSecretKey getPrimarySecretKeyFrom(PGPSecretKeyRing secretKeys) {
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
    public static PGPPublicKey requirePrimaryPublicKeyFrom(PGPKeyRing keyRing) {
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
    public static PGPPublicKey getPrimaryPublicKeyFrom(PGPKeyRing keyRing) {
        PGPPublicKey primaryPublicKey = keyRing.getPublicKey();
        if (primaryPublicKey.isMasterKey()) {
            return primaryPublicKey;
        }
        return null;
    }

    public static PGPPublicKey getPublicKeyFrom(PGPKeyRing keyRing, long subKeyId) {
        return keyRing.getPublicKey(subKeyId);
    }

    public static PGPPublicKey requirePublicKeyFrom(PGPKeyRing keyRing, long subKeyId) {
        PGPPublicKey publicKey = getPublicKeyFrom(keyRing, subKeyId);
        if (publicKey == null) {
            throw new NoSuchElementException("KeyRing does not contain public key with keyID " + Long.toHexString(subKeyId));
        }
        return publicKey;
    }

    public static PGPSecretKey requireSecretKeyFrom(PGPSecretKeyRing keyRing, long subKeyId) {
        PGPSecretKey secretKey = keyRing.getSecretKey(subKeyId);
        if (secretKey == null) {
            throw new NoSuchElementException("KeyRing does not contain secret key with keyID " + Long.toHexString(subKeyId));
        }
        return secretKey;
    }

    /**
     * Extract a {@link PGPPublicKeyRing} containing all public keys from the provided {@link PGPSecretKeyRing}.
     *
     * @param secretKeys secret key ring
     * @return public key ring
     */
    public static PGPPublicKeyRing publicKeyRingFrom(PGPSecretKeyRing secretKeys) {
        List<PGPPublicKey> publicKeyList = new ArrayList<>();
        Iterator<PGPPublicKey> publicKeyIterator = secretKeys.getPublicKeys();
        while (publicKeyIterator.hasNext()) {
            publicKeyList.add(publicKeyIterator.next());
        }
        PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(publicKeyList);
        return publicKeyRing;
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
    public static PGPPrivateKey unlockSecretKey(PGPSecretKey secretKey, SecretKeyRingProtector protector) throws PGPException {
        return UnlockSecretKey.unlockSecretKey(secretKey, protector);
    }

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

    public static boolean keyRingContainsKeyWithId(@Nonnull PGPPublicKeyRing ring,
                                                   long keyId) {
        return ring.getPublicKey(keyId) != null;
    }

    public static <T extends PGPKeyRing> T injectCertification(T keyRing, PGPPublicKey certifiedKey, PGPSignature certification) {
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

    public static <T extends PGPKeyRing> T injectCertification(T keyRing, String userId, PGPSignature certification) {
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

    public static <T extends PGPKeyRing> T injectCertification(T keyRing, PGPUserAttributeSubpacketVector userAttributes, PGPSignature certification) {
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

    public static <T extends PGPKeyRing> T keysPlusPublicKey(T keyRing, PGPPublicKey publicKey) {
        if (true)
            // Is currently broken beyond repair
            throw new NotYetImplementedException();

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
            // TODO: Replace with PGPSecretKeyRing.insertOrReplacePublicKey() once available
            //  Right now replacePublicKeys looses extra public keys.
            //  See https://github.com/bcgit/bc-java/pull/1068 for a possible fix
            secretKeys = PGPSecretKeyRing.replacePublicKeys(secretKeys, publicKeys);
            return (T) secretKeys;
        }
    }

    public static PGPSecretKeyRing keysPlusSecretKey(PGPSecretKeyRing secretKeys, PGPSecretKey secretKey) {
        return PGPSecretKeyRing.insertSecretKey(secretKeys, secretKey);
    }

    public static PGPSecretKey secretKeyPlusSignature(PGPSecretKey secretKey, PGPSignature signature) {
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
     * @throws IOException
     * @throws PGPException
     */
    public static PGPSecretKeyRing removeSecretKey(PGPSecretKeyRing secretKeys, long secretKeyId)
            throws IOException, PGPException {
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
}
