// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util;

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
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.CollectionUtils;

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
     * @throws PGPException if something goes wrong (eg. wrong passphrase)
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

    /**
     * Delete the given user-id and its certification signatures from the given key.
     *
     * @deprecated Deleting user-ids is highly discouraged, since it might lead to all sorts of problems
     * (e.g. lost key properties).
     * Instead, user-ids should only be revoked.
     *
     * @param secretKeys secret keys
     * @param userId user-id
     * @return modified secret keys
     */
    @Deprecated
    public static PGPSecretKeyRing deleteUserId(PGPSecretKeyRing secretKeys, String userId) {
        PGPSecretKey secretKey = secretKeys.getSecretKey(); // user-ids are located on primary key only
        PGPPublicKey publicKey = secretKey.getPublicKey(); // user-ids are placed on the public key part
        publicKey = PGPPublicKey.removeCertification(publicKey, userId);
        if (publicKey == null) {
            throw new NoSuchElementException("User-ID " + userId + " not found on the key.");
        }
        secretKey = PGPSecretKey.replacePublicKey(secretKey, publicKey);
        secretKeys = PGPSecretKeyRing.insertSecretKey(secretKeys, secretKey);
        return secretKeys;
    }

    /**
     * Delete the given user-id and its certification signatures from the given certificate.
     *
     * @deprecated Deleting user-ids is highly discouraged, since it might lead to all sorts of problems
     * (e.g. lost key properties).
     * Instead, user-ids should only be revoked.
     *
     * @param publicKeys certificate
     * @param userId user-id
     * @return modified secret keys
     */
    @Deprecated
    public static PGPPublicKeyRing deleteUserId(PGPPublicKeyRing publicKeys, String userId) {
        PGPPublicKey publicKey = publicKeys.getPublicKey(); // user-ids are located on primary key only
        publicKey = PGPPublicKey.removeCertification(publicKey, userId);
        if (publicKey == null) {
            throw new NoSuchElementException("User-ID " + userId + " not found on the key.");
        }
        publicKeys = PGPPublicKeyRing.insertPublicKey(publicKeys, publicKey);
        return publicKeys;
    }

    public static PGPSecretKeyRing secretKeysPlusPublicKey(PGPSecretKeyRing secretKeys, PGPPublicKey subkey) {
        PGPPublicKeyRing publicKeys = publicKeyRingFrom(secretKeys);
        PGPPublicKeyRing newPublicKeys = publicKeysPlusPublicKey(publicKeys, subkey);
        PGPSecretKeyRing newSecretKeys = PGPSecretKeyRing.replacePublicKeys(secretKeys, newPublicKeys);
        return newSecretKeys;
    }

    public static PGPPublicKeyRing publicKeysPlusPublicKey(PGPPublicKeyRing publicKeys, PGPPublicKey subkey) {
        List<PGPPublicKey> publicKeyList = CollectionUtils.iteratorToList(publicKeys.getPublicKeys());
        publicKeyList.add(subkey);
        PGPPublicKeyRing newPublicKeys = new PGPPublicKeyRing(publicKeyList);
        return newPublicKeys;
    }

    public static PGPSecretKeyRing secretKeysPlusSecretKey(PGPSecretKeyRing secretKeys, PGPSecretKey subkey) {
        return PGPSecretKeyRing.insertSecretKey(secretKeys, subkey);
    }

    public static PGPSecretKey secretKeyPlusSignature(PGPSecretKey secretKey, PGPSignature signature) {
        PGPPublicKey publicKey = secretKey.getPublicKey();
        publicKey = PGPPublicKey.addCertification(publicKey, signature);
        PGPSecretKey newSecretKey = PGPSecretKey.replacePublicKey(secretKey, publicKey);
        return newSecretKey;
    }
}
