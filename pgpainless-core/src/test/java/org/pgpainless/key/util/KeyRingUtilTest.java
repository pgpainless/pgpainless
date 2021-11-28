// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.NoSuchElementException;
import java.util.Random;

import org.bouncycastle.bcpg.attr.ImageAttribute;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.CollectionUtils;

public class KeyRingUtilTest {

    @Test
    public void testDeleteUserIdFromSecretKeyRing()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice", null);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Bob", SecretKeyRingProtector.unprotectedKeys())
                .done();
        assertEquals(2, CollectionUtils.iteratorToList(secretKeys.getPublicKey().getUserIDs()).size());

        secretKeys = KeyRingUtils.deleteUserId(secretKeys, "Bob");

        assertEquals(1, CollectionUtils.iteratorToList(secretKeys.getPublicKey().getUserIDs()).size());
    }

    @Test
    public void testDeleteUserIdFromPublicKeyRing()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice", null);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Bob", SecretKeyRingProtector.unprotectedKeys())
                .done();
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);
        assertEquals(2, CollectionUtils.iteratorToList(publicKeys.getPublicKey().getUserIDs()).size());

        publicKeys = KeyRingUtils.deleteUserId(publicKeys, "Alice");

        assertEquals(1, CollectionUtils.iteratorToList(publicKeys.getPublicKey().getUserIDs()).size());
    }

    @Test
    public void testDeleteNonexistentUserIdFromKeyRingThrows()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice", null);

        assertThrows(NoSuchElementException.class,
                () -> KeyRingUtils.deleteUserId(secretKeys, "Charlie"));
    }

    @Test
    public void testInjectCertification() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice", null);

        // test preconditions
        assertFalse(secretKeys.getPublicKey().getUserAttributes().hasNext());
        int sigCount = CollectionUtils.iteratorToList(secretKeys.getPublicKey().getSignatures()).size();

        // Create "image"
        byte[] image = new byte[512];
        new Random().nextBytes(image);
        PGPUserAttributeSubpacketVectorGenerator userAttrGen = new PGPUserAttributeSubpacketVectorGenerator();
        userAttrGen.setImageAttribute(ImageAttribute.JPEG, image);
        PGPUserAttributeSubpacketVector userAttr = userAttrGen.generate();

        // create sig
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                ImplementationFactory.getInstance().getPGPContentSignerBuilder(
                        secretKeys.getPublicKey().getAlgorithm(), HashAlgorithm.SHA512.getAlgorithmId()
                ));
        sigGen.init(
                SignatureType.POSITIVE_CERTIFICATION.getCode(),
                UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), SecretKeyRingProtector.unprotectedKeys()));
        PGPSignature signature = sigGen.generateCertification(userAttr, secretKeys.getPublicKey());
        // inject sig
        secretKeys = KeyRingUtils.injectCertification(secretKeys, userAttr, signature);

        assertTrue(secretKeys.getPublicKey().getUserAttributes().hasNext());
        assertEquals(userAttr, secretKeys.getPublicKey().getUserAttributes().next());
        assertEquals(sigCount + 1, CollectionUtils.iteratorToList(secretKeys.getPublicKey().getSignatures()).size());
    }
}
