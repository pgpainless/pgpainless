// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util;

import org.bouncycastle.bcpg.attr.ImageAttribute;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.CollectionUtils;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class KeyRingUtilTest {

    @Test
    public void testInjectCertification() throws PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice")
                .getPGPSecretKeyRing();

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
                OpenPGPImplementation.getInstance().pgpContentSignerBuilder(
                        secretKeys.getPublicKey().getAlgorithm(), HashAlgorithm.SHA512.getAlgorithmId()
                ), secretKeys.getPublicKey());
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

    @Test
    public void testKeysPlusPublicKey() {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice")
                .getPGPSecretKeyRing();
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);

        PGPKeyPair keyPair = KeyRingBuilder.generateKeyPair(KeySpec.getBuilder(
                KeyType.ECDH(EllipticCurve._P256), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE).build(),
                OpenPGPKeyVersion.v4);
        PGPPublicKey pubkey = keyPair.getPublicKey();
        assertFalse(pubkey.isMasterKey());

        PGPSecretKeyRing secretKeysPlus = KeyRingUtils.keysPlusPublicKey(secretKeys, pubkey);
        assertNotNull(secretKeysPlus.getPublicKey(pubkey.getKeyID()));

        PGPPublicKeyRing publicKeysPlus = KeyRingUtils.keysPlusPublicKey(publicKeys, pubkey);
        assertNotNull(publicKeysPlus.getPublicKey(pubkey.getKeyID()));
    }
}
