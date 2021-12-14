// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.key.info.KeyInfo;
import org.pgpainless.key.util.UserId;
import org.pgpainless.util.BCUtil;
import org.pgpainless.util.TestAllImplementations;
import org.pgpainless.util.Passphrase;

public class BrainpoolKeyGenerationTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void generateEcKeysTest()
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {

        for (EllipticCurve curve : EllipticCurve.values()) {
            PGPSecretKeyRing secretKeys = generateKey(
                    KeySpec.getBuilder(
                            KeyType.ECDSA(curve), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA).build(),
                    KeySpec.getBuilder(
                            KeyType.ECDH(curve), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE).build(),
                    "Elliptic Curve <elliptic@curve.key>");

            assertEquals(PublicKeyAlgorithm.ECDSA, PublicKeyAlgorithm.fromId(secretKeys.getPublicKey().getAlgorithm()));
            Iterator<PGPSecretKey> secretKeyIterator = secretKeys.iterator();

            PGPSecretKey primaryKey = secretKeyIterator.next();
            KeyInfo primaryInfo = new KeyInfo(primaryKey);
            assertEquals(curve.getName(), primaryInfo.getCurveName());
            assertFalse(primaryInfo.isEncrypted());
            assertTrue(primaryInfo.isDecrypted());
            assertFalse(primaryInfo.hasDummyS2K());

            PGPSecretKey subKey = secretKeyIterator.next();
            KeyInfo subInfo = new KeyInfo(subKey);
            assertEquals(curve.getName(), subInfo.getCurveName());
        }
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void generateEdDSAKeyTest()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {

        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(
                        KeyType.ECDSA(EllipticCurve._BRAINPOOLP384R1), KeyFlag.CERTIFY_OTHER))
                .addSubkey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(
                        KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .addSubkey(KeySpec.getBuilder(
                        KeyType.RSA(RsaLength._3072), KeyFlag.SIGN_DATA))
                .addUserId(UserId.nameAndEmail("Alice", "alice@pgpainless.org"))
                .setPassphrase(Passphrase.fromPassword("passphrase"))
                .build();

        for (PGPSecretKey key : secretKeys) {
            KeyInfo info = new KeyInfo(key);
            assertTrue(info.isEncrypted());
            assertFalse(info.isDecrypted());

            PGPPublicKey pubKey = key.getPublicKey();
            assertFalse(new KeyInfo(pubKey).isEncrypted());
            assertTrue(new KeyInfo(pubKey).isDecrypted());
            assertFalse(new KeyInfo(pubKey).hasDummyS2K());
        }

        Iterator<PGPSecretKey> iterator = secretKeys.iterator();
        PGPSecretKey ecdsaPrim = iterator.next();
        KeyInfo ecdsaInfo = new KeyInfo(ecdsaPrim);
        assertEquals(EllipticCurve._BRAINPOOLP384R1.getName(), ecdsaInfo.getCurveName());
        assertEquals(384, BCUtil.getBitStrength(ecdsaPrim.getPublicKey()));

        PGPSecretKey eddsaSub = iterator.next();
        KeyInfo eddsaInfo = new KeyInfo(eddsaSub);
        assertEquals(EdDSACurve._Ed25519.getName(), eddsaInfo.getCurveName());
        assertEquals(256, BCUtil.getBitStrength(eddsaSub.getPublicKey()));

        PGPSecretKey xdhSub = iterator.next();
        KeyInfo xdhInfo = new KeyInfo(xdhSub);
        assertEquals(XDHSpec._X25519.getCurveName(), xdhInfo.getCurveName());
        assertEquals(256, BCUtil.getBitStrength(xdhSub.getPublicKey()));

        PGPSecretKey rsaSub = iterator.next();
        KeyInfo rsaInfo = new KeyInfo(rsaSub);
        assertThrows(IllegalArgumentException.class, rsaInfo::getCurveName, "RSA is not a curve-based encryption system");
        assertEquals(3072, BCUtil.getBitStrength(rsaSub.getPublicKey()));
    }

    public PGPSecretKeyRing generateKey(KeySpec primaryKey, KeySpec subKey, String userId) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(primaryKey)
                .addSubkey(subKey)
                .addUserId(userId)
                .build();
        return secretKeys;
    }
}
