// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Iterator;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.bouncycastle.extensions.PGPPublicKeyExtensionsKt;
import org.pgpainless.bouncycastle.extensions.PGPSecretKeyExtensionsKt;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec;
import org.pgpainless.key.util.UserId;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.TestAllImplementations;

public class BrainpoolKeyGenerationTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void generateEcKeysTest() {

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
            assertEquals(curve.getName(), PGPPublicKeyExtensionsKt.getCurveName(primaryKey.getPublicKey()));
            assertFalse(PGPSecretKeyExtensionsKt.isEncrypted(primaryKey));
            assertTrue(PGPSecretKeyExtensionsKt.isDecrypted(primaryKey));
            assertFalse(PGPSecretKeyExtensionsKt.hasDummyS2K(primaryKey));

            PGPSecretKey subKey = secretKeyIterator.next();
            assertEquals(curve.getName(), PGPPublicKeyExtensionsKt.getCurveName(subKey.getPublicKey()));
        }
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void generateEdDSAKeyTest() {

        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(
                        KeyType.ECDSA(EllipticCurve._BRAINPOOLP384R1), KeyFlag.CERTIFY_OTHER))
                .addSubkey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(
                        KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .addSubkey(KeySpec.getBuilder(
                        KeyType.RSA(RsaLength._3072), KeyFlag.SIGN_DATA))
                .addUserId(UserId.nameAndEmail("Alice", "alice@pgpainless.org"))
                .setPassphrase(Passphrase.fromPassword("passphrase"))
                .build()
                .getPGPSecretKeyRing();

        for (PGPSecretKey key : secretKeys) {
            assertTrue(PGPSecretKeyExtensionsKt.isEncrypted(key));
            assertFalse(PGPSecretKeyExtensionsKt.isDecrypted(key));
            assertFalse(PGPSecretKeyExtensionsKt.hasDummyS2K(key));
        }

        Iterator<PGPSecretKey> iterator = secretKeys.iterator();
        PGPSecretKey ecdsaPrim = iterator.next();
        assertEquals(EllipticCurve._BRAINPOOLP384R1.getName(), PGPPublicKeyExtensionsKt.getCurveName(ecdsaPrim.getPublicKey()));
        assertEquals(384, ecdsaPrim.getPublicKey().getBitStrength());

        PGPSecretKey eddsaSub = iterator.next();
        assertEquals(EdDSALegacyCurve._Ed25519.getName(), PGPPublicKeyExtensionsKt.getCurveName(eddsaSub.getPublicKey()));
        assertEquals(256, eddsaSub.getPublicKey().getBitStrength());

        PGPSecretKey xdhSub = iterator.next();
        assertEquals(XDHLegacySpec._X25519.getCurveName(), PGPPublicKeyExtensionsKt.getCurveName(xdhSub.getPublicKey()));
        assertEquals(256, xdhSub.getPublicKey().getBitStrength());

        PGPSecretKey rsaSub = iterator.next();
        assertThrows(IllegalArgumentException.class,
                () -> PGPPublicKeyExtensionsKt.getCurveName(rsaSub.getPublicKey()),
                "RSA is not a curve-based encryption system");
        assertEquals(3072, rsaSub.getPublicKey().getBitStrength());
    }

    public PGPSecretKeyRing generateKey(KeySpec primaryKey, KeySpec subKey, String userId) {
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(primaryKey)
                .addSubkey(subKey)
                .addUserId(userId)
                .build()
                .getPGPSecretKeyRing();
        return secretKeys;
    }
}
