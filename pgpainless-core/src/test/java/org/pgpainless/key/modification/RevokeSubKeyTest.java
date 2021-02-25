/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.util.ArmorUtils;
import org.pgpainless.util.Passphrase;

public class RevokeSubKeyTest {

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void revokeSukeyTest(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();

        Iterator<PGPSecretKey> keysIterator = secretKeys.iterator();
        PGPSecretKey primaryKey = keysIterator.next();
        PGPSecretKey subKey = keysIterator.next();

        assertFalse(subKey.getPublicKey().hasRevocation());

        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys, Passphrase.fromPassword("password123"));

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .revokeSubKey(new OpenPgpV4Fingerprint(subKey), protector)
                .done();
        keysIterator = secretKeys.iterator();
        primaryKey = keysIterator.next();
        subKey = keysIterator.next();

        assertTrue(subKey.getPublicKey().hasRevocation());
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void detachedRevokeSubkeyTest(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(secretKeys);
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector.forKey(secretKeys, Passphrase.fromPassword("password123"));

        PGPSignature revocationCertificate = PGPainless.modifyKeyRing(secretKeys)
                .createRevocationCertificate(fingerprint, protector, RevocationAttributes.createKeyRevocation()
                        .withReason(RevocationAttributes.Reason.KEY_RETIRED)
                        .withDescription("Key no longer used."));

        // CHECKSTYLE:OFF
        System.out.println("Revocation Certificate:");
        System.out.println(ArmorUtils.toAsciiArmoredString(revocationCertificate.getEncoded()));
        // CHECKSTYLE:ON

        PGPPublicKey publicKey = secretKeys.getPublicKey();
        assertFalse(publicKey.hasRevocation());

        publicKey = PGPPublicKey.addCertification(publicKey, revocationCertificate);

        assertTrue(publicKey.hasRevocation());
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void testRevocationSignatureTypeCorrect(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        Iterator<PGPPublicKey> keysIterator = secretKeys.getPublicKeys();
        PGPPublicKey primaryKey = keysIterator.next();
        PGPPublicKey subKey = keysIterator.next();
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys, Passphrase.fromPassword("password123"));

        SecretKeyRingEditorInterface editor = PGPainless.modifyKeyRing(secretKeys);
        PGPSignature keyRevocation = editor.createRevocationCertificate(primaryKey.getKeyID(), protector, null);
        PGPSignature subkeyRevocation = editor.createRevocationCertificate(subKey.getKeyID(), protector, null);

        assertEquals(SignatureType.KEY_REVOCATION.getCode(), keyRevocation.getSignatureType());
        assertEquals(SignatureType.SUBKEY_REVOCATION.getCode(), subkeyRevocation.getSignatureType());
    }

    @Test
    public void testThrowsIfRevocationReasonTypeMismatch() {
        // Key revocation cannot have reason type USER_ID_NO_LONGER_VALID
        assertThrows(IllegalArgumentException.class, () -> RevocationAttributes.createKeyRevocation()
                .withReason(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID));
        // Cert revocations cannot have the reason types KEY_SUPERSEDED, KEY_COMPROMIZED, KEY_RETIRED
        assertThrows(IllegalArgumentException.class, () -> RevocationAttributes.createCertificateRevocation()
                .withReason(RevocationAttributes.Reason.KEY_SUPERSEDED));
        assertThrows(IllegalArgumentException.class, () -> RevocationAttributes.createCertificateRevocation()
                .withReason(RevocationAttributes.Reason.KEY_COMPROMISED));
        assertThrows(IllegalArgumentException.class, () -> RevocationAttributes.createCertificateRevocation()
                .withReason(RevocationAttributes.Reason.KEY_RETIRED));
    }

    @Test
    public void testReasonToString() {
        RevocationAttributes.Reason reason = RevocationAttributes.Reason.KEY_COMPROMISED;
        assertEquals("2 - KEY_COMPROMISED", reason.toString());
    }
}
