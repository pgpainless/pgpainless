// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;

/**
 * Test functionality of the {@link MissingPublicKeyCallback} which is called when during signature verification,
 * a signature is encountered which was made by a key that was not provided in
 * {@link ConsumerOptions#addVerificationCert(PGPPublicKeyRing)}.
 */
public class VerifyWithMissingPublicKeyCallbackTest {

    @Test
    public void testMissingPublicKeyCallback() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing signingSecKeys = PGPainless.generateKeyRing().modernKeyRing("alice");
        PGPPublicKey signingKey = new KeyRingInfo(signingSecKeys).getSigningSubkeys().get(0);
        PGPPublicKeyRing signingPubKeys = KeyRingUtils.publicKeyRingFrom(signingSecKeys);
        PGPPublicKeyRing unrelatedKeys = TestKeys.getJulietPublicKeyRing();

        String msg = "Arguing that you don't care about the right to privacy because you have nothing to hide" +
                "is no different than saying you don't care about free speech because you have nothing to say.";
        ByteArrayOutputStream signOut = new ByteArrayOutputStream();
        EncryptionStream signingStream = PGPainless.encryptAndOrSign().onOutputStream(signOut)
                .withOptions(ProducerOptions.sign(new SigningOptions().addInlineSignature(
                        SecretKeyRingProtector.unprotectedKeys(),
                        signingSecKeys, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT
                )));
        Streams.pipeAll(new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8)), signingStream);
        signingStream.close();

        DecryptionStream verificationStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(signOut.toByteArray()))
                .withOptions(new ConsumerOptions()
                        .addVerificationCert(unrelatedKeys)
                        .setMissingCertificateCallback(new MissingPublicKeyCallback() {
                            @Nullable
                            @Override
                            public PGPPublicKeyRing onMissingPublicKeyEncountered(@Nonnull Long keyId) {
                                assertEquals(signingKey.getKeyID(), (long) keyId, "Signing key-ID mismatch.");
                                return signingPubKeys;
                            }
                        }));

        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(verificationStream, plainOut);
        verificationStream.close();

        assertArrayEquals(msg.getBytes(StandardCharsets.UTF_8), plainOut.toByteArray());
        OpenPgpMetadata metadata = verificationStream.getResult();
        assertTrue(metadata.containsVerifiedSignatureFrom(signingPubKeys));
    }
}
