// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.authentication.CertificateAuthenticity;
import org.pgpainless.authentication.CertificateAuthority;
import org.pgpainless.authentication.CertificationChain;
import org.pgpainless.authentication.ChainLink;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.TestAllImplementations;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class VerifyWithCertificateAuthorityTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testVerifySignatureFromAuthenticatedCert() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey aliceKey = api.generateKey().modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPCertificate aliceCert = aliceKey.toCertificate();

        SimpleCertificateAuthority authority = new SimpleCertificateAuthority();
        authority.addDirectlyAuthenticatedCert(aliceCert, 120);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        EncryptionStream eOut = api.generateMessage()
                .onOutputStream(bOut)
                .withOptions(ProducerOptions.signAndEncrypt(
                        EncryptionOptions.encryptCommunications()
                                .addAuthenticatableRecipients("Alice <alice@pgpainless.org>", false, authority),
                        SigningOptions.get().addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), aliceKey)
                ));

        eOut.write("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        eOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DecryptionStream dIn = api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get()
                        .addVerificationCert(aliceCert)
                        .addDecryptionKey(aliceKey));
        Streams.drain(dIn);
        dIn.close();

        MessageMetadata metadata = dIn.getMetadata();
        assertTrue(metadata.isEncryptedFor(aliceCert));

        assertTrue(metadata.isAuthenticatablySignedBy("Alice <alice@pgpainless.org>", false, authority));
        assertTrue(metadata.isAuthenticatablySignedBy("alice@pgpainless.org", true, authority));
        assertFalse(metadata.isAuthenticatablySignedBy("mallory@pgpainless.org", true, authority));
    }

    public static class SimpleCertificateAuthority implements CertificateAuthority {

        Map<OpenPGPCertificate, Integer> directlyAuthenticatedCerts = new HashMap<>();

        public void addDirectlyAuthenticatedCert(OpenPGPCertificate cert, int trustAmount) {
            directlyAuthenticatedCerts.put(cert, trustAmount);
        }

        @Override
        public CertificateAuthenticity authenticateBinding(
                @NotNull KeyIdentifier certIdentifier,
                @NotNull CharSequence userId,
                boolean email,
                @NotNull Date referenceTime,
                int targetAmount) {
            Optional<OpenPGPCertificate> opt = directlyAuthenticatedCerts.keySet().stream()
                    .filter(it -> it.getKey(certIdentifier) != null)
                    .findFirst();
            if (opt.isEmpty()) {
                return null;
            }

            OpenPGPCertificate cert = opt.get();
            Optional<OpenPGPCertificate.OpenPGPUserId> uid;
            if (email) {
                uid = cert.getAllUserIds().stream().filter(it -> it.getUserId().contains("<" + userId + ">"))
                        .findFirst();
            } else {
                uid = cert.getAllUserIds().stream().filter(it -> it.getUserId().contentEquals(userId))
                        .findFirst();
            }
            return uid.map(openPGPUserId -> authenticatedUserId(openPGPUserId, targetAmount)).orElse(null);
        }

        @NotNull
        @Override
        public List<CertificateAuthenticity> lookupByUserId(
                @NotNull CharSequence userId,
                boolean email,
                @NotNull Date referenceTime,
                int targetAmount) {
            List<CertificateAuthenticity> matches = new ArrayList<>();

            for (OpenPGPCertificate cert : directlyAuthenticatedCerts.keySet()) {
                cert.getAllUserIds()
                        .stream().filter(it -> {
                            if (email) return it.getUserId().contains("<" + userId + ">");
                            else return it.getUserId().contentEquals(userId);
                        }).forEach(it -> {
                            matches.add(authenticatedUserId(it, targetAmount));
                        });
            }
            return matches;
        }

        @NotNull
        @Override
        public List<CertificateAuthenticity> identifyByFingerprint(
                @NotNull KeyIdentifier certIdentifier,
                @NotNull Date referenceTime,
                int targetAmount) {
            List<CertificateAuthenticity> matches = new ArrayList<>();

            directlyAuthenticatedCerts.keySet()
                    .stream().filter(it -> it.getKey(certIdentifier) != null)
                    .forEach(it -> {
                        for (OpenPGPCertificate.OpenPGPUserId userId : it.getAllUserIds()) {
                            matches.add(authenticatedUserId(userId, targetAmount));
                        }
                    });

            return matches;
        }

        private CertificateAuthenticity authenticatedUserId(OpenPGPCertificate.OpenPGPUserId userId, int targetAmount) {
            OpenPGPCertificate cert = userId.getCertificate();
            int certTrust = directlyAuthenticatedCerts.get(cert);
            Map<CertificationChain, Integer> chains = new HashMap<>();
            chains.put(new CertificationChain(certTrust, Collections.singletonList(new ChainLink(cert))), certTrust);
            return new CertificateAuthenticity(userId.getUserId(), cert, chains, targetAmount);
        }
    }
}
