// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.SignatureParameters;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.CertificationSubpackets;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Unfortunately, with the switch to BCs new high level API, PGPainless releases 2.0.0, 2.0.1 and 2.0.2 suffer
 * from a bug where the certificate evaluation logic accidentally tries to evaluate third-party signatures,
 * causing breakage as certificate preferences and key flags can no longer be determined properly.
 *
 * @see <a href="https://github.com/pgpainless/pgpainless/issues/498">PGPainless bug report</a>
 * @see <a href="https://github.com/bcgit/bc-java/pull/2217">Bouncy Castle patch</a>
 */
public class CertificateWith3rdPartySigsRegressionTest {

    @Test
    public void testRegression() throws PGPException {
        PGPainless api = PGPainless.getInstance();
        Date now = new Date();
        Date twoHourAgo = new Date(now.getTime() - 1000 * 60 * 60 * 2);
        Date oneHourAgo = new Date(now.getTime() - 1000 * 60 * 60);

        // Create test keys at t-2
        OpenPGPKey aliceKey = api._buildKey(OpenPGPKeyVersion.v4, twoHourAgo)
                .withPrimaryKey(
                        PGPKeyPairGenerator::generateEd25519KeyPair,
                        new SignatureParameters.Callback() {
                            @Override
                            public SignatureParameters apply(SignatureParameters parameters) {
                                return null; // no dk sig
                            }
                        })
                .addEncryptionSubkey()
                .addUserId("Alice", SignatureParameters.Callback.Util.modifyHashedSubpackets(s -> {
                    s.setKeyFlags(KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
                    return s;
                }))
                .build();
        OpenPGPKey bobKey = api.generateKey(OpenPGPKeyVersion.v4, twoHourAgo)
                .modernKeyRing("Bob");
        // Check that alice can sign
        assertFalse(api.inspect(aliceKey.toCertificate()).getSigningSubkeys().isEmpty(),
                "Fresh key is expected to be able to sign.");

        // Create a third-party sig on Alice at t-1
        OpenPGPCertificate aliceSigned = api.generateCertification()
                .certifyUserId("Alice", aliceKey.toCertificate())
                .withKey(bobKey, SecretKeyRingProtector.unprotectedKeys())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(@NotNull CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.setSignatureCreationTime(oneHourAgo);
                    }
                })
                .getCertifiedCertificate();

        // Inspect alice at t-0 and check if it can still sign
        KeyRingInfo info = api.inspect(aliceSigned);
        assertFalse(info.getSigningSubkeys().isEmpty(),
                "A recent 3rd party signature MUST NOT alter the capability of the key to sign.");
    }
}
