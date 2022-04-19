// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import java.security.MessageDigest;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;

import javax.annotation.Nonnull;

public class BcHashContextSigner {

    public static PGPSignature signHashContext(@Nonnull MessageDigest hashContext,
                                               @Nonnull SignatureType signatureType,
                                               @Nonnull PGPSecretKeyRing secretKeys,
                                               @Nonnull SecretKeyRingProtector protector)
            throws PGPException {
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        List<PGPPublicKey> signingSubkeyCandidates = info.getSigningSubkeys();
        PGPSecretKey signingKey = null;
        for (PGPPublicKey signingKeyCandidate : signingSubkeyCandidates) {
            signingKey = secretKeys.getSecretKey(signingKeyCandidate.getKeyID());
            if (signingKey != null) {
                break;
            }
        }
        if (signingKey == null) {
            throw new PGPException("Key does not contain suitable signing subkey.");
        }

        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(signingKey, protector);
        return signHashContext(hashContext, signatureType, privateKey);
    }

    /**
     * Create an OpenPGP Signature over the given {@link MessageDigest} hash context.
     *
     * @param hashContext hash context
     * @param privateKey signing-capable key
     * @return signature
     * @throws PGPException in case of an OpenPGP error
     */
    static PGPSignature signHashContext(MessageDigest hashContext, SignatureType signatureType, PGPPrivateKey privateKey)
            throws PGPException {
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new BcPGPHashContextContentSignerBuilder(hashContext)
        );

        sigGen.init(signatureType.getCode(), privateKey);
        return sigGen.generate();
    }
}
