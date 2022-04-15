// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import java.security.MessageDigest;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.pgpainless.algorithm.SignatureType;

public class HashContextSigner {

    /**
     * Create an OpenPGP Signature over the given {@link MessageDigest} hash context.
     *
     * WARNING: This method does not yet validate the signing key.
     * TODO: Change API to receive and evaluate PGPSecretKeyRing + SecretKeyRingProtector instead.
     *
     * @param hashContext hash context
     * @param privateKey signing-capable key
     * @return signature
     * @throws PGPException in case of an OpenPGP error
     */
    public static PGPSignature signHashContext(MessageDigest hashContext, SignatureType signatureType, PGPPrivateKey privateKey)
            throws PGPException {
        // TODO: Validate signing key
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new HashContextPGPContentSignerBuilder(hashContext)
        );

        sigGen.init(signatureType.getCode(), privateKey);
        return sigGen.generate();
    }
}
