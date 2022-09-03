// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpackets;

public class SubkeyBindingSignatureBuilder extends AbstractSignatureBuilder<SubkeyBindingSignatureBuilder> {

    public SubkeyBindingSignatureBuilder(PGPSecretKey signingKey, SecretKeyRingProtector protector)
            throws PGPException {
        super(SignatureType.SUBKEY_BINDING, signingKey, protector);
    }

    public SubkeyBindingSignatureBuilder(PGPSecretKey signingKey, SecretKeyRingProtector protector, HashAlgorithm hashAlgorithm)
            throws PGPException {
        super(SignatureType.SUBKEY_BINDING, signingKey, protector, hashAlgorithm,
                SignatureSubpackets.createHashedSubpackets(signingKey.getPublicKey()),
                SignatureSubpackets.createEmptySubpackets());
    }

    public SubkeyBindingSignatureBuilder(
            PGPSecretKey signingKey,
            SecretKeyRingProtector protector,
            PGPSignature oldSubkeyBinding)
            throws PGPException {
        super(signingKey, protector, requireValidSignatureType(oldSubkeyBinding));
    }

    private static PGPSignature requireValidSignatureType(PGPSignature signature) {
        if (signature.getSignatureType() == SignatureType.SUBKEY_BINDING.getCode()) {
            return signature;
        }
        throw new IllegalArgumentException("Invalid signature type.");
    }

    @Override
    protected boolean isValidSignatureType(SignatureType type) {
        return type == SignatureType.SUBKEY_BINDING;
    }

    public SelfSignatureSubpackets getHashedSubpackets() {
        return hashedSubpackets;
    }

    public SelfSignatureSubpackets getUnhashedSubpackets() {
        return unhashedSubpackets;
    }

    public void applyCallback(@Nullable SelfSignatureSubpackets.Callback callback) {
        if (callback != null) {
            callback.modifyHashedSubpackets(getHashedSubpackets());
            callback.modifyUnhashedSubpackets(getUnhashedSubpackets());
        }
    }

    public PGPSignature build(PGPPublicKey subkey) throws PGPException {
        return buildAndInitSignatureGenerator()
                .generateCertification(publicSigningKey, subkey);
    }
}
