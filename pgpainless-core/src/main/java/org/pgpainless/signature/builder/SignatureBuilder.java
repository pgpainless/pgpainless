// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import java.io.IOException;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.BindingSignatureCallback;
import org.pgpainless.signature.subpackets.SelfSignatureCallback;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;

public class SignatureBuilder {

    public SubkeyBindingSignatureBuilder bindSubkey(
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            PGPSecretKey subkey,
            SecretKeyRingProtector subkeyProtector,
            @Nullable BindingSignatureCallback subkeyBindingSubpacketsCallback,
            @Nullable BindingSignatureCallback primaryKeyBindingSubpacketsCallback,
            KeyFlag... flags)
            throws PGPException, IOException {
        if (flags.length == 0) {
            throw new IllegalArgumentException("Keyflags for subkey binding cannot be empty.");
        }
        SubkeyBindingSignatureBuilder subkeyBinder = new SubkeyBindingSignatureBuilder(primaryKey, primaryKeyProtector);

        SelfSignatureSubpackets hashedSubpackets = subkeyBinder.getHashedSubpackets();
        SelfSignatureSubpackets unhashedSubpackets = subkeyBinder.getUnhashedSubpackets();
        hashedSubpackets.setKeyFlags(flags);

        if (hasSignDataFlag(flags)) {
            PGPSignature backsig = createPrimaryKeyBinding(
                    subkey, subkeyProtector, primaryKeyBindingSubpacketsCallback, primaryKey.getPublicKey());
            hashedSubpackets.addEmbeddedSignature(backsig);
        }

        if (subkeyBindingSubpacketsCallback != null) {
            subkeyBindingSubpacketsCallback.modifyHashedSubpackets(hashedSubpackets);
            subkeyBindingSubpacketsCallback.modifyUnhashedSubpackets(unhashedSubpackets);
        }

        return subkeyBinder;
    }

    public PrimaryKeyBindingSignatureBuilder bindPrimaryKey(
            PGPSecretKey subkey,
            SecretKeyRingProtector subkeyProtector,
            @Nullable BindingSignatureCallback primaryKeyBindingSubpacketsCallback) throws WrongPassphraseException {
        PrimaryKeyBindingSignatureBuilder primaryKeyBinder = new PrimaryKeyBindingSignatureBuilder(subkey, subkeyProtector);

        if (primaryKeyBindingSubpacketsCallback != null) {
            primaryKeyBindingSubpacketsCallback.modifyHashedSubpackets(primaryKeyBinder.getHashedSubpackets());
            primaryKeyBindingSubpacketsCallback.modifyUnhashedSubpackets(primaryKeyBinder.getUnhashedSubpackets());
        }

        return primaryKeyBinder;
    }

    public PGPSignature createPrimaryKeyBinding(
            PGPSecretKey subkey,
            SecretKeyRingProtector subkeyProtector,
            @Nullable BindingSignatureCallback primaryKeyBindingSubpacketsCallback,
            PGPPublicKey primaryKey)
            throws PGPException {
        return bindPrimaryKey(subkey, subkeyProtector, primaryKeyBindingSubpacketsCallback)
                .build(primaryKey);
    }

    public CertificationSignatureBuilder selfCertifyUserId(
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            @Nullable SelfSignatureCallback selfSignatureCallback,
            KeyFlag... flags) throws WrongPassphraseException {

        CertificationSignatureBuilder certifier = new CertificationSignatureBuilder(primaryKey, primaryKeyProtector);
        certifier.getHashedSubpackets().setKeyFlags(flags);
        if (selfSignatureCallback != null) {
            selfSignatureCallback.modifyHashedSubpackets(certifier.getHashedSubpackets());
            selfSignatureCallback.modifyUnhashedSubpackets(certifier.getUnhashedSubpackets());
        }
        return certifier;
    }

    public CertificationSignatureBuilder renewSelfCertification(
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            @Nullable SelfSignatureCallback selfSignatureCallback,
            PGPSignature oldCertification) throws WrongPassphraseException {
        CertificationSignatureBuilder certifier =
                new CertificationSignatureBuilder(primaryKey, primaryKeyProtector, oldCertification);

        // TODO
        return null;
    }

    public PGPSignature createUserIdSelfCertification(
            String userId,
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            @Nullable SelfSignatureCallback selfSignatureCallback,
            KeyFlag... flags)
            throws PGPException {
        return selfCertifyUserId(primaryKey, primaryKeyProtector, selfSignatureCallback, flags)
                .build(primaryKey.getPublicKey(), userId);
    }

    private static boolean hasSignDataFlag(KeyFlag... flags) {
        if (flags == null) {
            return false;
        }
        for (KeyFlag flag : flags) {
            if (flag == KeyFlag.SIGN_DATA) {
                return true;
            }
        }
        return false;
    }
}
