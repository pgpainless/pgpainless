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
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;

public final class SignatureBuilder {

    private SignatureBuilder() {

    }

    public static SubkeyBindingSignatureBuilder bindNonSigningSubkey(
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            @Nullable SelfSignatureSubpackets.Callback subkeyBindingSubpacketsCallback,
            KeyFlag... flags) throws WrongPassphraseException {
        if (hasSignDataFlag(flags)) {
            throw new IllegalArgumentException("Binding a subkey with SIGN_DATA flag requires primary key backsig." +
                    "Please use the method bindSigningSubkey().");
        }

        return bindSubkey(primaryKey, primaryKeyProtector, subkeyBindingSubpacketsCallback, flags);
    }

    public static SubkeyBindingSignatureBuilder bindSigningSubkey(
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            PGPSecretKey subkey,
            SecretKeyRingProtector subkeyProtector,
            @Nullable SelfSignatureSubpackets.Callback subkeyBindingSubpacketsCallback,
            @Nullable SelfSignatureSubpackets.Callback primaryKeyBindingSubpacketsCallback,
            KeyFlag... flags)
            throws PGPException, IOException {

        SubkeyBindingSignatureBuilder subkeyBinder = bindSubkey(primaryKey, primaryKeyProtector, subkeyBindingSubpacketsCallback, flags);

        if (hasSignDataFlag(flags)) {
            PGPSignature backsig = createPrimaryKeyBinding(
                    subkey, subkeyProtector, primaryKeyBindingSubpacketsCallback, primaryKey.getPublicKey());
            subkeyBinder.getHashedSubpackets().addEmbeddedSignature(backsig);
        }

        return subkeyBinder;
    }

    private static SubkeyBindingSignatureBuilder bindSubkey(PGPSecretKey primaryKey,
                                                            SecretKeyRingProtector primaryKeyProtector,
                                                            @Nullable SelfSignatureSubpackets.Callback subkeyBindingSubpacketsCallback,
                                                            KeyFlag... flags) throws WrongPassphraseException {
        if (flags.length == 0) {
            throw new IllegalArgumentException("Keyflags for subkey binding cannot be empty.");
        }
        SubkeyBindingSignatureBuilder subkeyBinder = new SubkeyBindingSignatureBuilder(primaryKey, primaryKeyProtector);
        SelfSignatureSubpackets hashedSubpackets = subkeyBinder.getHashedSubpackets();
        SelfSignatureSubpackets unhashedSubpackets = subkeyBinder.getUnhashedSubpackets();
        hashedSubpackets.setKeyFlags(flags);

        if (subkeyBindingSubpacketsCallback != null) {
            subkeyBindingSubpacketsCallback.modifyHashedSubpackets(hashedSubpackets);
            subkeyBindingSubpacketsCallback.modifyUnhashedSubpackets(unhashedSubpackets);
        }

        return subkeyBinder;
    }

    public static PrimaryKeyBindingSignatureBuilder bindPrimaryKey(
            PGPSecretKey subkey,
            SecretKeyRingProtector subkeyProtector,
            @Nullable SelfSignatureSubpackets.Callback primaryKeyBindingSubpacketsCallback) throws WrongPassphraseException {
        PrimaryKeyBindingSignatureBuilder primaryKeyBinder = new PrimaryKeyBindingSignatureBuilder(subkey, subkeyProtector);

        if (primaryKeyBindingSubpacketsCallback != null) {
            primaryKeyBindingSubpacketsCallback.modifyHashedSubpackets(primaryKeyBinder.getHashedSubpackets());
            primaryKeyBindingSubpacketsCallback.modifyUnhashedSubpackets(primaryKeyBinder.getUnhashedSubpackets());
        }

        return primaryKeyBinder;
    }

    public static PGPSignature createPrimaryKeyBinding(
            PGPSecretKey subkey,
            SecretKeyRingProtector subkeyProtector,
            @Nullable SelfSignatureSubpackets.Callback primaryKeyBindingSubpacketsCallback,
            PGPPublicKey primaryKey)
            throws PGPException {
        return bindPrimaryKey(subkey, subkeyProtector, primaryKeyBindingSubpacketsCallback)
                .build(primaryKey);
    }

    public static CertificationSignatureBuilder selfCertifyUserId(
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            @Nullable SelfSignatureSubpackets.Callback selfSignatureCallback,
            KeyFlag... flags) throws WrongPassphraseException {

        CertificationSignatureBuilder certifier = new CertificationSignatureBuilder(primaryKey, primaryKeyProtector);
        certifier.getHashedSubpackets().setKeyFlags(flags);
        if (selfSignatureCallback != null) {
            selfSignatureCallback.modifyHashedSubpackets(certifier.getHashedSubpackets());
            selfSignatureCallback.modifyUnhashedSubpackets(certifier.getUnhashedSubpackets());
        }
        return certifier;
    }

    public static CertificationSignatureBuilder renewSelfCertification(
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            @Nullable SelfSignatureSubpackets.Callback selfSignatureCallback,
            PGPSignature oldCertification) throws WrongPassphraseException {
        CertificationSignatureBuilder certifier =
                new CertificationSignatureBuilder(primaryKey, primaryKeyProtector, oldCertification);

        // TODO
        return null;
    }

    public static PGPSignature createUserIdSelfCertification(
            String userId,
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            @Nullable SelfSignatureSubpackets.Callback selfSignatureCallback,
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
