// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import java.io.IOException;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.BaseSignatureSubpackets;
import org.pgpainless.signature.subpackets.CertificationSubpackets;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;

public final class SignatureFactory {

    private SignatureFactory() {

    }

    public static SubkeyBindingSignatureBuilder bindNonSigningSubkey(
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            @Nullable SelfSignatureSubpackets.Callback subkeyBindingSubpacketsCallback,
            KeyFlag... flags) throws WrongPassphraseException {
        if (hasSignDataFlag(flags)) {
            throw new IllegalArgumentException("Binding a subkey with SIGN_DATA flag requires primary key backsig.\n" +
                    "Please use the method bindSigningSubkey() instead.");
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
            PGPSignature backsig = bindPrimaryKey(
                    subkey, subkeyProtector, primaryKeyBindingSubpacketsCallback)
                    .build(primaryKey.getPublicKey());
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
        hashedSubpackets.setKeyFlags(flags);

        subkeyBinder.applyCallback(subkeyBindingSubpacketsCallback);

        return subkeyBinder;
    }

    public static PrimaryKeyBindingSignatureBuilder bindPrimaryKey(
            PGPSecretKey subkey,
            SecretKeyRingProtector subkeyProtector,
            @Nullable SelfSignatureSubpackets.Callback primaryKeyBindingSubpacketsCallback) throws WrongPassphraseException {
        PrimaryKeyBindingSignatureBuilder primaryKeyBinder = new PrimaryKeyBindingSignatureBuilder(subkey, subkeyProtector);

        primaryKeyBinder.applyCallback(primaryKeyBindingSubpacketsCallback);

        return primaryKeyBinder;
    }

    public static SelfSignatureBuilder selfCertifyUserId(
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            @Nullable SelfSignatureSubpackets.Callback selfSignatureCallback,
            KeyFlag... flags) throws WrongPassphraseException {

        SelfSignatureBuilder certifier = new SelfSignatureBuilder(SignatureType.POSITIVE_CERTIFICATION, primaryKey, primaryKeyProtector);
        certifier.getHashedSubpackets().setKeyFlags(flags);

        certifier.applyCallback(selfSignatureCallback);

        return certifier;
    }

    public static SelfSignatureBuilder renewSelfCertification(
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            @Nullable SelfSignatureSubpackets.Callback selfSignatureCallback,
            PGPSignature oldCertification) throws WrongPassphraseException {
        SelfSignatureBuilder certifier = new SelfSignatureBuilder(
                primaryKey, primaryKeyProtector, oldCertification);

        certifier.applyCallback(selfSignatureCallback);

        return certifier;
    }

    public static CertificationSignatureBuilder certifyUserId(
            PGPSecretKey signingKey,
            SecretKeyRingProtector signingKeyProtector,
            @Nullable CertificationSubpackets.Callback subpacketsCallback)
            throws WrongPassphraseException {
        CertificationSignatureBuilder certifier = new CertificationSignatureBuilder(signingKey, signingKeyProtector);

        certifier.applyCallback(subpacketsCallback);

        return certifier;
    }

    public static UniversalSignatureBuilder universalSignature(
            SignatureType signatureType,
            PGPSecretKey signingKey,
            SecretKeyRingProtector signingKeyProtector,
            @Nullable BaseSignatureSubpackets.Callback callback)
            throws WrongPassphraseException {
        UniversalSignatureBuilder builder =
                new UniversalSignatureBuilder(signatureType, signingKey, signingKeyProtector);

        builder.applyCallback(callback);

        return builder;
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
