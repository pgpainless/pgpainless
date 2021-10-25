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
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.BindingSignatureCallback;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;

public class SignatureBuilder {

    public SubkeyBindingSignatureBuilder subkeyBindingSignatureBuilder(
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
        SubkeyBindingSignatureBuilder subkeyBindingBuilder = new SubkeyBindingSignatureBuilder(primaryKey, primaryKeyProtector);

        SelfSignatureSubpackets hashedSubpackets = subkeyBindingBuilder.getHashedSubpackets();
        hashedSubpackets.setKeyFlags(flags);

        boolean isSigningKey = false;
        for (KeyFlag flag : flags) {
            if (flag == KeyFlag.SIGN_DATA) {
                isSigningKey = true;
                break;
            }
        }
        if (isSigningKey) {
            PGPSignature backsig = primaryKeyBindingSignature(
                    subkey, subkeyProtector, primaryKey.getPublicKey(), primaryKeyBindingSubpacketsCallback);
            hashedSubpackets.addEmbeddedSignature(backsig);
        }

        if (subkeyBindingSubpacketsCallback != null) {
            subkeyBindingSubpacketsCallback.modifyHashedSubpackets(subkeyBindingBuilder.getHashedSubpackets());
            subkeyBindingSubpacketsCallback.modifyUnhashedSubpackets(subkeyBindingBuilder.getUnhashedSubpackets());
        }

        return subkeyBindingBuilder;
    }

    public PGPSignature primaryKeyBindingSignature(
            PGPSecretKey subkey,
            SecretKeyRingProtector subkeyProtector,
            PGPPublicKey primaryKey,
            BindingSignatureCallback primaryKeyBindingSubpacketsCallback) throws PGPException {

        PrimaryKeyBindingSignatureBuilder builder = new PrimaryKeyBindingSignatureBuilder(subkey, subkeyProtector);
        if (primaryKeyBindingSubpacketsCallback != null) {
            primaryKeyBindingSubpacketsCallback.modifyHashedSubpackets(builder.getHashedSubpackets());
            primaryKeyBindingSubpacketsCallback.modifyUnhashedSubpackets(builder.getUnhashedSubpackets());
        }

        return builder.build(primaryKey);
    }

}
