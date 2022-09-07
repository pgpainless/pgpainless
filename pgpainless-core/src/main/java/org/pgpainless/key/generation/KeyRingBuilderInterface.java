// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.key.UserId;
import org.pgpainless.s2k.Passphrase;

public interface KeyRingBuilderInterface<B extends KeyRingBuilderInterface<B>> {

    B setPrimaryKey(@Nonnull KeySpec keySpec);

    default B setPrimaryKey(@Nonnull KeySpecBuilder builder) {
        return setPrimaryKey(builder.build());
    }

    B addSubkey(@Nonnull KeySpec keySpec);

    default B addSubkey(@Nonnull KeySpecBuilder builder) {
        return addSubkey(builder.build());
    }

    default B addUserId(UserId userId) {
        return addUserId(userId.toString());
    }

    B addUserId(@Nonnull String userId);

    B addUserId(@Nonnull byte[] userId);

    B setExpirationDate(@Nonnull Date expirationDate);

    B setPassphrase(@Nonnull Passphrase passphrase);

    PGPSecretKeyRing build() throws NoSuchAlgorithmException, PGPException,
                InvalidAlgorithmParameterException;
}
