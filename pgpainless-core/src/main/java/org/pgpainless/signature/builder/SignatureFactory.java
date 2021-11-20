// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import java.util.List;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;

public final class SignatureFactory {

    private SignatureFactory() {

    }

    public static SelfSignatureBuilder selfCertifyUserId(
            PGPSecretKey primaryKey,
            SecretKeyRingProtector primaryKeyProtector,
            @Nullable SelfSignatureSubpackets.Callback selfSignatureCallback,
            List<KeyFlag> keyFlags)
            throws WrongPassphraseException {
        KeyFlag[] keyFlagArray = keyFlags.toArray(new KeyFlag[0]);
        return selfCertifyUserId(primaryKey, primaryKeyProtector, selfSignatureCallback, keyFlagArray);
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

}
