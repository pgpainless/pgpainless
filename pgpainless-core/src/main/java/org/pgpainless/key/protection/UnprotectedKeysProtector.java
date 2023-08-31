// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import javax.annotation.Nullable;

import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;

/**
 * Implementation of the {@link SecretKeyRingProtector} which assumes that all handled keys are not password protected.
 */
public class UnprotectedKeysProtector implements SecretKeyRingProtector {

    @Override
    public boolean hasPassphraseFor(long keyId) {
        return true;
    }

    @Override
    @Nullable
    public PBESecretKeyDecryptor getDecryptor(long keyId) {
        return null;
    }

    @Override
    @Nullable
    public PBESecretKeyEncryptor getEncryptor(long keyId) {
        return null;
    }
}
