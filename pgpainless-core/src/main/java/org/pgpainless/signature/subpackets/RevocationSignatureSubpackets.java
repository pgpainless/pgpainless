// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.sig.RevocationReason;
import org.pgpainless.key.util.RevocationAttributes;

public interface RevocationSignatureSubpackets extends BaseSignatureSubpackets {

    interface Callback {
        default void modifyHashedSubpackets(RevocationSignatureSubpackets subpackets) {

        }

        default void modifyUnhashedSubpackets(RevocationSignatureSubpackets subpackets) {

        }
    }

    SignatureSubpacketGeneratorWrapper setRevocationReason(RevocationAttributes revocationAttributes);

    SignatureSubpacketGeneratorWrapper setRevocationReason(boolean isCritical, RevocationAttributes revocationAttributes);

    SignatureSubpacketGeneratorWrapper setRevocationReason(boolean isCritical, RevocationAttributes.Reason reason, @Nonnull String description);

    SignatureSubpacketGeneratorWrapper setRevocationReason(@Nullable RevocationReason reason);
}
