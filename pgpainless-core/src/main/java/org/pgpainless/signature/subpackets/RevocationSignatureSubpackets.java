// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.sig.RevocationReason;
import org.pgpainless.key.util.RevocationAttributes;

public interface RevocationSignatureSubpackets extends BaseSignatureSubpackets {

    interface Callback extends SignatureSubpacketCallback<RevocationSignatureSubpackets> {

    }

    RevocationSignatureSubpackets setRevocationReason(RevocationAttributes revocationAttributes);

    RevocationSignatureSubpackets setRevocationReason(boolean isCritical, RevocationAttributes revocationAttributes);

    RevocationSignatureSubpackets setRevocationReason(boolean isCritical, RevocationAttributes.Reason reason, @Nonnull String description);

    RevocationSignatureSubpackets setRevocationReason(@Nullable RevocationReason reason);
}
