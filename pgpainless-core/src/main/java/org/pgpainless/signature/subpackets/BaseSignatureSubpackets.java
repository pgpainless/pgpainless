// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import java.io.IOException;
import java.net.URL;
import java.util.Date;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.sig.EmbeddedSignature;
import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PolicyURI;
import org.bouncycastle.bcpg.sig.RegularExpression;
import org.bouncycastle.bcpg.sig.Revocable;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignatureTarget;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;

public interface BaseSignatureSubpackets {

    interface Callback extends SignatureSubpacketCallback<BaseSignatureSubpackets> {

    }

    /**
     * Add both an {@link IssuerKeyID} and {@link IssuerFingerprint} subpacket pointing to the given key.
     *
     * @param key key
     * @return this
     *
     * @deprecated this method MUST NOT be used for OpenPGP v6, since v6 signatures MUST NOT contain any
     * {@link IssuerKeyID} packets.
     */
    BaseSignatureSubpackets setIssuerFingerprintAndKeyId(PGPPublicKey key);

    BaseSignatureSubpackets setIssuerKeyId(long keyId);

    BaseSignatureSubpackets setIssuerKeyId(boolean isCritical, long keyId);

    BaseSignatureSubpackets setIssuerKeyId(@Nullable IssuerKeyID issuerKeyID);

    BaseSignatureSubpackets setIssuerFingerprint(@Nonnull PGPPublicKey key);

    BaseSignatureSubpackets setIssuerFingerprint(boolean isCritical, @Nonnull PGPPublicKey key);

    BaseSignatureSubpackets setIssuerFingerprint(@Nullable IssuerFingerprint fingerprint);

    BaseSignatureSubpackets setSignatureCreationTime(@Nonnull Date creationTime);

    BaseSignatureSubpackets setSignatureCreationTime(boolean isCritical, @Nonnull Date creationTime);

    BaseSignatureSubpackets setSignatureCreationTime(@Nullable SignatureCreationTime signatureCreationTime);

    BaseSignatureSubpackets setSignatureExpirationTime(@Nonnull Date creationTime, @Nonnull Date expirationTime);

    BaseSignatureSubpackets setSignatureExpirationTime(boolean isCritical, @Nonnull Date creationTime, @Nonnull Date expirationTime);

    BaseSignatureSubpackets setSignatureExpirationTime(boolean isCritical, long seconds);

    BaseSignatureSubpackets setSignatureExpirationTime(@Nullable SignatureExpirationTime expirationTime);

    BaseSignatureSubpackets setSignerUserId(@Nonnull String userId);

    BaseSignatureSubpackets setSignerUserId(boolean isCritical, @Nonnull String userId);

    BaseSignatureSubpackets setSignerUserId(@Nullable SignerUserID signerUserId);

    BaseSignatureSubpackets addNotationData(boolean isCritical, @Nonnull String notationName, @Nonnull String notationValue);

    BaseSignatureSubpackets addNotationData(boolean isCritical, boolean isHumanReadable, @Nonnull String notationName, @Nonnull String notationValue);

    BaseSignatureSubpackets addNotationData(@Nonnull NotationData notationData);

    BaseSignatureSubpackets clearNotationData();

    BaseSignatureSubpackets addIntendedRecipientFingerprint(@Nonnull PGPPublicKey recipient);

    BaseSignatureSubpackets addIntendedRecipientFingerprint(boolean isCritical, @Nonnull PGPPublicKey recipient);

    BaseSignatureSubpackets addIntendedRecipientFingerprint(IntendedRecipientFingerprint intendedRecipientFingerprint);

    BaseSignatureSubpackets clearIntendedRecipientFingerprints();

    BaseSignatureSubpackets setExportable(boolean isExportable);

    BaseSignatureSubpackets setExportable(boolean isCritical, boolean isExportable);

    BaseSignatureSubpackets setExportable(@Nullable Exportable exportable);

    BaseSignatureSubpackets setPolicyUrl(@Nonnull URL policyUrl);

    BaseSignatureSubpackets setPolicyUrl(boolean isCritical, @Nonnull URL policyUrl);

    BaseSignatureSubpackets setPolicyUrl(@Nullable PolicyURI policyUrl);

    BaseSignatureSubpackets setRegularExpression(@Nonnull String regex);

    BaseSignatureSubpackets setRegularExpression(boolean isCritical, @Nonnull String regex);

    BaseSignatureSubpackets setRegularExpression(@Nullable RegularExpression regex);

    BaseSignatureSubpackets setRevocable(boolean revocable);

    BaseSignatureSubpackets setRevocable(boolean isCritical, boolean isRevocable);

    BaseSignatureSubpackets setRevocable(@Nullable Revocable revocable);

    BaseSignatureSubpackets setSignatureTarget(@Nonnull PublicKeyAlgorithm keyAlgorithm, @Nonnull HashAlgorithm hashAlgorithm, @Nonnull byte[] hashData);

    BaseSignatureSubpackets setSignatureTarget(boolean isCritical, @Nonnull PublicKeyAlgorithm keyAlgorithm, @Nonnull HashAlgorithm hashAlgorithm, @Nonnull byte[] hashData);

    BaseSignatureSubpackets setSignatureTarget(@Nullable SignatureTarget signatureTarget);

    BaseSignatureSubpackets setTrust(int depth, int amount);

    BaseSignatureSubpackets setTrust(boolean isCritical, int depth, int amount);

    BaseSignatureSubpackets setTrust(@Nullable TrustSignature trust);

    BaseSignatureSubpackets addEmbeddedSignature(@Nonnull PGPSignature signature) throws IOException;

    BaseSignatureSubpackets addEmbeddedSignature(boolean isCritical, @Nonnull PGPSignature signature) throws IOException;

    BaseSignatureSubpackets addEmbeddedSignature(@Nonnull EmbeddedSignature embeddedSignature);

    BaseSignatureSubpackets clearEmbeddedSignatures();
}
