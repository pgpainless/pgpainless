// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import java.io.IOException;
import java.util.Date;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.sig.EmbeddedSignature;
import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.NotationData;
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

    SignatureSubpacketGeneratorWrapper setIssuerFingerprintAndKeyId(PGPPublicKey key);

    SignatureSubpacketGeneratorWrapper setIssuerKeyId(long keyId);

    SignatureSubpacketGeneratorWrapper setIssuerKeyId(boolean isCritical, long keyId);

    SignatureSubpacketGeneratorWrapper setIssuerKeyId(@Nullable IssuerKeyID issuerKeyID);

    SignatureSubpacketGeneratorWrapper setIssuerFingerprint(@Nonnull PGPPublicKey key);

    SignatureSubpacketGeneratorWrapper setIssuerFingerprint(boolean isCritical, @Nonnull PGPPublicKey key);

    SignatureSubpacketGeneratorWrapper setIssuerFingerprint(@Nullable IssuerFingerprint fingerprint);

    SignatureSubpacketGeneratorWrapper setSignatureCreationTime(@Nonnull Date creationTime);

    SignatureSubpacketGeneratorWrapper setSignatureCreationTime(boolean isCritical, @Nonnull Date creationTime);

    SignatureSubpacketGeneratorWrapper setSignatureCreationTime(@Nullable SignatureCreationTime signatureCreationTime);

    SignatureSubpacketGeneratorWrapper setSignatureExpirationTime(@Nonnull Date creationTime, @Nonnull Date expirationTime);

    SignatureSubpacketGeneratorWrapper setSignatureExpirationTime(boolean isCritical, @Nonnull Date creationTime, @Nonnull Date expirationTime);

    SignatureSubpacketGeneratorWrapper setSignatureExpirationTime(boolean isCritical, long seconds);

    SignatureSubpacketGeneratorWrapper setSignatureExpirationTime(@Nullable SignatureExpirationTime expirationTime);

    SignatureSubpacketGeneratorWrapper setSignerUserId(@Nonnull String userId);

    SignatureSubpacketGeneratorWrapper setSignerUserId(boolean isCritical, @Nonnull String userId);

    SignatureSubpacketGeneratorWrapper setSignerUserId(@Nullable SignerUserID signerUserId);

    SignatureSubpacketGeneratorWrapper addNotationData(boolean isCritical, @Nonnull String notationName, @Nonnull String notationValue);

    SignatureSubpacketGeneratorWrapper addNotationData(@Nonnull NotationData notationData);

    SignatureSubpacketGeneratorWrapper clearNotationData();

    SignatureSubpacketGeneratorWrapper addIntendedRecipientFingerprint(@Nonnull PGPPublicKey recipient);

    SignatureSubpacketGeneratorWrapper addIntendedRecipientFingerprint(boolean isCritical, @Nonnull PGPPublicKey recipient);

    SignatureSubpacketGeneratorWrapper addIntendedRecipientFingerprint(IntendedRecipientFingerprint intendedRecipientFingerprint);

    SignatureSubpacketGeneratorWrapper clearIntendedRecipientFingerprints();

    SignatureSubpacketGeneratorWrapper setExportable(boolean isCritical, boolean isExportable);

    SignatureSubpacketGeneratorWrapper setExportable(@Nullable Exportable exportable);

    SignatureSubpacketGeneratorWrapper setRevocable(boolean isCritical, boolean isRevocable);

    SignatureSubpacketGeneratorWrapper setRevocable(@Nullable Revocable revocable);

    SignatureSubpacketGeneratorWrapper setSignatureTarget(@Nonnull PublicKeyAlgorithm keyAlgorithm, @Nonnull HashAlgorithm hashAlgorithm, @Nonnull byte[] hashData);

    SignatureSubpacketGeneratorWrapper setSignatureTarget(boolean isCritical, @Nonnull PublicKeyAlgorithm keyAlgorithm, @Nonnull HashAlgorithm hashAlgorithm, @Nonnull byte[] hashData);

    SignatureSubpacketGeneratorWrapper setSignatureTarget(@Nullable SignatureTarget signatureTarget);

    SignatureSubpacketGeneratorWrapper setTrust(int depth, int amount);

    SignatureSubpacketGeneratorWrapper setTrust(boolean isCritical, int depth, int amount);

    SignatureSubpacketGeneratorWrapper setTrust(@Nullable TrustSignature trust);

    SignatureSubpacketGeneratorWrapper addEmbeddedSignature(@Nonnull PGPSignature signature) throws IOException;

    SignatureSubpacketGeneratorWrapper addEmbeddedSignature(boolean isCritical, @Nonnull PGPSignature signature) throws IOException;

    SignatureSubpacketGeneratorWrapper addEmbeddedSignature(@Nonnull EmbeddedSignature embeddedSignature);

    SignatureSubpacketGeneratorWrapper clearEmbeddedSignatures();
}
