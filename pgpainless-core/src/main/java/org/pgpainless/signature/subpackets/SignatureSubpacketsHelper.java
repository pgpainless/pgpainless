// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.sig.EmbeddedSignature;
import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PolicyURI;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.RegularExpression;
import org.bouncycastle.bcpg.sig.Revocable;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignatureTarget;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.util.RevocationAttributes;

public class SignatureSubpacketsHelper {

    public static SignatureSubpackets applyFrom(PGPSignatureSubpacketVector vector, SignatureSubpackets subpackets) {
        for (SignatureSubpacket subpacket : vector.toArray()) {
            org.pgpainless.algorithm.SignatureSubpacket type = org.pgpainless.algorithm.SignatureSubpacket.requireFromCode(subpacket.getType());
            switch (type) {
                case signatureCreationTime:
                case issuerKeyId:
                case issuerFingerprint:
                    // ignore, we override this anyways
                    break;
                case signatureExpirationTime:
                    SignatureExpirationTime sigExpTime = (SignatureExpirationTime) subpacket;
                    subpackets.setSignatureExpirationTime(sigExpTime.isCritical(), sigExpTime.getTime());
                    break;
                case exportableCertification:
                    Exportable exp = (Exportable) subpacket;
                    subpackets.setExportable(exp.isCritical(), exp.isExportable());
                    break;
                case trustSignature:
                    TrustSignature trustSignature = (TrustSignature) subpacket;
                    subpackets.setTrust(trustSignature.isCritical(), trustSignature.getDepth(), trustSignature.getTrustAmount());
                    break;
                case revocable:
                    Revocable rev = (Revocable) subpacket;
                    subpackets.setRevocable(rev.isCritical(), rev.isRevocable());
                    break;
                case keyExpirationTime:
                    KeyExpirationTime keyExpTime = (KeyExpirationTime) subpacket;
                    subpackets.setKeyExpirationTime(keyExpTime.isCritical(), keyExpTime.getTime());
                    break;
                case preferredSymmetricAlgorithms:
                    subpackets.setPreferredSymmetricKeyAlgorithms((PreferredAlgorithms) subpacket);
                    break;
                case revocationKey:
                    RevocationKey revocationKey = (RevocationKey) subpacket;
                    subpackets.addRevocationKey(revocationKey);
                    break;
                case notationData:
                    NotationData notationData = (NotationData) subpacket;
                    subpackets.addNotationData(notationData.isCritical(), notationData.getNotationName(), notationData.getNotationValue());
                    break;
                case preferredHashAlgorithms:
                    subpackets.setPreferredHashAlgorithms((PreferredAlgorithms) subpacket);
                    break;
                case preferredCompressionAlgorithms:
                    subpackets.setPreferredCompressionAlgorithms((PreferredAlgorithms) subpacket);
                    break;
                case primaryUserId:
                    PrimaryUserID primaryUserID = (PrimaryUserID) subpacket;
                    subpackets.setPrimaryUserId(primaryUserID);
                    break;
                case keyFlags:
                    KeyFlags flags = (KeyFlags) subpacket;
                    subpackets.setKeyFlags(flags.isCritical(), KeyFlag.fromBitmask(flags.getFlags()).toArray(new KeyFlag[0]));
                    break;
                case signerUserId:
                    SignerUserID signerUserID = (SignerUserID) subpacket;
                    subpackets.setSignerUserId(signerUserID.isCritical(), signerUserID.getID());
                    break;
                case revocationReason:
                    RevocationReason reason = (RevocationReason) subpacket;
                    subpackets.setRevocationReason(reason.isCritical(),
                            RevocationAttributes.Reason.fromCode(reason.getRevocationReason()),
                            reason.getRevocationDescription());
                    break;
                case features:
                    Features f = (Features) subpacket;
                    subpackets.setFeatures(f.isCritical(), Feature.fromBitmask(f.getData()[0]).toArray(new Feature[0]));
                    break;
                case signatureTarget:
                    SignatureTarget target = (SignatureTarget) subpacket;
                    subpackets.setSignatureTarget(target.isCritical(),
                            PublicKeyAlgorithm.requireFromId(target.getPublicKeyAlgorithm()),
                            HashAlgorithm.requireFromId(target.getHashAlgorithm()),
                            target.getHashData());
                    break;
                case embeddedSignature:
                    EmbeddedSignature embeddedSignature = (EmbeddedSignature) subpacket;
                    subpackets.addEmbeddedSignature(embeddedSignature);
                    break;
                case intendedRecipientFingerprint:
                    IntendedRecipientFingerprint intendedRecipientFingerprint = (IntendedRecipientFingerprint) subpacket;
                    subpackets.addIntendedRecipientFingerprint(intendedRecipientFingerprint);
                    break;
                case policyUrl:
                    PolicyURI policyURI = (PolicyURI) subpacket;
                    subpackets.setPolicyUrl(policyURI);
                    break;
                case regularExpression:
                    RegularExpression regex = (RegularExpression) subpacket;
                    subpackets.setRegularExpression(regex);
                    break;
                    
                case keyServerPreferences:
                case preferredKeyServers:
                case placeholder:
                case preferredAEADAlgorithms:
                case attestedCertification:
                    subpackets.addResidualSubpacket(subpacket);
                    break;
            }
        }
        return subpackets;
    }

    public static PGPSignatureSubpacketGenerator applyTo(SignatureSubpackets subpackets, PGPSignatureSubpacketGenerator generator) {
        addSubpacket(generator, subpackets.getIssuerKeyIdSubpacket());
        addSubpacket(generator, subpackets.getIssuerFingerprintSubpacket());
        addSubpacket(generator, subpackets.getSignatureCreationTimeSubpacket());
        addSubpacket(generator, subpackets.getSignatureExpirationTimeSubpacket());
        addSubpacket(generator, subpackets.getExportableSubpacket());
        addSubpacket(generator, subpackets.getPolicyURI());
        addSubpacket(generator, subpackets.getRegularExpression());
        for (NotationData notationData : subpackets.getNotationDataSubpackets()) {
            addSubpacket(generator, notationData);
        }
        for (IntendedRecipientFingerprint intendedRecipientFingerprint : subpackets.getIntendedRecipientFingerprintSubpackets()) {
            addSubpacket(generator, intendedRecipientFingerprint);
        }
        for (RevocationKey revocationKey : subpackets.getRevocationKeySubpackets()) {
            addSubpacket(generator, revocationKey);
        }
        addSubpacket(generator, subpackets.getSignatureTargetSubpacket());
        addSubpacket(generator, subpackets.getFeaturesSubpacket());
        addSubpacket(generator, subpackets.getKeyFlagsSubpacket());
        addSubpacket(generator, subpackets.getTrustSubpacket());
        addSubpacket(generator, subpackets.getPreferredCompressionAlgorithmsSubpacket());
        addSubpacket(generator, subpackets.getPreferredSymmetricKeyAlgorithmsSubpacket());
        addSubpacket(generator, subpackets.getPreferredHashAlgorithmsSubpacket());
        for (EmbeddedSignature embeddedSignature : subpackets.getEmbeddedSignatureSubpackets()) {
            addSubpacket(generator, embeddedSignature);
        }
        addSubpacket(generator, subpackets.getSignerUserIdSubpacket());
        addSubpacket(generator, subpackets.getKeyExpirationTimeSubpacket());
        addSubpacket(generator, subpackets.getPrimaryUserIdSubpacket());
        addSubpacket(generator, subpackets.getRevocableSubpacket());
        addSubpacket(generator, subpackets.getRevocationReasonSubpacket());
        for (SignatureSubpacket subpacket : subpackets.getResidualSubpackets()) {
            addSubpacket(generator, subpacket);
        }

        return generator;
    }

    private static void addSubpacket(PGPSignatureSubpacketGenerator generator, SignatureSubpacket subpacket) {
        if (subpacket != null) {
            generator.addCustomSubpacket(subpacket);
        }
    }

    public static PGPSignatureSubpacketVector toVector(SignatureSubpackets subpackets) {
        PGPSignatureSubpacketGenerator generator = new PGPSignatureSubpacketGenerator();
        applyTo(subpackets, generator);
        return generator.generate();
    }

    public static PGPSignatureSubpacketVector toVector(RevocationSignatureSubpackets subpackets) {
        PGPSignatureSubpacketGenerator generator = new PGPSignatureSubpacketGenerator();
        applyTo((SignatureSubpackets) subpackets, generator);
        return generator.generate();
    }
}
