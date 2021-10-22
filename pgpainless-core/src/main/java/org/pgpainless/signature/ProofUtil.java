// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.builder.CertificationSignatureBuilder;
import org.pgpainless.signature.builder.DirectKeySignatureBuilder;

public class ProofUtil {

    public PGPSecretKeyRing addProof(PGPSecretKeyRing secretKey, SecretKeyRingProtector protector, Proof proof)
            throws PGPException {
        return addProofs(secretKey, protector, Collections.singletonList(proof));
    }

    public PGPSecretKeyRing addProofs(PGPSecretKeyRing secretKey, SecretKeyRingProtector protector, List<Proof> proofs)
            throws PGPException {
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        return addProofs(secretKey, protector, info.getPrimaryUserId(), proofs);
    }

    public PGPSecretKeyRing addProof(PGPSecretKeyRing secretKey, SecretKeyRingProtector protector, String userId, Proof proof)
            throws PGPException {
        return addProofs(secretKey, protector, userId, Collections.singletonList(proof));
    }

    public PGPSecretKeyRing addProofs(PGPSecretKeyRing secretKey, SecretKeyRingProtector protector,
                          @Nullable String userId, List<Proof> proofs)
            throws PGPException {
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        PGPSecretKey certificationKey = secretKey.getSecretKey();
        PGPPublicKey certificationPubKey = certificationKey.getPublicKey();
        PGPSignature certification = null;

        // null userid -> make direct key sig
        if (userId == null) {
            PGPSignature previousCertification = info.getLatestDirectKeySelfSignature();
            if (previousCertification == null) {
                throw new NoSuchElementException("No previous valid direct key signature found.");
            }

            DirectKeySignatureBuilder sigBuilder = new DirectKeySignatureBuilder(certificationKey, protector, previousCertification);
            for (Proof proof : proofs) {
                sigBuilder.getHashedSubpackets().addNotationData(false, proof.getNotationName(), proof.getNotationValue());
            }
            certification = sigBuilder.build(certificationPubKey);
            certificationPubKey = PGPPublicKey.addCertification(certificationPubKey, certification);
        } else {
            if (!info.isUserIdValid(userId)) {
                throw new IllegalArgumentException("User ID " + userId + " seems to not be valid for this key.");
            }
            PGPSignature previousCertification = info.getLatestUserIdCertification(userId);
            if (previousCertification == null) {
                throw new NoSuchElementException("No previous valid user-id certification found.");
            }

            CertificationSignatureBuilder sigBuilder = new CertificationSignatureBuilder(certificationKey, protector, previousCertification);
            for (Proof proof : proofs) {
                sigBuilder.getHashedSubpackets().addNotationData(false, proof.getNotationName(), proof.getNotationValue());
            }
            certification = sigBuilder.build(certificationPubKey, userId);
            certificationPubKey = PGPPublicKey.addCertification(certificationPubKey, userId, certification);
        }
        certificationKey = PGPSecretKey.replacePublicKey(certificationKey, certificationPubKey);
        secretKey = PGPSecretKeyRing.insertSecretKey(secretKey, certificationKey);

        return secretKey;
    }

    public static class Proof {
        public static final String NOTATION_NAME = "proof@metacode.biz";
        private final String notationValue;

        public Proof(String notationValue) {
            if (notationValue == null) {
                throw new IllegalArgumentException("Notation value cannot be null.");
            }
            String trimmed = notationValue.trim();
            if (trimmed.isEmpty()) {
                throw new IllegalArgumentException("Notation value cannot be empty.");
            }
            this.notationValue = trimmed;
        }

        public String getNotationName() {
            return NOTATION_NAME;
        }

        public String getNotationValue() {
            return notationValue;
        }

        public static Proof fromMatrixPermalink(String username, String eventPermalink) {
            Pattern pattern = Pattern.compile("^https:\\/\\/matrix\\.to\\/#\\/(![a-zA-Z]{18}:matrix\\.org)\\/(\\$[a-zA-Z0-9\\-_]{43})\\?via=.*$");
            Matcher matcher = pattern.matcher(eventPermalink);
            if (!matcher.matches()) {
                throw new IllegalArgumentException("Invalid matrix event permalink.");
            }
            String roomId = matcher.group(1);
            String eventId = matcher.group(2);
            return new Proof(String.format("matrix:u/%s?org.keyoxide.r=%s&org.keyoxide.e=%s", username, roomId, eventId));
        }

        @Override
        public String toString() {
            return getNotationName() + "=" + getNotationValue();
        }
    }

    public static List<Proof> getProofs(PGPSignature signature) {
        PGPSignatureSubpacketVector hashedSubpackets = signature.getHashedSubPackets();
        NotationData[] notations = hashedSubpackets.getNotationDataOccurrences();

        List<Proof> proofs = new ArrayList<>();
        for (NotationData notation : notations) {
            if (notation.getNotationName().equals(Proof.NOTATION_NAME)) {
                proofs.add(new Proof(notation.getNotationValue()));
            }
        }
        return proofs;
    }
}
