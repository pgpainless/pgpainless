/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.algorithm;

import static org.bouncycastle.bcpg.SignatureSubpacketTags.ATTESTED_CERTIFICATIONS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.CREATION_TIME;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.EMBEDDED_SIGNATURE;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.EXPIRE_TIME;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.EXPORTABLE;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.FEATURES;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.INTENDED_RECIPIENT_FINGERPRINT;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.ISSUER_FINGERPRINT;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.ISSUER_KEY_ID;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.KEY_EXPIRE_TIME;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.KEY_FLAGS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.KEY_SERVER_PREFS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.NOTATION_DATA;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PLACEHOLDER;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.POLICY_URL;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PREFERRED_COMP_ALGS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PREFERRED_HASH_ALGS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PREFERRED_KEY_SERV;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PREFERRED_SYM_ALGS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PRIMARY_USER_ID;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.REG_EXP;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.REVOCABLE;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.REVOCATION_KEY;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.REVOCATION_REASON;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.SIGNATURE_TARGET;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.SIGNER_USER_ID;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.TRUST_SIG;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public enum SignatureSubpacket {
    signatureCreationTime(CREATION_TIME),
    signatureExpirationTime(EXPIRE_TIME),
    exportableCertification(EXPORTABLE),
    trustSignature(TRUST_SIG),
    regularExpression(REG_EXP),
    revocable(REVOCABLE),
    keyExpirationTime(KEY_EXPIRE_TIME),
    placeholder(PLACEHOLDER),
    preferredSymmetricAlgorithms(PREFERRED_SYM_ALGS),
    revocationKey(REVOCATION_KEY),
    issuerKeyId(ISSUER_KEY_ID),
    notationData(NOTATION_DATA),
    preferredHashAlgorithms(PREFERRED_HASH_ALGS),
    preferredCompressionAlgorithms(PREFERRED_COMP_ALGS),
    keyServerPreferences(KEY_SERVER_PREFS),
    preferredKeyServers(PREFERRED_KEY_SERV),
    primaryUserId(PRIMARY_USER_ID),
    policyUrl(POLICY_URL),
    keyFlags(KEY_FLAGS),
    signerUserId(SIGNER_USER_ID),
    revocationReason(REVOCATION_REASON),
    features(FEATURES),
    signatureTarget(SIGNATURE_TARGET),
    embeddedSignature(EMBEDDED_SIGNATURE),
    issuerFingerprint(ISSUER_FINGERPRINT),
    preferredAEADAlgorithms(PREFERRED_AEAD_ALGORITHMS),
    intendedRecipientFingerprint(INTENDED_RECIPIENT_FINGERPRINT),
    attestedCertification(ATTESTED_CERTIFICATIONS)
    ;

    private static final Map<Integer, SignatureSubpacket> MAP = new ConcurrentHashMap<>();
    static {
        for (SignatureSubpacket p : values()) {
            MAP.put(p.code, p);
        }
    }

    private final int code;

    SignatureSubpacket(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public static SignatureSubpacket fromCode(int code) {
        SignatureSubpacket tag = MAP.get(code);
        if (tag == null) {
            throw new IllegalArgumentException("No SignatureSubpacket tag found with code " + code);
        }
        return tag;
    }

    public static List<SignatureSubpacket> fromCodes(int[] codes) {
        List<SignatureSubpacket> tags = new ArrayList<>();
        for (int code : codes) {
            tags.add(fromCode(code));
        }
        return tags;
    }
}
