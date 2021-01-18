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
package org.pgpainless.util;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureSubpacket;
import org.pgpainless.key.OpenPgpV4Fingerprint;

public class SubpacketsInspector {

    public static StringBuilder toString(PGPSignatureSubpacketVector vector) {
        StringBuilder sb = new StringBuilder();
        optAppendSignatureCreationTime(sb, vector);
        optAppendSignatureExpirationTime(sb, vector);
        optAppendFlags(sb, vector);
        optAppendFeatures(sb, vector);
        optAppendIssuerKeyID(sb, vector);
        optAppendSignerUserID(sb, vector);
        optAppendKeyExpirationTime(sb, vector);
        optAppendIntendedRecipientFingerprint(sb, vector);
        optAppendNotationDataOccurrences(sb, vector);
        optAppendCriticalTags(sb, vector);
        return sb;
    }

    private static StringBuilder optAppendCriticalTags(StringBuilder sb, PGPSignatureSubpacketVector v) {
        int[] criticalTagCodes = v.getCriticalTags();
        if (criticalTagCodes.length == 0) {
            return sb;
        }

        sb.append("Critical Tags: ").append('[');
        for (int i = 0; i < criticalTagCodes.length; i++) {
            int tag = criticalTagCodes[i];
            try {
                sb.append(SignatureSubpacket.fromCode(tag)).append(i == criticalTagCodes.length - 1 ? "" : ", ");
            } catch (IllegalArgumentException e) {

            }
        }
        return sb.append(']').append('\n');
    }

    private static StringBuilder optAppendNotationDataOccurrences(StringBuilder sb, PGPSignatureSubpacketVector v) {
        NotationData[] notationData = v.getNotationDataOccurrences();
        if (notationData.length == 0) {
            return sb;
        }
        sb.append("Notation Data: [").append('\n');
        for (int i = 0; i < notationData.length; i++) {
            NotationData n = notationData[i];
            sb.append('\'').append(n.getNotationName())
                    .append("' = '").append(n.getNotationValue())
                    .append(i == notationData.length - 1 ? "'" : "', ");
        }
        return sb.append('\n');
    }

    private static StringBuilder optAppendSignatureCreationTime(StringBuilder sb, PGPSignatureSubpacketVector v) {
        return sb.append("Sig created: ").append(v.getSignatureCreationTime()).append('\n');
    }

    private static StringBuilder optAppendSignatureExpirationTime(StringBuilder sb, PGPSignatureSubpacketVector v) {
        long time = v.getSignatureExpirationTime();
        sb.append("Sig expires: ");
        if (time == 0) {
            sb.append("never");
        } else {
            Date creationTime = v.getSignatureCreationTime();
            if (creationTime != null) {
                long seconds = creationTime.getTime() / 1000;
                Date expirationDate = new Date((seconds + time) * 1000);
                sb.append(expirationDate).append(" (").append(time).append(')');
            } else {
                sb.append(time);
            }
        }
        return sb.append('\n');
    }

    private static StringBuilder optAppendFlags(StringBuilder sb, PGPSignatureSubpacketVector v) {
        List<KeyFlag> flagList = KeyFlag.fromBitmask(v.getKeyFlags());
        sb.append("Flags: ").append(Arrays.toString(flagList.toArray())).append('\n');
        return sb;
    }

    private static StringBuilder optAppendFeatures(StringBuilder sb, PGPSignatureSubpacketVector v) {
        Features features = v.getFeatures();
        if (features == null) {
            return sb;
        }
        sb.append("Features: ");
        sb.append('[');
        if (features.supportsModificationDetection()) {
            sb.append("Modification Detection");
        }
        sb.append(']');
        return sb.append('\n');
    }

    private static StringBuilder optAppendIssuerKeyID(StringBuilder sb, PGPSignatureSubpacketVector v) {
        long keyId = v.getIssuerKeyID();
        if (keyId == 0) {
            return sb;
        }
        return sb.append("Issuer KeyID: ").append(Long.toHexString(keyId)).append('\n');
    }

    private static StringBuilder optAppendSignerUserID(StringBuilder sb, PGPSignatureSubpacketVector v) {
        String userID = v.getSignerUserID();
        if (userID == null) {
            return sb;
        }
        return sb.append("Signer UserID: ").append(userID).append('\n');
    }

    private static StringBuilder optAppendKeyExpirationTime(StringBuilder sb, PGPSignatureSubpacketVector v) {
        long expirationTime = v.getKeyExpirationTime();
        sb.append("Key Expiration Time: ");
        if (expirationTime == 0) {
            sb.append("never");
        } else {
            sb.append(expirationTime).append(" seconds after creation");
        }
        return sb.append('\n');
    }

    private static StringBuilder optAppendIntendedRecipientFingerprint(StringBuilder sb, PGPSignatureSubpacketVector v) {
        IntendedRecipientFingerprint fingerprint = v.getIntendedRecipientFingerprint();
        if (fingerprint == null) {
            return sb;
        }
        return sb.append("Intended Recipient Fingerprint: ")
                .append(new OpenPgpV4Fingerprint(fingerprint.getFingerprint()))
                .append('\n');
    }

}
