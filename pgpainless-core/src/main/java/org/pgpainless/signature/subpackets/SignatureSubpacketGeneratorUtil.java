// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import java.util.Date;
import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;

/**
 * Utility class that helps to deal with BCs SignatureSubpacketGenerator class.
 */
public final class SignatureSubpacketGeneratorUtil {

    private SignatureSubpacketGeneratorUtil() {

    }

    /**
     * Remove all packets of the given type from the {@link PGPSignatureSubpacketGenerator PGPSignatureSubpacketGenerators}
     * internal set.
     *
     * @param subpacketType type of subpacket to remove
     * @param subpacketGenerator subpacket generator
     */
    public static void removeAllPacketsOfType(org.pgpainless.algorithm.SignatureSubpacket subpacketType,
                                              PGPSignatureSubpacketGenerator subpacketGenerator) {
        removeAllPacketsOfType(subpacketType.getCode(), subpacketGenerator);
    }

    /**
     * Remove all packets of the given type from the {@link PGPSignatureSubpacketGenerator PGPSignatureSubpacketGenerators}
     * internal set.
     *
     * @param type type of subpacket to remove
     * @param subpacketGenerator subpacket generator
     */
    public static void removeAllPacketsOfType(int type, PGPSignatureSubpacketGenerator subpacketGenerator) {
        for (SignatureSubpacket subpacket : subpacketGenerator.getSubpackets(type)) {
            subpacketGenerator.removePacket(subpacket);
        }
    }

    /**
     * Replace all occurrences of a signature creation time subpackets in the subpacket generator
     * with a single new instance representing the provided date.
     *
     * @param date signature creation time
     * @param subpacketGenerator subpacket generator
     */
    public static void setSignatureCreationTimeInSubpacketGenerator(Date date, PGPSignatureSubpacketGenerator subpacketGenerator) {
        removeAllPacketsOfType(SignatureSubpacketTags.CREATION_TIME, subpacketGenerator);
        subpacketGenerator.setSignatureCreationTime(false, date);
    }

    /**
     * Replace all occurrences of key expiration time subpackets in the subpacket generator
     * with a single instance representing the new expiration time.
     *
     * @param expirationDate expiration time as date or null for no expiration
     * @param creationDate date on which the key was created
     * @param subpacketGenerator subpacket generator
     */
    public static void setKeyExpirationDateInSubpacketGenerator(Date expirationDate,
                                                                @Nonnull Date creationDate,
                                                                PGPSignatureSubpacketGenerator subpacketGenerator) {
        removeAllPacketsOfType(SignatureSubpacketTags.KEY_EXPIRE_TIME, subpacketGenerator);
        long secondsToExpire = SignatureSubpacketsUtil.getKeyLifetimeInSeconds(expirationDate, creationDate);
        subpacketGenerator.setKeyExpirationTime(true, secondsToExpire);
    }
}
