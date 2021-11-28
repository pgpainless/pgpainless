// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.pgpainless.algorithm.KeyFlag;

/**
 * Utility class that helps dealing with BCs SignatureSubpacketGenerator class.
 */
public final class SignatureSubpacketGeneratorUtil {

    private SignatureSubpacketGeneratorUtil() {

    }

    /**
     * Return a list of {@link SignatureSubpacket SignatureSubpackets} from the subpacket generator, which correspond
     * to the given {@link org.pgpainless.algorithm.SignatureSubpacket} type.
     *
     * @param type subpacket type
     * @param generator subpacket generator
     * @param <P> generic subpacket type
     * @return possibly empty list of subpackets
     */
    public static <P extends SignatureSubpacket> List<P> getSubpacketsOfType(org.pgpainless.algorithm.SignatureSubpacket type,
                                                               PGPSignatureSubpacketGenerator generator) {
        SignatureSubpacket[] subpackets = generator.getSubpackets(type.getCode());
        List<P> list = new ArrayList<>();
        for (SignatureSubpacket p : subpackets) {
            list.add((P) p);
        }
        return list;
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

    /**
     * Return true, if the subpacket generator has a {@link KeyFlags} subpacket which carries the given key flag.
     * Returns false, if no {@link KeyFlags} subpacket is present.
     * If there are more than one instance of a {@link KeyFlags} packet present, only the last occurrence will
     * be tested.
     *
     * @param keyFlag flag to test for
     * @param generator subpackets generator
     * @return true if the generator has the given key flag set
     */
    public static boolean hasKeyFlag(KeyFlag keyFlag, PGPSignatureSubpacketGenerator generator) {
        List<KeyFlags> keyFlagPackets = getSubpacketsOfType(org.pgpainless.algorithm.SignatureSubpacket.keyFlags, generator);
        if (keyFlagPackets.isEmpty()) {
            return false;
        }
        KeyFlags last = keyFlagPackets.get(keyFlagPackets.size() - 1);
        return KeyFlag.hasKeyFlag(last.getFlags(), keyFlag);
    }
}
