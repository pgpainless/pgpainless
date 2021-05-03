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
public class SignatureSubpacketGeneratorUtil {

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
    public static void setExpirationDateInSubpacketGenerator(Date expirationDate,
                                                       @Nonnull Date creationDate,
                                                       PGPSignatureSubpacketGenerator subpacketGenerator) {
        removeAllPacketsOfType(SignatureSubpacketTags.KEY_EXPIRE_TIME, subpacketGenerator);
        long secondsToExpire = getKeyLifetimeInSeconds(expirationDate, creationDate);
        subpacketGenerator.setKeyExpirationTime(true, secondsToExpire);
    }

    /**
     * Calculate the duration in seconds until the key expires after creation.
     *
     * @param expirationDate new expiration date
     * @param creationTime key creation time
     * @return life time of the key in seconds
     */
    private static long getKeyLifetimeInSeconds(Date expirationDate, @Nonnull Date creationTime) {
        long secondsToExpire = 0; // 0 means "no expiration"
        if (expirationDate != null) {
            if (creationTime.after(expirationDate)) {
                throw new IllegalArgumentException("Key MUST NOT expire before being created. (creation: " + creationTime + ", expiration: " + expirationDate + ")");
            }
            secondsToExpire = (expirationDate.getTime() - creationTime.getTime()) / 1000;
        }
        return secondsToExpire;
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
