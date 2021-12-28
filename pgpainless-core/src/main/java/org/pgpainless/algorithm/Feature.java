// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.bcpg.sig.Features;

/**
 * An enumeration of features that may be set in the {@link Features} subpacket.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.24">RFC4880: Features</a>
 */
public enum Feature {

    /**
     * Support for Symmetrically Encrypted Integrity Protected Data Packets using Modification Detection Code Packets.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.14">
     *     RFC-4880 §5.14: Modification Detection Code Packet</a>
     */
    MODIFICATION_DETECTION(Features.FEATURE_MODIFICATION_DETECTION),

    /**
     * Support for Authenticated Encryption with Additional Data (AEAD).
     * If a key announces this feature, it signals support for consuming AEAD Encrypted Data Packets.
     *
     * NOTE: PGPAINLESS DOES NOT YET SUPPORT THIS FEATURE!!!
     *
     * @see <a href="https://openpgp-wg.gitlab.io/rfc4880bis/#name-aead-encrypted-data-packet-">
     *     AEAD Encrypted Data Packet</a>
     */
    AEAD_ENCRYPTED_DATA(Features.FEATURE_AEAD_ENCRYPTED_DATA),

    /**
     * If a key announces this feature, it is a version 5 public key.
     * The version 5 format is similar to the version 4 format except for the addition of a count for the key material.
     * This count helps to parse secret key packets (which are an extension of the public key packet format) in the case
     * of an unknown algorithm.
     * In addition, fingerprints of version 5 keys are calculated differently from version 4 keys.
     *
     * NOTE: PGPAINLESS DOES NOT YET SUPPORT THIS FEATURE!!!
     *
     * @see <a href="https://openpgp-wg.gitlab.io/rfc4880bis/#name-public-key-packet-formats">
     *     Public-Key Packet Formats</a>
     */
    VERSION_5_PUBLIC_KEY(Features.FEATURE_VERSION_5_PUBLIC_KEY)
    ;

    private static final Map<Byte, Feature> MAP = new ConcurrentHashMap<>();

    static {
        for (Feature f : Feature.values()) {
            MAP.put(f.featureId, f);
        }
    }

    public static Feature fromId(byte id) {
        return MAP.get(id);
    }

    private final byte featureId;

    Feature(byte featureId) {
        this.featureId = featureId;
    }

    public byte getFeatureId() {
        return featureId;
    }

    /**
     * Convert a bitmask into a list of {@link KeyFlag KeyFlags}.
     *
     * @param bitmask bitmask
     * @return list of key flags encoded by the bitmask
     */
    public static List<Feature> fromBitmask(int bitmask) {
        List<Feature> features = new ArrayList<>();
        for (Feature f : Feature.values()) {
            if ((bitmask & f.featureId) != 0) {
                features.add(f);
            }
        }
        return features;
    }

    /**
     * Encode a list of {@link KeyFlag KeyFlags} into a bitmask.
     *
     * @param features list of flags
     * @return bitmask
     */
    public static byte toBitmask(Feature... features) {
        byte mask = 0;
        for (Feature f : features) {
            mask |= f.featureId;
        }
        return mask;
    }
}
