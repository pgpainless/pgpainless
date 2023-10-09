// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.bcpg.sig.KeyFlags;

/**
 * Enumeration of different key flags.
 * Key flags denote different capabilities of a key pair.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.21">RFC4880: Key Flags</a>
 */
public enum KeyFlag {

    /**
     * This key may be used to certify third-party keys.
     */
    CERTIFY_OTHER  (KeyFlags.CERTIFY_OTHER),

    /**
     * This key may be used to sign data.
     */
    SIGN_DATA      (KeyFlags.SIGN_DATA),

    /**
     * This key may be used to encrypt communications.
     */
    ENCRYPT_COMMS  (KeyFlags.ENCRYPT_COMMS),

    /**
     * This key may be used to encrypt storage.
     */
    ENCRYPT_STORAGE(KeyFlags.ENCRYPT_STORAGE),

    /**
     * The private component of this key may have been split by a secret-sharing mechanism.
     */
    SPLIT          (KeyFlags.SPLIT),

    /**
     * This key may be used for authentication.
     */
    AUTHENTICATION (KeyFlags.AUTHENTICATION),

    /**
     * The private component of this key may be in the possession of more than one person.
     */
    SHARED         (KeyFlags.SHARED),
    ;

    private final int flag;

    KeyFlag(int flag) {
        this.flag = flag;
    }

    /**
     * Return the numeric id of the {@link KeyFlag}.
     *
     * @return numeric id
     */
    public int getFlag() {
        return flag;
    }

    /**
     * Convert a bitmask into a list of {@link KeyFlag KeyFlags}.
     *
     * @param bitmask bitmask
     * @return list of key flags encoded by the bitmask
     */
    public static List<KeyFlag> fromBitmask(int bitmask) {
        List<KeyFlag> flags = new ArrayList<>();
        for (KeyFlag f : KeyFlag.values()) {
            if ((bitmask & f.flag) != 0) {
                flags.add(f);
            }
        }
        return flags;
    }

    /**
     * Encode a list of {@link KeyFlag KeyFlags} into a bitmask.
     *
     * @param flags list of flags
     * @return bitmask
     */
    public static int toBitmask(KeyFlag... flags) {
        int mask = 0;
        for (KeyFlag f : flags) {
            mask |= f.getFlag();
        }
        return mask;
    }

    /**
     * Return true if the provided bitmask has the bit for the provided flag set.
     * Return false if the mask does not contain the flag.
     *
     * @param mask bitmask
     * @param flag flag to be tested for
     * @return true if flag is set, false otherwise
     */
    public static boolean hasKeyFlag(int mask, KeyFlag flag) {
        return (mask & flag.getFlag()) == flag.getFlag();
    }

    public static boolean containsAny(int mask, KeyFlag... flags) {
        for (KeyFlag flag : flags) {
            if (hasKeyFlag(mask, flag)) {
                return true;
            }
        }
        return false;
    }
}
