// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.gnupg;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.pgpainless.key.SubkeyIdentifier;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * This class can be used to remove private keys from secret software-keys by replacing them with
 * stub secret keys in the style of GnuPGs proprietary extensions.
 *
 * @see <a href="https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=doc/DETAILS;hb=HEAD#l1489">
 *     GnuPGs doc/DETAILS - GNU extensions to the S2K algorithm</a>
 */
public final class GnuPGDummyKeyUtil {

    private GnuPGDummyKeyUtil() {

    }

    /**
     * Return the key-ids of all keys which appear to be stored on a hardware token / smartcard by GnuPG.
     * Note, that this functionality is based on GnuPGs proprietary S2K extensions, which are not strictly required
     * for dealing with hardware-backed keys.
     *
     * @param secretKeys secret keys
     * @return set of keys with S2K type GNU_DUMMY_S2K and protection mode DIVERT_TO_CARD
     */
    public static Set<SubkeyIdentifier> getIdsOfKeysWithGnuPGS2KDivertedToCard(@Nonnull PGPSecretKeyRing secretKeys) {
        Set<SubkeyIdentifier> hardwareBackedKeys = new HashSet<>();
        for (PGPSecretKey secretKey : secretKeys) {
            S2K s2K = secretKey.getS2K();
            if (s2K == null) {
                continue;
            }

            int type = s2K.getType();
            int mode = s2K.getProtectionMode();
            // TODO: Is GNU_DUMMY_S2K appropriate?
            if (type == S2K.GNU_DUMMY_S2K && mode == S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD) {
                SubkeyIdentifier hardwareBackedKey = new SubkeyIdentifier(secretKeys, secretKey.getKeyID());
                hardwareBackedKeys.add(hardwareBackedKey);
            }
        }
        return hardwareBackedKeys;
    }

    public static Builder modify(@Nonnull OpenPGPKey key) {
        return modify(key.getPGPSecretKeyRing());
    }

    /**
     * Modify the given {@link PGPSecretKeyRing}.
     *
     * @param secretKeys secret keys
     * @return builder
     */
    public static Builder modify(@Nonnull PGPSecretKeyRing secretKeys) {
        return new Builder(secretKeys);
    }

    public static final class Builder {

        private final PGPSecretKeyRing keys;

        private Builder(@Nonnull PGPSecretKeyRing keys) {
            this.keys = keys;
        }

        /**
         * Remove all private keys that match the given {@link KeyFilter} from the key ring and replace them with
         * GNU_DUMMY keys with S2K protection mode {@link GnuPGDummyExtension#NO_PRIVATE_KEY}.
         *
         * @param filter filter to select keys for removal
         * @return modified key ring
         */
        public PGPSecretKeyRing removePrivateKeys(@Nonnull KeyFilter filter) {
            return replacePrivateKeys(GnuPGDummyExtension.NO_PRIVATE_KEY, null, filter);
        }

        /**
         * Remove all private keys that match the given {@link KeyFilter} from the key ring and replace them with
         * GNU_DUMMY keys with S2K protection mode {@link GnuPGDummyExtension#DIVERT_TO_CARD}.
         * This method will set the serial number of the card to 0x00000000000000000000000000000000.
         * NOTE: This method does not actually move any keys to a card.
         *
         * @param filter filter to select keys for removal
         * @return modified key ring
         */
        public PGPSecretKeyRing divertPrivateKeysToCard(@Nonnull KeyFilter filter) {
            return divertPrivateKeysToCard(filter, new byte[16]);
        }

        /**
         * Remove all private keys that match the given {@link KeyFilter} from the key ring and replace them with
         * GNU_DUMMY keys with S2K protection mode {@link GnuPGDummyExtension#DIVERT_TO_CARD}.
         * This method will include the card serial number into the encoded dummy key.
         * NOTE: This method does not actually move any keys to a card.
         *
         * @param filter filter to select keys for removal
         * @param cardSerialNumber serial number of the card (at most 16 bytes long)
         * @return modified key ring
         */
        public PGPSecretKeyRing divertPrivateKeysToCard(@Nonnull KeyFilter filter, @Nullable byte[] cardSerialNumber) {
            if (cardSerialNumber != null && cardSerialNumber.length > 16) {
                throw new IllegalArgumentException("Card serial number length cannot exceed 16 bytes.");
            }
            return replacePrivateKeys(GnuPGDummyExtension.DIVERT_TO_CARD, cardSerialNumber, filter);
        }

        private PGPSecretKeyRing replacePrivateKeys(@Nonnull GnuPGDummyExtension extension,
                                                    @Nullable byte[] serial,
                                                    @Nonnull KeyFilter filter) {
            byte[] encodedSerial = serial != null ? encodeSerial(serial) : null;
            S2K s2k = extensionToS2K(extension);

            List<PGPSecretKey> secretKeyList = new ArrayList<>();
            for (PGPSecretKey secretKey : keys) {
                if (!filter.filter(secretKey.getKeyID())) {
                    // No conversion, do not modify subkey
                    secretKeyList.add(secretKey);
                    continue;
                }

                PublicKeyPacket publicKeyPacket = secretKey.getPublicKey().getPublicKeyPacket();
                if (secretKey.isMasterKey()) {
                    SecretKeyPacket keyPacket = new SecretKeyPacket(publicKeyPacket,
                            0, SecretKeyPacket.USAGE_SHA1, s2k, null, encodedSerial);
                    PGPSecretKey onCard = new PGPSecretKey(keyPacket, secretKey.getPublicKey());
                    secretKeyList.add(onCard);
                } else {
                    SecretSubkeyPacket keyPacket = new SecretSubkeyPacket(publicKeyPacket,
                            0, SecretKeyPacket.USAGE_SHA1, s2k, null, encodedSerial);
                    PGPSecretKey onCard = new PGPSecretKey(keyPacket, secretKey.getPublicKey());
                    secretKeyList.add(onCard);
                }
            }

            return new PGPSecretKeyRing(secretKeyList);
        }

        private byte[] encodeSerial(@Nonnull byte[] serial) {
            byte[] encoded = new byte[serial.length + 1];
            encoded[0] = (byte) (serial.length & 0xff);
            System.arraycopy(serial, 0, encoded, 1, serial.length);
            return encoded;
        }

        private S2K extensionToS2K(@Nonnull GnuPGDummyExtension extension) {
            return S2K.gnuDummyS2K(extension == GnuPGDummyExtension.DIVERT_TO_CARD ?
                    S2K.GNUDummyParams.divertToCard() : S2K.GNUDummyParams.noPrivateKey());
        }
    }

    /**
     * Filter for selecting keys.
     */
    @FunctionalInterface
    public interface KeyFilter {

        /**
         * Return true, if the given key should be selected, false otherwise.
         *
         * @param keyId id of the key
         * @return select
         */
        boolean filter(long keyId);

        /**
         * Select any key.
         *
         * @return filter
         */
        static KeyFilter any() {
            return keyId -> true;
        }

        /**
         * Select only the given keyId.
         *
         * @param onlyKeyId only acceptable key id
         * @return filter
         */
        static KeyFilter only(long onlyKeyId) {
            return keyId -> keyId == onlyKeyId;
        }

        /**
         * Select all keyIds which are contained in the given set of ids.
         *
         * @param ids set of acceptable keyIds
         * @return filter
         */
        static KeyFilter selected(Collection<Long> ids) {
            // noinspection Convert2MethodRef
            return keyId -> ids.contains(keyId);
        }
    }
}
