// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.gnu_dummy_s2k;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

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
     * Modify the given {@link PGPSecretKeyRing}.
     *
     * @param secretKeys secret keys
     * @return builder
     */
    public static Builder modify(PGPSecretKeyRing secretKeys) {
        return new Builder(secretKeys);
    }

    public static final class Builder {

        private final PGPSecretKeyRing keys;

        private Builder(PGPSecretKeyRing keys) {
            this.keys = keys;
        }

        /**
         * Remove all private keys that match the given {@link KeyFilter} from the key ring and replace them with
         * GNU_DUMMY keys with S2K protection mode {@link GnuPGDummyExtension#NO_PRIVATE_KEY}.
         *
         * @param filter filter to select keys for removal
         * @return modified key ring
         */
        public PGPSecretKeyRing removePrivateKeys(KeyFilter filter) {
            return replacePrivateKeys(GnuPGDummyExtension.NO_PRIVATE_KEY, null, filter);
        }

        /**
         * Remove all private keys that match the given {@link KeyFilter} from the key ring and replace them with
         * GNU_DUMMY keys with S2K protection mode {@link GnuPGDummyExtension#DIVERT_TO_CARD}.
         * This method will set the serial number of the card to 0x00000000000000000000000000000000.
         *
         * NOTE: This method does not actually move any keys to a card.
         *
         * @param filter filter to select keys for removal
         * @return modified key ring
         */
        public PGPSecretKeyRing divertPrivateKeysToCard(KeyFilter filter) {
            return divertPrivateKeysToCard(filter, new byte[16]);
        }

        /**
         * Remove all private keys that match the given {@link KeyFilter} from the key ring and replace them with
         * GNU_DUMMY keys with S2K protection mode {@link GnuPGDummyExtension#DIVERT_TO_CARD}.
         * This method will include the card serial number into the encoded dummy key.
         *
         * NOTE: This method does not actually move any keys to a card.
         *
         * @param filter filter to select keys for removal
         * @param cardSerialNumber serial number of the card (at most 16 bytes long)
         * @return modified key ring
         */
        public PGPSecretKeyRing divertPrivateKeysToCard(KeyFilter filter, byte[] cardSerialNumber) {
            if (cardSerialNumber != null && cardSerialNumber.length > 16) {
                throw new IllegalArgumentException("Card serial number length cannot exceed 16 bytes.");
            }
            return replacePrivateKeys(GnuPGDummyExtension.DIVERT_TO_CARD, cardSerialNumber, filter);
        }

        private PGPSecretKeyRing replacePrivateKeys(GnuPGDummyExtension extension, byte[] serial, KeyFilter filter) {
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
