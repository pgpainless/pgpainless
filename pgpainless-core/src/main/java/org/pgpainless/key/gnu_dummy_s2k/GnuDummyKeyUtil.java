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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public final class GnuDummyKeyUtil {

    private GnuDummyKeyUtil() {

    }

    public static Builder modify(PGPSecretKeyRing secretKeys) {
        return new Builder(secretKeys);
    }

    public static final class Builder {

        private final PGPSecretKeyRing keys;

        private Builder(PGPSecretKeyRing keys) {
            this.keys = keys;
        }

        public PGPSecretKeyRing removePrivateKeys(KeyFilter filter) {
            return doIt(GNUExtension.NO_PRIVATE_KEY, null, filter);
        }

        public PGPSecretKeyRing divertPrivateKeysToCard(KeyFilter filter) {
            return divertPrivateKeysToCard(filter, new byte[16]);
        }

        public PGPSecretKeyRing divertPrivateKeysToCard(KeyFilter filter, byte[] cardSerialNumber) {
            return doIt(GNUExtension.DIVERT_TO_CARD, cardSerialNumber, filter);
        }

        private PGPSecretKeyRing doIt(GNUExtension extension, byte[] serial, KeyFilter filter) {
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
                            0, 255, s2k, null, encodedSerial);
                    PGPSecretKey onCard = new PGPSecretKey(keyPacket, secretKey.getPublicKey());
                    secretKeyList.add(onCard);
                } else {
                    SecretSubkeyPacket keyPacket = new SecretSubkeyPacket(publicKeyPacket,
                            0, 255, s2k, null, encodedSerial);
                    PGPSecretKey onCard = new PGPSecretKey(keyPacket, secretKey.getPublicKey());
                    secretKeyList.add(onCard);
                }
            }

            PGPSecretKeyRing gnuDummyKey = new PGPSecretKeyRing(secretKeyList);
            return gnuDummyKey;
        }

        private byte[] encodeSerial(byte[] serial) {
            byte[] encoded = new byte[serial.length + 1];
            encoded[0] = 0x10;
            System.arraycopy(serial, 0, encoded, 1, serial.length);
            return encoded;
        }

        private S2K extensionToS2K(GNUExtension extension) {
            S2K s2k = S2K.gnuDummyS2K(extension == GNUExtension.DIVERT_TO_CARD ?
                    S2K.GNUDummyParams.divertToCard() : S2K.GNUDummyParams.noPrivateKey());
            return s2k;
        }
    }

    public interface KeyFilter {

        /**
         * Return true, if the given key should be selected, false otherwise.
         *
         * @param keyId id of the key
         * @return select
         */
        boolean filter(long keyId);

        static KeyFilter any() {
            return keyId -> true;
        }

        static KeyFilter only(long onlyKeyId) {
            return keyId -> keyId == onlyKeyId;
        }

        static KeyFilter selected(Collection<Long> ids) {
            return keyId -> ids.contains(keyId);
        }
    }
}
