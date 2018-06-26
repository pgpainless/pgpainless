/*
 * Copyright 2018 Paul Schaub.
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
package de.vanitasvitae.crypto.pgpainless.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import de.vanitasvitae.crypto.pgpainless.algorithm.KeyFlag;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.io.Streams;

public class BCUtil {

    private static final Logger LOGGER = Logger.getLogger(BCUtil.class.getName());

    /*
    PGPXxxKeyRing -> PGPXxxKeyRingCollection
     */
    public static PGPPublicKeyRingCollection keyRingsToKeyRingCollection(PGPPublicKeyRing... rings)
            throws IOException, PGPException {
        return new PGPPublicKeyRingCollection(Arrays.asList(rings));
    }

    public static PGPSecretKeyRingCollection keyRingsToKeyRingCollection(PGPSecretKeyRing... rings)
            throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(Arrays.asList(rings));
    }

    /*
    PGPSecretKeyRing -> PGPPublicKeyRing
     */

    public static PGPPublicKeyRing publicKeyRingFromSecretKeyRing(PGPSecretKeyRing secring) {
        List<PGPPublicKey> list = new ArrayList<>();
        for (Iterator<PGPPublicKey> i = secring.getPublicKeys(); i.hasNext(); ) {
            PGPPublicKey k = i.next();
            list.add(k);
        }

        // TODO: Change to simply using the List constructor once BC 1.60 gets released.
        try {
            Constructor<PGPPublicKeyRing> constructor;
            constructor = PGPPublicKeyRing.class.getDeclaredConstructor(List.class);
            constructor.setAccessible(true);
            PGPPublicKeyRing pubring = constructor.newInstance(list);
            return pubring;
        } catch (NoSuchMethodException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
            throw new AssertionError(e);
        }
    }

    /*
    PGPXxxKeyRingCollection -> PGPXxxKeyRing
     */

    public static PGPSecretKeyRing getKeyRingFromCollection(PGPSecretKeyRingCollection collection, Long id)
            throws PGPException {
        PGPSecretKeyRing uncleanedRing = collection.getSecretKeyRing(id);
        PGPPublicKeyRing publicKeys = publicKeyRingFromSecretKeyRing(uncleanedRing);

        // Determine ids of signed keys
        Set<Long> signedKeyIds = new HashSet<>();
        signedKeyIds.add(id); // Add the signing key itself
        Iterator<PGPPublicKey> signedPubKeys = publicKeys.getKeysWithSignaturesBy(id);
        while (signedPubKeys.hasNext()) {
            signedKeyIds.add(signedPubKeys.next().getKeyID());
        }

        PGPSecretKeyRing cleanedRing = uncleanedRing;
        Iterator<PGPSecretKey> secretKeys = uncleanedRing.getSecretKeys();
        while (secretKeys.hasNext()) {
            PGPSecretKey secretKey = secretKeys.next();
            if (!signedKeyIds.contains(secretKey.getKeyID())) {
                cleanedRing = PGPSecretKeyRing.removeSecretKey(cleanedRing, secretKey);
            }
        }
        return cleanedRing;
    }

    public static PGPPublicKeyRing getKeyRingFromCollection(PGPPublicKeyRingCollection collection, Long id)
            throws PGPException {
        return removeUnsignedKeysFromKeyRing(collection.getPublicKeyRing(id), id);
    }

    public static InputStream getPgpDecoderInputStream(byte[] bytes) throws IOException {
        return getPgpDecoderInputStream(new ByteArrayInputStream(bytes));
    }

    public static InputStream getPgpDecoderInputStream(InputStream inputStream) throws IOException {
        return PGPUtil.getDecoderStream(inputStream);
    }

    public static byte[] getDecodedBytes(byte[] bytes) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Streams.pipeAll(getPgpDecoderInputStream(bytes), buffer);
        return buffer.toByteArray();
    }

    public static byte[] getDecodedBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Streams.pipeAll(inputStream, buffer);
        return getDecodedBytes(buffer.toByteArray());
    }

    public static PGPPublicKeyRing removeUnsignedKeysFromKeyRing(PGPPublicKeyRing ring, Long masterKeyId) {

        Set<Long> signedKeyIds = new HashSet<>();
        signedKeyIds.add(masterKeyId);
        Iterator<PGPPublicKey> signedKeys = ring.getKeysWithSignaturesBy(masterKeyId);
        while (signedKeys.hasNext()) {
            signedKeyIds.add(signedKeys.next().getKeyID());
        }

        PGPPublicKeyRing cleaned = ring;

        Iterator<PGPPublicKey> publicKeys = ring.getPublicKeys();
        while (publicKeys.hasNext()) {
            PGPPublicKey publicKey = publicKeys.next();
            if (!signedKeyIds.contains(publicKey.getKeyID())) {
                cleaned = PGPPublicKeyRing.removePublicKey(cleaned, publicKey);
            }
        }

        return cleaned;
    }

    public static PGPPublicKey getMasterKeyFrom(PGPPublicKeyRing ring) {
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        while (it.hasNext()) {
            PGPPublicKey k = it.next();
            if (k.isMasterKey()) {
                return k;
            }
        }
        return null;
    }

    public static Set<Long> signingKeyIds(PGPSecretKeyRing ring) {
        Set<Long> ids = new HashSet<>();
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        while (it.hasNext()) {
            PGPPublicKey k = it.next();

            boolean signingKey = false;

            Iterator sit = k.getSignatures();
            while (sit.hasNext()) {
                Object n = sit.next();
                if (!(n instanceof PGPSignature)) {
                    continue;
                }

                PGPSignature s = (PGPSignature) n;
                if (!s.hasSubpackets()) {
                    continue;
                }

                try {
                    s.verifyCertification(ring.getPublicKey(s.getKeyID()));
                } catch (PGPException e) {
                    LOGGER.log(Level.WARNING, "Could not verify signature on " + Long.toHexString(k.getKeyID()) + " made by " + Long.toHexString(s.getKeyID()));
                    continue;
                }

                PGPSignatureSubpacketVector hashed = s.getHashedSubPackets();
                if (KeyFlag.fromInteger(hashed.getKeyFlags()).contains(KeyFlag.SIGN_DATA)) {
                    signingKey = true;
                    break;
                }
            }

            if (signingKey) {
                ids.add(k.getKeyID());
            }
        }
        return ids;
    }
}