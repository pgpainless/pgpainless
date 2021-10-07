// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.collection;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.util.ArmorUtils;

/**
 * This class describes a logic of handling a collection of different {@link PGPKeyRing}. The logic was inspired by
 * {@link PGPSecretKeyRingCollection} and {@link PGPPublicKeyRingCollection}.
 */
public class PGPKeyRingCollection {

    private final PGPSecretKeyRingCollection pgpSecretKeyRingCollection;
    private final PGPPublicKeyRingCollection pgpPublicKeyRingCollection;

    public PGPKeyRingCollection(@Nonnull byte[] encoding, boolean isSilent) throws IOException, PGPException {
        this(new ByteArrayInputStream(encoding), isSilent);
    }

    /**
     * Build a {@link PGPKeyRingCollection} from the passed in input stream.
     *
     * @param in       input stream containing data
     * @param isSilent flag indicating that unsupported objects will be ignored
     * @throws IOException  if a problem parsing the base stream occurs
     * @throws PGPException if an object is encountered which isn't a {@link PGPSecretKeyRing} or {@link PGPPublicKeyRing}
     */
    public PGPKeyRingCollection(@Nonnull InputStream in, boolean isSilent) throws IOException, PGPException {
        // Double getDecoderStream because of #96
        InputStream decoderStream = ArmorUtils.getDecoderStream(in);
        PGPObjectFactory pgpFact = new PGPObjectFactory(decoderStream, ImplementationFactory.getInstance().getKeyFingerprintCalculator());
        Object obj;

        List<PGPSecretKeyRing> secretKeyRings = new ArrayList<>();
        List<PGPPublicKeyRing> publicKeyRings = new ArrayList<>();

        while ((obj = pgpFact.nextObject()) != null) {
            if (obj instanceof PGPMarker) {
                // Skip marker packets
                continue;
            }
            if (obj instanceof PGPSecretKeyRing) {
                secretKeyRings.add((PGPSecretKeyRing) obj);
            } else if (obj instanceof PGPPublicKeyRing) {
                publicKeyRings.add((PGPPublicKeyRing) obj);
            } else if (!isSilent) {
                throw new PGPException(obj.getClass().getName() + " found where " +
                        PGPSecretKeyRing.class.getSimpleName() + " or " +
                        PGPPublicKeyRing.class.getSimpleName() + " expected");
            }
        }

        pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(secretKeyRings);
        pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(publicKeyRings);
    }

    public PGPKeyRingCollection(@Nonnull Collection<PGPKeyRing> collection, boolean isSilent)
            throws IOException, PGPException {
        List<PGPSecretKeyRing> secretKeyRings = new ArrayList<>();
        List<PGPPublicKeyRing> publicKeyRings = new ArrayList<>();

        for (PGPKeyRing pgpKeyRing : collection) {
            if (pgpKeyRing instanceof PGPSecretKeyRing) {
                secretKeyRings.add((PGPSecretKeyRing) pgpKeyRing);
            } else if (pgpKeyRing instanceof PGPPublicKeyRing) {
                publicKeyRings.add((PGPPublicKeyRing) pgpKeyRing);
            } else if (!isSilent) {
                throw new PGPException(pgpKeyRing.getClass().getName() + " found where " +
                        PGPSecretKeyRing.class.getSimpleName() + " or " +
                        PGPPublicKeyRing.class.getSimpleName() + " expected");
            }
        }

        pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(secretKeyRings);
        pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(publicKeyRings);
    }

    public @Nonnull PGPSecretKeyRingCollection getPGPSecretKeyRingCollection() {
        return pgpSecretKeyRingCollection;
    }

    public @Nonnull PGPPublicKeyRingCollection getPgpPublicKeyRingCollection() {
        return pgpPublicKeyRingCollection;
    }

    /**
     * Return the number of rings in this collection.
     *
     * @return total size of {@link PGPSecretKeyRingCollection} and {@link PGPPublicKeyRingCollection}
     * in this collection
     */
    public int size() {
        return pgpSecretKeyRingCollection.size() + pgpPublicKeyRingCollection.size();
    }
}
