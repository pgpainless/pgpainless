package org.pgpainless.pgpainless.key.selection.key.impl;

import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.pgpainless.key.selection.key.PublicKeySelectionStrategy;

public class SignedByMasterKey {

    private static final Logger LOGGER = Logger.getLogger(SignedByMasterKey.class.getName());

    public static class PubkeySelectionStrategy extends PublicKeySelectionStrategy<Long> {

        @Override
        public boolean accept(Long identifier, PGPPublicKey key) {
            Iterator<PGPSignature> signatures = key.getSignaturesForKeyID(identifier);
            while (signatures.hasNext()) {
                PGPSignature signature = signatures.next();
                if (signature.getSignatureType() == PGPSignature.SUBKEY_BINDING) {
                    try {
                        return signature.verify();
                    } catch (PGPException e) {
                        LOGGER.log(Level.WARNING, "Could not verify subkey signature of key " +
                                Long.toHexString(signature.getKeyID()) + " on key " + Long.toHexString(key.getKeyID()));

                        return false;
                    }
                }
            }
            return false;
        }
    }
}
