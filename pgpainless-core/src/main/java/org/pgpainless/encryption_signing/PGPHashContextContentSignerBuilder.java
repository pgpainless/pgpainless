// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import java.io.OutputStream;
import java.security.MessageDigest;
import javax.annotation.Nonnull;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;

abstract class PGPHashContextContentSignerBuilder implements PGPContentSignerBuilder {

    // Copied from BC, required since BCs class is package visible only
    static class SignerOutputStream
            extends OutputStream {
        private Signer sig;

        SignerOutputStream(Signer sig) {
            this.sig = sig;
        }

        public void write(@Nonnull byte[] bytes, int off, int len) {
            sig.update(bytes, off, len);
        }

        public void write(@Nonnull byte[] bytes) {
            sig.update(bytes, 0, bytes.length);
        }

        public void write(int b) {
            sig.update((byte) b);
        }
    }


    static class ExistingMessageDigest implements Digest {

        private final MessageDigest digest;

        ExistingMessageDigest(MessageDigest messageDigest) {
            this.digest = messageDigest;
        }

        @Override
        public void update(byte in) {
            digest.update(in);
        }

        @Override
        public void update(byte[] in, int inOff, int len) {
            digest.update(in, inOff, len);
        }

        @Override
        public int doFinal(byte[] out, int outOff) {
            byte[] hash = digest.digest();
            System.arraycopy(hash, 0, out, outOff, hash.length);
            return getDigestSize();
        }

        @Override
        public void reset() {
            // Nope!
            // We cannot reset, since BCs signer classes are resetting in their init() methods, which would also reset
            // the messageDigest, losing its state. This would shatter our intention.
        }

        @Override
        public String getAlgorithmName() {
            return digest.getAlgorithm();
        }

        @Override
        public int getDigestSize() {
            return digest.getDigestLength();
        }
    }

}
