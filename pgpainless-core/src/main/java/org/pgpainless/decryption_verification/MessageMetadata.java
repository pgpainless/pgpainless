// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.util.SessionKey;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

public class MessageMetadata {

    protected Message message;

    public MessageMetadata(@Nonnull Message message) {
        this.message = message;
    }

    public @Nullable SymmetricKeyAlgorithm getEncryptionAlgorithm() {
        Iterator<SymmetricKeyAlgorithm> algorithms = getEncryptionAlgorithms();
        if (algorithms.hasNext()) {
            return algorithms.next();
        }
        return null;
    }

    public @Nonnull Iterator<SymmetricKeyAlgorithm> getEncryptionAlgorithms() {
        return new LayerIterator<SymmetricKeyAlgorithm>(message) {
            @Override
            public boolean matches(Nested layer) {
                return layer instanceof EncryptedData;
            }

            @Override
            public SymmetricKeyAlgorithm getProperty(Layer last) {
                return ((EncryptedData) last).algorithm;
            }
        };
    }

    public @Nullable CompressionAlgorithm getCompressionAlgorithm() {
        Iterator<CompressionAlgorithm> algorithms = getCompressionAlgorithms();
        if (algorithms.hasNext()) {
            return algorithms.next();
        }
        return null;
    }

    public @Nonnull Iterator<CompressionAlgorithm> getCompressionAlgorithms() {
        return new LayerIterator<CompressionAlgorithm>(message) {
            @Override
            public boolean matches(Nested layer) {
                return layer instanceof CompressedData;
            }

            @Override
            public CompressionAlgorithm getProperty(Layer last) {
                return ((CompressedData) last).algorithm;
            }
        };
    }

    public String getFilename() {
        return findLiteralData().getFileName();
    }

    public Date getModificationDate() {
        return findLiteralData().getModificationDate();
    }

    public StreamEncoding getFormat() {
        return findLiteralData().getFormat();
    }

    private LiteralData findLiteralData() {
        Nested nested = message.child;
        while (nested.hasNestedChild()) {
            Layer layer = (Layer) nested;
            nested = layer.child;
        }
        return (LiteralData) nested;
    }

    public abstract static class Layer {
        protected final List<SignatureVerification> verifiedSignatures = new ArrayList<>();
        protected final List<SignatureVerification.Failure> failedSignatures = new ArrayList<>();
        protected Nested child;

        public Nested getChild() {
            return child;
        }

        public void setChild(Nested child) {
            this.child = child;
        }

        public List<SignatureVerification> getVerifiedSignatures() {
            return new ArrayList<>(verifiedSignatures);
        }

        public List<SignatureVerification.Failure> getFailedSignatures() {
            return new ArrayList<>(failedSignatures);
        }
    }

    public interface Nested {
        boolean hasNestedChild();
    }

    public static class Message extends Layer {

    }

    public static class LiteralData implements Nested {
        protected String fileName;
        protected Date modificationDate;
        protected StreamEncoding format;

        public LiteralData() {
            this("", new Date(0L), StreamEncoding.BINARY);
        }

        public LiteralData(String fileName, Date modificationDate, StreamEncoding format) {
            this.fileName = fileName;
            this.modificationDate = modificationDate;
            this.format = format;
        }

        public String getFileName() {
            return fileName;
        }

        public Date getModificationDate() {
            return modificationDate;
        }

        public StreamEncoding getFormat() {
            return format;
        }

        @Override
        public boolean hasNestedChild() {
            return false;
        }
    }

    public static class CompressedData extends Layer implements Nested {
        protected final CompressionAlgorithm algorithm;

        public CompressedData(CompressionAlgorithm zip) {
            this.algorithm = zip;
        }

        public CompressionAlgorithm getAlgorithm() {
            return algorithm;
        }

        @Override
        public boolean hasNestedChild() {
            return true;
        }
    }

    public static class EncryptedData extends Layer implements Nested {
        protected final SymmetricKeyAlgorithm algorithm;
        protected SessionKey sessionKey;
        protected List<Long> recipients;

        public EncryptedData(SymmetricKeyAlgorithm algorithm) {
            this.algorithm = algorithm;
        }

        public SymmetricKeyAlgorithm getAlgorithm() {
            return algorithm;
        }

        public SessionKey getSessionKey() {
            return sessionKey;
        }

        public List<Long> getRecipients() {
            return new ArrayList<>(recipients);
        }

        @Override
        public boolean hasNestedChild() {
            return true;
        }
    }


    private abstract static class LayerIterator<O> implements Iterator<O> {
        private Nested current;
        Layer last = null;

        LayerIterator(Message message) {
            super();
            this.current = message.child;
            if (matches(current)) {
                last = (Layer) current;
            }
        }

        @Override
        public boolean hasNext() {
            if (last == null) {
                findNext();
            }
            return last != null;
        }

        @Override
        public O next() {
            if (last == null) {
                findNext();
            }
            if (last != null) {
                O property = getProperty(last);
                last = null;
                return property;
            }
            throw new NoSuchElementException();
        }

        private void findNext() {
            while (current instanceof Layer) {
                current = ((Layer) current).child;
                if (matches(current)) {
                    last = (Layer) current;
                    break;
                }
            }
        }

        abstract boolean matches(Nested layer);

        abstract O getProperty(Layer last);
    }

}
