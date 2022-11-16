// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.util.SessionKey;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * View for extracting metadata about a {@link Message}.
 */
public class MessageMetadata {

    protected Message message;

    public MessageMetadata(@Nonnull Message message) {
        this.message = message;
    }

    /**
     * Convert this {@link MessageMetadata} object into a legacy {@link OpenPgpMetadata} object.
     * This method is intended to be used for a transition period between the 1.3 / 1.4+ branches.
     * TODO: Remove in 1.5.X
     *
     * @return converted {@link OpenPgpMetadata} object
     */
    public @Nonnull OpenPgpMetadata toLegacyMetadata() {
        OpenPgpMetadata.Builder resultBuilder = OpenPgpMetadata.getBuilder();
        resultBuilder.setCompressionAlgorithm(getCompressionAlgorithm());
        Date modDate = getModificationDate();
        if (modDate != null) {
            resultBuilder.setModificationDate(modDate);
        }
        String fileName = getFilename();
        if (fileName != null) {
            resultBuilder.setFileName(fileName);
        }
        StreamEncoding encoding = getFormat();
        if (encoding != null) {
            resultBuilder.setFileEncoding(encoding);
        }
        resultBuilder.setSessionKey(getSessionKey());
        resultBuilder.setDecryptionKey(getDecryptionKey());

        for (SignatureVerification accepted : getVerifiedDetachedSignatures()) {
            resultBuilder.addVerifiedDetachedSignature(accepted);
        }
        for (SignatureVerification.Failure rejected : getRejectedDetachedSignatures()) {
            resultBuilder.addInvalidDetachedSignature(rejected.getSignatureVerification(), rejected.getValidationException());
        }

        for (SignatureVerification accepted : getVerifiedInlineSignatures()) {
            resultBuilder.addVerifiedInbandSignature(accepted);
        }
        for (SignatureVerification.Failure rejected : getRejectedInlineSignatures()) {
            resultBuilder.addInvalidInbandSignature(rejected.getSignatureVerification(), rejected.getValidationException());
        }
        if (message.isCleartextSigned()) {
            resultBuilder.setCleartextSigned();
        }

        return resultBuilder.build();
    }

    /**
     * Return the {@link SymmetricKeyAlgorithm} of the outermost encrypted data packet, or null if message is
     * unencrypted.
     *
     * @return encryption algorithm
     */
    public @Nullable SymmetricKeyAlgorithm getEncryptionAlgorithm() {
        Iterator<SymmetricKeyAlgorithm> algorithms = getEncryptionAlgorithms();
        if (algorithms.hasNext()) {
            return algorithms.next();
        }
        return null;
    }

    /**
     * Return an {@link Iterator} of {@link SymmetricKeyAlgorithm SymmetricKeyAlgorithms} encountered in the message.
     * The first item returned by the iterator is the algorithm of the outermost encrypted data packet, the next item
     * that of the next nested encrypted data packet and so on.
     * The iterator might also be empty, in case of an unencrypted message.
     *
     * @return iterator of symmetric encryption algorithms
     */
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

    /**
     * Return the {@link CompressionAlgorithm} of the outermost compressed data packet, or null, if the message
     * does not contain any compressed data packets.
     *
     * @return compression algorithm
     */
    public @Nullable CompressionAlgorithm getCompressionAlgorithm() {
        Iterator<CompressionAlgorithm> algorithms = getCompressionAlgorithms();
        if (algorithms.hasNext()) {
            return algorithms.next();
        }
        return null;
    }

    /**
     * Return an {@link Iterator} of {@link CompressionAlgorithm CompressionAlgorithms} encountered in the message.
     * The first item returned by the iterator is the algorithm of the outermost compressed data packet, the next
     * item that of the next nested compressed data packet and so on.
     * The iterator might also be empty, in case of a message without any compressed data packets.
     *
     * @return iterator of compression algorithms
     */
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

    /**
     * Return the {@link SessionKey} of the outermost encrypted data packet.
     * If the message was unencrypted, this method returns <pre>null</pre>.
     *
     * @return session key of the message
     */
    public @Nullable SessionKey getSessionKey() {
        Iterator<SessionKey> sessionKeys = getSessionKeys();
        if (sessionKeys.hasNext()) {
            return sessionKeys.next();
        }
        return null;
    }

    /**
     * Return an {@link Iterator} of {@link SessionKey SessionKeys} for all encrypted data packets in the message.
     * The first item returned by the iterator is the session key of the outermost encrypted data packet,
     * the next item that of the next nested encrypted data packet and so on.
     * The iterator might also be empty, in case of an unencrypted message.
     *
     * @return iterator of session keys
     */
    public @Nonnull Iterator<SessionKey> getSessionKeys() {
        return new LayerIterator<SessionKey>(message) {
            @Override
            boolean matches(Nested layer) {
                return layer instanceof EncryptedData;
            }

            @Override
            SessionKey getProperty(Layer last) {
                return ((EncryptedData) last).getSessionKey();
            }
        };
    }

    /**
     * Return a list of all verified detached signatures.
     * This list contains all acceptable, correct detached signatures.
     *
     * @return verified detached signatures
     */
    public @Nonnull List<SignatureVerification> getVerifiedDetachedSignatures() {
        return message.getVerifiedDetachedSignatures();
    }

    /**
     * Return a list of all rejected detached signatures.
     *
     * @return rejected detached signatures
     */
    public @Nonnull List<SignatureVerification.Failure> getRejectedDetachedSignatures() {
        return message.getRejectedDetachedSignatures();
    }

    /**
     * Return a list of all verified inline-signatures.
     * This list contains all acceptable, correct signatures that were part of the message itself.
     *
     * @return verified inline signatures
     */
    public @Nonnull List<SignatureVerification> getVerifiedInlineSignatures() {
        List<SignatureVerification> verifications = new ArrayList<>();
        Iterator<List<SignatureVerification>> verificationsByLayer = getVerifiedInlineSignaturesByLayer();
        while (verificationsByLayer.hasNext()) {
            verifications.addAll(verificationsByLayer.next());
        }
        return verifications;
    }

    /**
     * Return an {@link Iterator} of {@link List Lists} of verified inline-signatures of the message.
     * Since signatures might occur in different layers within a message, this method can be used to gain more detailed
     * insights into what signatures were encountered at what layers of the message structure.
     * Each item of the {@link Iterator} represents a layer of the message and contains only signatures from
     * this layer.
     * An empty list means no (or no acceptable) signatures were encountered in that layer.
     *
     * @return iterator of lists of signatures by-layer.
     */
    public @Nonnull Iterator<List<SignatureVerification>> getVerifiedInlineSignaturesByLayer() {
        return new LayerIterator<List<SignatureVerification>>(message) {
            @Override
            boolean matches(Nested layer) {
                return layer instanceof Layer;
            }

            @Override
            boolean matches(Layer layer) {
                return true;
            }

            @Override
            List<SignatureVerification> getProperty(Layer last) {
                List<SignatureVerification> list = new ArrayList<>();
                list.addAll(last.getVerifiedOnePassSignatures());
                list.addAll(last.getVerifiedPrependedSignatures());
                return list;
            }
        };
    }

    /**
     * Return a list of all rejected inline-signatures of the message.
     *
     * @return list of rejected inline-signatures
     */
    public @Nonnull List<SignatureVerification.Failure> getRejectedInlineSignatures() {
        List<SignatureVerification.Failure> rejected = new ArrayList<>();
        Iterator<List<SignatureVerification.Failure>> rejectedByLayer = getRejectedInlineSignaturesByLayer();
        while (rejectedByLayer.hasNext()) {
            rejected.addAll(rejectedByLayer.next());
        }
        return rejected;
    }

    /**
     * Similar to {@link #getVerifiedInlineSignaturesByLayer()}, this method returns all rejected inline-signatures
     * of the message, but organized by layer.
     *
     * @return rejected inline-signatures by-layer
     */
    public @Nonnull Iterator<List<SignatureVerification.Failure>> getRejectedInlineSignaturesByLayer() {
        return new LayerIterator<List<SignatureVerification.Failure>>(message) {
            @Override
            boolean matches(Nested layer) {
                return layer instanceof Layer;
            }

            @Override
            boolean matches(Layer layer) {
                return true;
            }

            @Override
            List<SignatureVerification.Failure> getProperty(Layer last) {
                List<SignatureVerification.Failure> list = new ArrayList<>();
                list.addAll(last.getRejectedOnePassSignatures());
                list.addAll(last.getRejectedPrependedSignatures());
                return list;
            }
        };
    }

    /**
     * Return the value of the literal data packet's filename field.
     * This value can be used to store a decrypted file under its original filename,
     * but since this field is not necessarily part of the signed data of a message, usage of this field is
     * discouraged.
     *
     * @return filename
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-5.9">RFC4880 §5.9. Literal Data Packet</a>
     */
    public @Nullable String getFilename() {
        LiteralData literalData = findLiteralData();
        if (literalData == null) {
            return null;
        }
        return literalData.getFileName();
    }

    /**
     * Return the value of the literal data packets modification date field.
     * This value can be used to restore the modification date of a decrypted file,
     * but since this field is not necessarily part of the signed data, its use is discouraged.
     *
     * @return modification date
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-5.9">RFC4880 §5.9. Literal Data Packet</a>
     */
    public @Nullable Date getModificationDate() {
        LiteralData literalData = findLiteralData();
        if (literalData == null) {
            return null;
        }
        return literalData.getModificationDate();
    }

    /**
     * Return the value of the format field of the literal data packet.
     * This value indicates what format (text, binary data, ...) the data has.
     * Since this field is not necessarily part of the signed data of a message, its usage is discouraged.
     *
     * @return format
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-5.9">RFC4880 §5.9. Literal Data Packet</a>
     */
    public @Nullable StreamEncoding getFormat() {
        LiteralData literalData = findLiteralData();
        if (literalData == null) {
            return null;
        }
        return literalData.getFormat();
    }

    /**
     * Find the {@link LiteralData} layer of an OpenPGP message.
     * Usually, every message has a literal data packet, but for malformed messages this method might still
     * return <pre>null</pre>.
     *
     * @return literal data
     */
    private @Nullable LiteralData findLiteralData() {
        Nested nested = message.getChild();
        if (nested == null) {
            return null;
        }

        while (nested != null && nested.hasNestedChild()) {
            Layer layer = (Layer) nested;
            nested = layer.getChild();
        }
        return (LiteralData) nested;
    }

    /**
     * Return the {@link SubkeyIdentifier} of the decryption key that was used to decrypt the outermost encryption
     * layer.
     * If the message was unencrypted, this might return <pre>null</pre>.
     *
     * @return decryption key
     */
    public SubkeyIdentifier getDecryptionKey() {
        Iterator<SubkeyIdentifier> iterator = new LayerIterator<SubkeyIdentifier>(message) {
            @Override
            public boolean matches(Nested layer) {
                return layer instanceof EncryptedData;
            }

            @Override
            public SubkeyIdentifier getProperty(Layer last) {
                return ((EncryptedData) last).decryptionKey;
            }
        };
        if (iterator.hasNext()) {
            return iterator.next();
        }
        return null;
    }

    public abstract static class Layer {
        public static final int MAX_LAYER_DEPTH = 16;
        protected final int depth;
        protected final List<SignatureVerification> verifiedDetachedSignatures = new ArrayList<>();
        protected final List<SignatureVerification.Failure> rejectedDetachedSignatures = new ArrayList<>();
        protected final List<SignatureVerification> verifiedOnePassSignatures = new ArrayList<>();
        protected final List<SignatureVerification.Failure> rejectedOnePassSignatures = new ArrayList<>();
        protected final List<SignatureVerification> verifiedPrependedSignatures = new ArrayList<>();
        protected final List<SignatureVerification.Failure> rejectedPrependedSignatures = new ArrayList<>();
        protected Nested child;

        public Layer(int depth) {
            this.depth = depth;
            if (depth > MAX_LAYER_DEPTH) {
                throw new MalformedOpenPgpMessageException("Maximum packet nesting depth (" + MAX_LAYER_DEPTH + ") exceeded.");
            }
        }

        /**
         * Return the nested child element of this layer.
         * Might return <pre>null</pre>, if this layer does not have a child element
         * (e.g. if this is a {@link LiteralData} packet).
         *
         * @return child element
         */
        public @Nullable Nested getChild() {
            return child;
        }

        /**
         * Set the nested child element for this layer.
         *
         * @param child child element
         */
        void setChild(Nested child) {
            this.child = child;
        }

        /**
         * Return a list of all verified detached signatures of this layer.
         *
         * @return all verified detached signatures of this layer
         */
        public List<SignatureVerification> getVerifiedDetachedSignatures() {
            return new ArrayList<>(verifiedDetachedSignatures);
        }

        /**
         * Return a list of all rejected detached signatures of this layer.
         *
         * @return all rejected detached signatures of this layer
         */
        public List<SignatureVerification.Failure> getRejectedDetachedSignatures() {
            return new ArrayList<>(rejectedDetachedSignatures);
        }

        /**
         * Add a verified detached signature for this layer.
         *
         * @param signatureVerification verified detached signature
         */
        void addVerifiedDetachedSignature(SignatureVerification signatureVerification) {
            verifiedDetachedSignatures.add(signatureVerification);
        }

        /**
         * Add a rejected detached signature for this layer.
         *
         * @param failure rejected detached signature
         */
        void addRejectedDetachedSignature(SignatureVerification.Failure failure) {
            rejectedDetachedSignatures.add(failure);
        }

        /**
         * Return a list of all verified one-pass-signatures of this layer.
         *
         * @return all verified one-pass-signatures of this layer
         */
        public List<SignatureVerification> getVerifiedOnePassSignatures() {
            return new ArrayList<>(verifiedOnePassSignatures);
        }

        /**
         * Return a list of all rejected one-pass-signatures of this layer.
         *
         * @return all rejected one-pass-signatures of this layer
         */
        public List<SignatureVerification.Failure> getRejectedOnePassSignatures() {
            return new ArrayList<>(rejectedOnePassSignatures);
        }

        /**
         * Add a verified one-pass-signature for this layer.
         *
         * @param verifiedOnePassSignature verified one-pass-signature for this layer
         */
        void addVerifiedOnePassSignature(SignatureVerification verifiedOnePassSignature) {
            this.verifiedOnePassSignatures.add(verifiedOnePassSignature);
        }

        /**
         * Add a rejected one-pass-signature for this layer.
         *
         * @param rejected rejected one-pass-signature for this layer
         */
        void addRejectedOnePassSignature(SignatureVerification.Failure rejected) {
            this.rejectedOnePassSignatures.add(rejected);
        }

        /**
         * Return a list of all verified prepended signatures of this layer.
         *
         * @return all verified prepended signatures of this layer
         */
        public List<SignatureVerification> getVerifiedPrependedSignatures() {
            return new ArrayList<>(verifiedPrependedSignatures);
        }

        /**
         * Return a list of all rejected prepended signatures of this layer.
         *
         * @return all rejected prepended signatures of this layer
         */
        public List<SignatureVerification.Failure> getRejectedPrependedSignatures() {
            return new ArrayList<>(rejectedPrependedSignatures);
        }

        /**
         * Add a verified prepended signature for this layer.
         *
         * @param verified verified prepended signature
         */
        void addVerifiedPrependedSignature(SignatureVerification verified) {
            this.verifiedPrependedSignatures.add(verified);
        }

        /**
         * Add a rejected prepended signature for this layer.
         *
         * @param rejected rejected prepended signature
         */
        void addRejectedPrependedSignature(SignatureVerification.Failure rejected) {
            this.rejectedPrependedSignatures.add(rejected);
        }

    }

    public interface Nested {
        boolean hasNestedChild();
    }

    public static class Message extends Layer {

        protected boolean cleartextSigned;

        public Message() {
            super(0);
        }

        /**
         * Returns true, is the message is a signed message using the cleartext signature framework.
         *
         * @return <pre>true</pre> if message is cleartext-signed, <pre>false</pre> otherwise
         * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-7">RFC4880 §7. Cleartext Signature Framework</a>
         */
        public boolean isCleartextSigned() {
            return cleartextSigned;
        }

    }

    public static class LiteralData implements Nested {
        protected String fileName;
        protected Date modificationDate;
        protected StreamEncoding format;

        public LiteralData() {
            this("", new Date(0L), StreamEncoding.BINARY);
        }

        public LiteralData(@Nonnull String fileName,
                           @Nonnull Date modificationDate,
                           @Nonnull StreamEncoding format) {
            this.fileName = fileName;
            this.modificationDate = modificationDate;
            this.format = format;
        }

        /**
         * Return the value of the filename field.
         * An empty String <pre>""</pre> indicates no filename.
         *
         * @return filename
         */
        public @Nonnull String getFileName() {
            return fileName;
        }

        /**
         * Return the value of the modification date field.
         * A special date <pre>{@code new Date(0L)}</pre> indicates no modification date.
         *
         * @return modification date
         */
        public @Nonnull Date getModificationDate() {
            return modificationDate;
        }

        /**
         * Return the value of the format field.
         *
         * @return format
         */
        public @Nonnull StreamEncoding getFormat() {
            return format;
        }

        @Override
        public boolean hasNestedChild() {
            // A literal data packet MUST NOT have a child element, as its content is the plaintext
            return false;
        }
    }

    public static class CompressedData extends Layer implements Nested {
        protected final CompressionAlgorithm algorithm;

        public CompressedData(@Nonnull CompressionAlgorithm zip, int depth) {
            super(depth);
            this.algorithm = zip;
        }

        /**
         * Return the {@link CompressionAlgorithm} used to compress the packet.
         * @return compression algorithm
         */
        public @Nonnull CompressionAlgorithm getAlgorithm() {
            return algorithm;
        }

        @Override
        public boolean hasNestedChild() {
            // A compressed data packet MUST have a child element
            return true;
        }
    }

    public static class EncryptedData extends Layer implements Nested {
        protected final SymmetricKeyAlgorithm algorithm;
        protected SubkeyIdentifier decryptionKey;
        protected SessionKey sessionKey;
        protected List<Long> recipients;

        public EncryptedData(@Nonnull SymmetricKeyAlgorithm algorithm, int depth) {
            super(depth);
            this.algorithm = algorithm;
        }

        /**
         * Return the {@link SymmetricKeyAlgorithm} used to encrypt the packet.
         * @return symmetric encryption algorithm
         */
        public @Nonnull SymmetricKeyAlgorithm getAlgorithm() {
            return algorithm;
        }

        /**
         * Return the {@link SessionKey} used to decrypt the packet.
         *
         * @return session key
         */
        public @Nonnull SessionKey getSessionKey() {
            return sessionKey;
        }

        /**
         * Return a list of all recipient key ids to which the packet was encrypted for.
         *
         * @return recipients
         */
        public @Nonnull List<Long> getRecipients() {
            return new ArrayList<>(recipients);
        }

        @Override
        public boolean hasNestedChild() {
            // An encrypted data packet MUST have a child element
            return true;
        }
    }


    private abstract static class LayerIterator<O> implements Iterator<O> {
        private Nested current;
        Layer last = null;
        Message parent;

        LayerIterator(@Nonnull Message message) {
            super();
            this.parent = message;
            this.current = message.getChild();
            if (matches(current)) {
                last = (Layer) current;
            }
        }

        @Override
        public boolean hasNext() {
            if (parent != null && matches(parent)) {
                return true;
            }
            if (last == null) {
                findNext();
            }
            return last != null;
        }

        @Override
        public O next() {
            if (parent != null && matches(parent)) {
                O property = getProperty(parent);
                parent = null;
                return property;
            }
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
            while (current != null && current instanceof Layer) {
                current = ((Layer) current).getChild();
                if (matches(current)) {
                    last = (Layer) current;
                    break;
                }
            }
        }

        boolean matches(Nested layer) {
            return false;
        }

        boolean matches(Layer layer) {
            if (layer instanceof Nested) {
                return matches((Nested) layer);
            }
            return false;
        }

        abstract O getProperty(Layer last);
    }
}
