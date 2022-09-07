// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import javax.annotation.Nonnull;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class RevocationAttributes {

    /**
     * Reason for revocation.
     * There are two kinds of reasons: hard and soft reason.
     *
     * Soft revocation reasons gracefully disable keys or user-ids.
     * Softly revoked keys can no longer be used to encrypt data to or to generate signatures.
     * Any signature made after a key has been soft revoked is deemed invalid.
     * Any signature made before the key has been soft revoked stays valid.
     * Soft revoked info can be re-certified at a later point.
     *
     * Hard revocation reasons on the other hand renders the key or user-id invalid immediately.
     * Hard reasons are suitable to use if for example a key got compromised.
     * Any signature made before or after a key has been hard revoked is no longer considered valid.
     * Hard revoked information can also not be re-certified.
     */
    public enum Reason {
        /**
         * The key or certification is being revoked without a reason.
         * This is a HARD revocation reason and cannot be undone.
         */
        NO_REASON((byte) 0),
        /**
         * The key was superseded by another key.
         * This is a SOFT revocation reason and can be undone.
         */
        KEY_SUPERSEDED((byte) 1),
        /**
         * The key has potentially been compromised.
         * This is a HARD revocation reason and cannot be undone.
         */
        KEY_COMPROMISED((byte) 2),
        /**
         * The key was retired and shall no longer be used.
         * This is a SOFT revocation reason can can be undone.
         */
        KEY_RETIRED((byte) 3),
        /**
         * The user-id is no longer valid.
         * This is a SOFT revocation reason and can be undone.
         */
        USER_ID_NO_LONGER_VALID((byte) 32),
        ;

        private static final Map<Byte, Reason> MAP = new ConcurrentHashMap<>();
        static {
            for (Reason r : Reason.values()) {
                MAP.put(r.reasonCode, r);
            }
        }

        /**
         * Decode a machine-readable reason code.
         *
         * @param code byte
         * @return reason
         */
        public static Reason fromCode(byte code) {
            Reason reason = MAP.get(code);
            if (reason == null) {
                throw new IllegalArgumentException("Invalid revocation reason: " + code);
            }
            return reason;
        }

        /**
         * Return true if the {@link Reason} the provided code encodes is a hard revocation reason, false
         * otherwise.
         * Hard revocations cannot be undone, while keys or certifications with soft revocations can be
         * re-certified by placing another signature on them.
         *
         * @param code reason code
         * @return is hard
         */
        public static boolean isHardRevocation(byte code) {
            Reason reason = MAP.get(code);
            return reason != KEY_SUPERSEDED && reason != KEY_RETIRED && reason != USER_ID_NO_LONGER_VALID;
        }

        /**
         * Return true if the given {@link Reason} is a hard revocation, false otherwise.
         * Hard revocations cannot be undone, while keys or certifications with soft revocations can be
         * re-certified by placing another signature on them.
         *
         * @param reason reason
         * @return is hard
         */
        public static boolean isHardRevocation(@Nonnull Reason reason) {
            return isHardRevocation(reason.reasonCode);
        }

        private final byte reasonCode;

        Reason(byte reasonCode) {
            this.reasonCode = reasonCode;
        }

        public byte code() {
            return reasonCode;
        }

        @Override
        public String toString() {
            return code() + " - " + name();
        }
    }

    public enum RevocationType {
        KEY_REVOCATION,
        CERT_REVOCATION
    }

    private final Reason reason;
    private final String description;

    private RevocationAttributes(Reason reason, String description) {
        this.reason = reason;
        this.description = description;
    }

    /**
     * Return the machine-readable reason for revocation.
     *
     * @return reason
     */
    public @Nonnull Reason getReason() {
        return reason;
    }

    /**
     * Return the human-readable description for the revocation reason.
     * @return description
     */
    public @Nonnull String getDescription() {
        return description;
    }

    /**
     * Build a {@link RevocationAttributes} object suitable for key revocations.
     * Key revocations are revocations for keys or subkeys.
     *
     * @return builder
     */
    public static WithReason createKeyRevocation() {
        return new WithReason(RevocationType.KEY_REVOCATION);
    }

    /**
     * Build a {@link RevocationAttributes} object suitable for certification (e.g. user-id) revocations.
     *
     * @return builder
     */
    public static WithReason createCertificateRevocation() {
        return new WithReason(RevocationType.CERT_REVOCATION);
    }

    public static final class WithReason {

        private final RevocationType type;

        private WithReason(RevocationType type) {
            this.type = type;
        }

        /**
         * Set the machine-readable reason.
         * Note that depending on whether this is a key-revocation or certification-revocation,
         * only certain reason codes are valid.
         * Invalid input will result in an {@link IllegalArgumentException} to be thrown.
         *
         * @param reason reason
         * @throws IllegalArgumentException in case of an invalid revocation reason
         * @return builder
         */
        public WithDescription withReason(Reason reason) {
            throwIfReasonTypeMismatch(reason, type);
            return new WithDescription(reason);
        }

        private void throwIfReasonTypeMismatch(Reason reason, RevocationType type) {
            if (type == RevocationType.KEY_REVOCATION) {
                if (reason == Reason.USER_ID_NO_LONGER_VALID) {
                    throw new IllegalArgumentException("Reason " + reason + " can only be used for certificate revocations, not to revoke keys.");
                }
            } else if (type == RevocationType.CERT_REVOCATION) {
                switch (reason) {
                    case KEY_SUPERSEDED:
                    case KEY_COMPROMISED:
                    case KEY_RETIRED:
                        throw new IllegalArgumentException("Reason " + reason + " can only be used for key revocations, not to revoke certificates.");
                }
            }
        }

    }

    public static final class WithDescription {

        private final Reason reason;

        private WithDescription(Reason reason) {
            this.reason = reason;
        }

        /**
         * Set a human-readable description of the revocation reason.
         *
         * @param description description
         * @return revocation attributes
         */
        public RevocationAttributes withDescription(@Nonnull String description) {
            return new RevocationAttributes(reason, description);
        }

        /**
         * Set an empty human-readable description.
         * @return revocation attributes
         */
        public RevocationAttributes withoutDescription() {
            return withDescription("");
        }
    }
}
