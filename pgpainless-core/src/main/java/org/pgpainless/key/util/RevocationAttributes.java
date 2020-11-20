/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.key.util;

public final class RevocationAttributes {

    public enum Reason {
        NO_REASON((byte) 0),
        KEY_SUPERSEDED((byte) 1),
        KEY_COMPROMISED((byte) 2),
        KEY_RETIRED((byte) 3),
        USER_ID_NO_LONGER_VALID((byte) 32),
        ;

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

    public Reason getReason() {
        return reason;
    }

    public String getDescription() {
        return description;
    }

    public static WithReason createKeyRevocation() {
        return new WithReason(RevocationType.KEY_REVOCATION);
    }

    public static WithReason createCertificateRevocation() {
        return new WithReason(RevocationType.CERT_REVOCATION);
    }

    public static final class WithReason {

        private final RevocationType type;

        private WithReason(RevocationType type) {
            this.type = type;
        }

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

        public RevocationAttributes withDescription(String description) {
            return new RevocationAttributes(reason, description);
        }
    }
}
