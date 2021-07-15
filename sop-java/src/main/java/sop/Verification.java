/*
 * Copyright 2021 Paul Schaub.
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
package sop;

import java.util.Date;

import sop.util.UTCUtil;

public class Verification {

    private final Date creationTime;
    private final String signingKeyFingerprint;
    private final String signingCertFingerprint;

    public Verification(Date creationTime, String signingKeyFingerprint, String signingCertFingerprint) {
        this.creationTime = creationTime;
        this.signingKeyFingerprint = signingKeyFingerprint;
        this.signingCertFingerprint = signingCertFingerprint;
    }

    /**
     * Return the signatures creation time.
     *
     * @return signature creation time
     */
    public Date getCreationTime() {
        return creationTime;
    }

    /**
     * Return the fingerprint of the signing (sub)key.
     *
     * @return signing key fingerprint
     */
    public String getSigningKeyFingerprint() {
        return signingKeyFingerprint;
    }

    /**
     * Return the fingerprint fo the signing certificate.
     *
     * @return signing certificate fingerprint
     */
    public String getSigningCertFingerprint() {
        return signingCertFingerprint;
    }

    @Override
    public String toString() {
        return UTCUtil.formatUTCDate(getCreationTime()) +
                ' ' +
                getSigningKeyFingerprint() +
                ' ' +
                getSigningCertFingerprint();
    }
}
