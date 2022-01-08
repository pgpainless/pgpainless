// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop;

/**
 * This class contains various information about a signed message.
 */
public final class SigningResult {

    private final MicAlg micAlg;

    private SigningResult(MicAlg micAlg) {
        this.micAlg = micAlg;
    }

    /**
     * Return a string identifying the digest mechanism used to create the signed message.
     * This is useful for setting the micalg= parameter for the multipart/signed
     * content type of a PGP/MIME object as described in section 5 of [RFC3156].
     *
     * If more than one signature was generated and different digest mechanisms were used,
     * the value of the micalg object is an empty string.
     *
     * @return micalg
     */
    public MicAlg getMicAlg() {
        return micAlg;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private MicAlg micAlg;

        public Builder setMicAlg(MicAlg micAlg) {
            this.micAlg = micAlg;
            return this;
        }

        public SigningResult build() {
            SigningResult signingResult = new SigningResult(micAlg);
            return signingResult;
        }
    }
}
