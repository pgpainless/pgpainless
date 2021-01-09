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
package org.pgpainless.key;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;

/**
 * This class contains a set of slightly out of spec or weird keys.
 * Those are used to test whether implementations behave correctly when dealing with such keys.
 *
 * Original source: https://gitlab.com/sequoia-pgp/weird-keys
 */
public class WeirdKeys {

    /**
     * This key has two encryption subkeys, both "may be used to encrypt
     * communications" (key flag 0x04), and "may be used to encrypt storage"
     * (key flag 0x08).
     */
    public static final String TWO_CRYPT_SUBKEYS = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
        "\n" +
        "xVgEWxpOHRYJKwYBBAHaRw8BAQdAxq7YVmI0c+fxhv9fCd3SwrVIvXiUkKjS/Zz8\n" +
        "xmkV+4YAAP9QXswTMSNZScLMSB186DmFrDYvdv9a5dYJaMbn3ssAXBBVzRpUd28g\n" +
        "RmlzaCA8dHdvQGV4YW1wbGUub3JnPsJ+BBMWCgAwApsDBYJbGk4dBYkB3+IAFqEE\n" +
        "K3dX2K8oNGigV0aZkQ5VRHjM3gAJkJEOVUR4zN4AAAC9/AD9F+KyqaTdSZxn6KKd\n" +
        "grcOiunuxA1pZ/bP2TYBWLXoirQA+wTm9K2aSc9YulbJcFF3XKQJDzvKeDyknok+\n" +
        "TVzYIVMIx10EWxpOHRIKKwYBBAGXVQEFAQEHQEr7lcszstnVdhkTOYGfZJuYQznG\n" +
        "pfz2/Jydug3Mmn19AwEKCQAA/3jWHYWk3UY4L9aqcHwJj9VdKxrjP5soyUx1Uey/\n" +
        "4dUYENHCfgQYFgoAMAKbDAWCWxpOHQWJAd/iABahBCt3V9ivKDRooFdGmZEOVUR4\n" +
        "zN4ACZCRDlVEeMzeAAAAllIBAPrKUhqobdgqYkK2sz6Rmh+EYFKDfQw2/PEfdRU4\n" +
        "WGuWAP9RR1cEVzArXFgjfuyoeFjH7eUUY8+mLcpzEgKrykhxD8ddBFsaTh0SCisG\n" +
        "AQQBl1UBBQEBB0AZvZWhCE0hWegUjFz193npbGPib3EmdzgbbrfjefDNNAMBCgkA\n" +
        "AP9e5eLZhejDULF5JI9OQ7mCrabEEYbuoPy2njhHJa5XwBMbwn4EGBYKADACmwwF\n" +
        "glsaTh0FiQHf4gAWoQQrd1fYryg0aKBXRpmRDlVEeMzeAAmQkQ5VRHjM3gAAAAj2\n" +
        "AP0bD/gR70zkMKwC3+dEpPZ41+gyjlrrrHbGMiaBEzug5QD/e3I6t5XtPbRg66np\n" +
        "GwsOQiY1zEbCH/CpCRO3w/OQUgM=\n" +
        "=+0IG\n" +
        "-----END PGP PRIVATE KEY BLOCK-----\n";

    public static PGPSecretKeyRing getTwoCryptSubkeysKey() throws IOException, PGPException {
        return PGPainless.readKeyRing().secretKeyRing(TWO_CRYPT_SUBKEYS);
    }

    /**
     * This key has two encryption subkeys, both "may be used to encrypt
     * communications" (key flag 0x04), and "may be used to encrypt storage"
     * (key flag 0x08).
     */
    public static final String ARCHIVE_COMMS_SUBKEYS = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xVgEWxjzpRYJKwYBBAHaRw8BAQdA99pRASsejv2MgFMYg6LDPyK3BCT7xXhC2f09\n" +
            "fqT7oQEAAQCouh/2DcFODQGEARwJU3JXvna3ylSGENAxk/0fFmStXQ07zSZCYXJi\n" +
            "YXJhIEJvb2t3b3JtIDxiYXJiYXJhQGV4YW1wbGUub3JnPsJ+BBMWCgAwApsDBYJb\n" +
            "GPOlBYkB3+IAFqEE1IeY6A/QyQJeHtHU084ZkNvzgW8JkNPOGZDb84FvAACnswEA\n" +
            "tRh0mZPid3fMJH0i/Z2mYniJDkjZSlTcyjU71qPbifIA/1rapZ4lSk4x0/spKB6b\n" +
            "DU2On70rFOiHm+Dgn2BiI6gKx10EWxjzpRIKKwYBBAGXVQEFAQEHQDMzo7bN+wEH\n" +
            "8HaSeuhpt6Qbl5fDqjvjXTq46fVLyJFqAwEKCQAA/0wtp9u69jRBfQnZkf/X0Ed3\n" +
            "WbswE4XPremh+UPYYbCwEyrCfgQYFgoAMAKbCAWCWxjzpQWJAd/iABahBNSHmOgP\n" +
            "0MkCXh7R1NPOGZDb84FvCZDTzhmQ2/OBbwAAmN8A+gNLRbqxCfyVxFeUuTRpAM+g\n" +
            "vPxW/x8Wn6EXgYuyzXB0AP4xg/dWdZEaORArLgrFNzeQVxhWwT9LQ0wkKK2MDP7y\n" +
            "DcddBFsY86USCisGAQQBl1UBBQEBB0DCSkkrqL/6JMFuPdhD3VJd35dBIM618Niv\n" +
            "i8gzZWMARAMBCgkAAP93iLDHFbRfBV1J/OIxjjQny2h5XRdjOzFPxYxnDOd1IA6+\n" +
            "wn4EGBYKADACmwQFglsY86UFiQHf4gAWoQTUh5joD9DJAl4e0dTTzhmQ2/OBbwmQ\n" +
            "084ZkNvzgW8AAHv1AP9psIMvVd3G7ha+aITWjj8J+YpJ6Q4MC7fWNJ8jWf7FAAD+\n" +
            "Ki/Tb93AMDlwEMcZsyKj3Oa28tsS1ybS6y3ZSs4wqQs=\n" +
            "=h6sT\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    public static PGPSecretKeyRing getArchiveCommsSubkeysKey() throws IOException, PGPException {
        return PGPainless.readKeyRing().secretKeyRing(ARCHIVE_COMMS_SUBKEYS);
    }
}
