/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.pgpainless;

import static junit.framework.TestCase.assertEquals;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.Test;
import org.pgpainless.pgpainless.key.OpenPgpV4Fingerprint;

public class OpenPgpV4FingerprintTest {

    @Test(expected = PGPException.class)
    public void fpTooShort() throws PGPException {
        String fp = "484f57414c495645"; // Asking Mark
        new OpenPgpV4Fingerprint(fp);
    }

    @Test(expected = PGPException.class)
    public void invalidHexTest() throws PGPException {
        String fp = "UNFORTUNATELYTHISISNOVALIDHEXADECIMALDOH";
        new OpenPgpV4Fingerprint(fp);
    }

    @Test
    public void validFingerprintTest() throws PGPException {
        String fp = "4A4F48414E4E53454E2049532041204E45524421";
        OpenPgpV4Fingerprint finger = new OpenPgpV4Fingerprint(fp);
        assertEquals(fp, finger.toString());
    }

    @Test
    public void convertsToUpperCaseTest() throws PGPException {
        String fp = "444f4e5420552048415645204120484f4242593f";
        OpenPgpV4Fingerprint finger = new OpenPgpV4Fingerprint(fp);
        assertEquals("444F4E5420552048415645204120484F4242593F", finger.toString());
    }

    @Test
    public void equalsOtherFingerprintTest() throws PGPException {
        OpenPgpV4Fingerprint finger = new OpenPgpV4Fingerprint("5448452043414b452049532041204c4945212121");
        assertEquals(finger, new OpenPgpV4Fingerprint("5448452043414B452049532041204C4945212121"));
    }

    @Test
    public void keyIdTest() throws IOException, PGPException {
        PGPPublicKey key = TestKeys.getJulietPublicKeyRing().getPublicKey();
        long keyId = key.getKeyID();

        OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(key);
        assertEquals(keyId, fingerprint.getKeyId());
    }
}
