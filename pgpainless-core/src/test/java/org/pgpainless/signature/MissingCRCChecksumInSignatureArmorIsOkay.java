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
package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;

public class MissingCRCChecksumInSignatureArmorIsOkay {

    public static final String ARMORED_SIGNATURE_WITH_MISSING_CRC_SUM = "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "wsE7BAABCgBvBYJgyf3FCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
            "cy5zZXF1b2lhLXBncC5vcmdbH+E3jkMYSiFZOF5cHIUCy8UjqEvHbrCCxxhnEu1J\n" +
            "ThYhBNGmbhojsYLJmA94jPv8yCoBXnMwAACzOAv/QAmXX9mPJ4Xtk1SNKPH11izO\n" +
            "G8OK+dKL46O7AQGJFjdwiA8SdyFatVzUUNHcyi0HJ2iNes5DPObxDweqy9MijHkx\n" +
            "U4RotWUwdhGoTWqAj3cipDXJZi4MD46qi8AkmmT1xGk3GuPH/ymgbefMIZymczKw\n" +
            "1YjDoq0AFVCeBWekCsVjZsUYBamgG0WNKEKXk3bNHObaUAqpJZFKvZKslZByyuOm\n" +
            "nq5BlscmalWTxhDPNZDPigFeoa+MI72ckquD9cJG3P4WHaWos0EfkWDwIRhB4888\n" +
            "5jB4moQr6dDfELbtEqcBj9CecrXmPqv18qmoIgR9tAeeJsyqIC5TS9j6iDoYJ9bJ\n" +
            "4H4OcfJtTtXMSMPppH/hEOS88R/F2m0Szc4leyHtXSZXZ2I8RJLG4u+2RZlh+vBh\n" +
            "sakyriei09Kz3Gdk6deDCO0uCrYQA7GQ9xFMzrfay1B0Lr7pAe8BTg6xuauwfGZh\n" +
            "wDz6hyIxJ3IhAln5GX7NGsXu3eoEjMfZZ29rY7BC\n" +
            "-----END PGP SIGNATURE-----";

    @Test
    public void assertMissingCRCSumInSignatureArmorIsOkay() throws PGPException, IOException {
        List<PGPSignature> signatureList = SignatureUtils.readSignatures(ARMORED_SIGNATURE_WITH_MISSING_CRC_SUM);
        assertEquals(1, signatureList.size());
    }
}
