// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.api.OpenPGPKeyReader;

import java.io.IOException;

public class PublicKeyPacketFuzzTest {

    private final OpenPGPKeyReader reader = new OpenPGPKeyReader();

    @FuzzTest(maxDuration = "60s")
    public void parsePublicKeyPacket(FuzzedDataProvider provider) {
        byte[] encoding = provider.consumeRemainingAsBytes();
        if (encoding.length == 0) {
            return;
        }

        try {
            reader.parseCertificate(encoding);
        } catch (IOException e) {
            // ignore
        } catch (UnsupportedPacketVersionException e) {
            // ignore
        } catch (ClassCastException e) {
            // ignore
        }
    }
}
