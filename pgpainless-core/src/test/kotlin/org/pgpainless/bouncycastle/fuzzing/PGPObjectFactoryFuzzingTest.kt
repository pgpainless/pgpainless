// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.fuzzing

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import java.io.EOFException
import java.io.IOException
import org.bouncycastle.bcpg.ArmoredInputException
import org.bouncycastle.bcpg.UnsupportedPacketVersionException
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory

class PGPObjectFactoryFuzzingTest {

    @FuzzTest
    fun parseFuzzedObjects(provider: FuzzedDataProvider) {
        val encoding = provider.consumeRemainingAsBytes()

        if (encoding.isEmpty()) {
            return
        }
        try {
            val decIn = PGPUtil.getDecoderStream(encoding.inputStream())
            val objFac = BcPGPObjectFactory(decIn)
            var obj = objFac.nextObject()
            while (obj != null) {
                obj = objFac.nextObject()
            }
        } catch (e: ArmoredInputException) {
            return
        } catch (e: PGPException) {
            return
        } catch (e: EOFException) {
            return
        } catch (e: IOException) {
            return
        } catch (e: UnsupportedPacketVersionException) {
            return
        } catch (e: ClassCastException) {
            if (e.message?.contains("SecretSubkeyPacket") != false) {
                return
            }
            throw e
        } catch (e: OutOfMemoryError) {
            return
        }
    }
}
