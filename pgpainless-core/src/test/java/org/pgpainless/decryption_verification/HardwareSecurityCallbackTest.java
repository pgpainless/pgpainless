package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.util.SessionKey;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class HardwareSecurityCallbackTest {

    @Test
    public void test() throws PGPException, IOException {
        PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(new byte[0]))
                .withOptions(ConsumerOptions.get()
                        .setHardwareDecryptionCallback(new HardwareSecurity.DecryptionCallback() {
                            @Override
                            public SessionKey decryptSessionKey(PGPPublicKeyEncryptedData pkesk) throws HardwareSecurity.HardwareSecurityException {
                                /*
                                pkesk.getSessionKey(new PublicKeyDataDecryptorFactory() {
                                    @Override
                                    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData) throws PGPException {
                                        return new byte[0];
                                    }

                                    @Override
                                    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key) throws PGPException {
                                        return null;
                                    }
                                });
                                 */
                                return null;
                            }
                        }));
    }
}
