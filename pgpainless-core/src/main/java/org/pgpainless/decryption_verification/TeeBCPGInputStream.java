package org.pgpainless.decryption_verification;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.pgpainless.util.ArmorUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TeeBCPGInputStream extends BCPGInputStream {

    private final OutputStream out;

    public TeeBCPGInputStream(InputStream in, OutputStream outputStream) {
        super(in);
        this.out = outputStream;
    }

    @Override
    public int read() throws IOException {
        int r = super.read();
        if (r != -1) {
            out.write(r);
        }
        return r;
    }

    @Override
    public int read(byte[] buf, int off, int len) throws IOException {
        int r = super.read(buf, off, len);
        if (r > 0) {
            out.write(buf, off, r);
        }
        return r;
    }
}
