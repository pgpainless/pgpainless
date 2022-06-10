// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.misc;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.cli.PGPainlessCLI;
import org.pgpainless.cli.TestUtils;
import sop.exception.SOPGPException;

public class SignUsingPublicKeyBehaviorTest {

    public static final String KEY_THAT_IS_A_CERT = "" +
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xcLYBF2lnPIBCACjEFpOZIbVN2la1dFPlhksA6D7D/n+eQ0y+201cWZXFLJ0MAE0\n" +
            "L+9lK1hvp1XTfFvdChdMmgziTLhyR/1im0qk38oVMpyF8JKJ118U35+y5rObaB5I\n" +
            "sbzka4y5Qj5KXTtHEXSsMH8bkBoUUXcbNvw+FFys8ZcW/21fvzB8ZD4vtef6ogNZ\n" +
            "hG/W0+Mi2d/zBhZqiHEHR6bJeIGmFhfT36C0jXssRL5de44xpWSqwqfHBrx6n7sq\n" +
            "iDABT2sEzckDNikobhnZ1ZRay+1xxAJDKVglRzb3O/fgvV+vUE90OI2r9iX6kpiC\n" +
            "sybpAwrlYCHz/NXJZ6wjFCKccNyrxuunjkC3ABEBAAEAB/sEMKNhaEveprHaV6wt\n" +
            "M1oqO12jleGCnHGuYa+ItAVBL5L2UVV2ldS88MQw+kfGS2fA4kV+/mZeWkJTDW6B\n" +
            "XiQo4Gc87DQBbREW4aXbz3M3EZ6D28ULcSW9aNYQ3JblKkgfp18sHYLmnmlNJFq/\n" +
            "JEaPAc7v0rVjLeUNlMgWKi0+5I8xbFQS4fyoRPGC/CjN9i+6SMZhFlyD+XV0lqHd\n" +
            "1A+y9pVTeVsPnm24wx9UPF4ucbrHW0vvj8khDmATcnGtJEqQ0D3pxnuCI6a0jc0D\n" +
            "C1ADFLP2+6EX8DpTxl2btDiBShRVbVInhDz0yIwIAe98vgo5joBeLDVXE5puevIu\n" +
            "Y3iBBADBedq17N0p15P+c6Wfr8fK2h+BKmZexbrFVxnjs9f4N19gKKPb1GfTo724\n" +
            "4bcvfnKde1JdXQ4gQGMN6U4u5O60IlizKXltsfQxvhhQ8wUBCBro8fbr6GGLeOz9\n" +
            "WqkdXgRLoXdDvRHSADWCmErnaTdz0HarLE1TY8HOa3CcWJb88QQA18KGAsBBL8Nq\n" +
            "MBjBW0276Pv2hI7vBfzAjv/sBTu1VfBeGXw6V774KVjfwI63MBpg21XxC+LNQ0/l\n" +
            "gLT1ZeL/I/tRy1Kn9yKV7r/BWGfOvrsqBH27AHuAk8GIM/1PjxY3iPDfzabc2ew5\n" +
            "CbyrgBBQygPGwQN1Zr21g+a9lQjJOCcD/jLeuw8qPgxT7NRdm0PK+TyJXMth2/xZ\n" +
            "leG76Ea/QI91pvEiAaxPJZS4uDYlSe2YMklgLdCA/NyWA1xockFmJ7lXRuAOoUBv\n" +
            "pvbBG4YKqAoYDTVmimZixod5Qutgc0VruXkFUZdJ1FoBOGWY+t+OgO2TJAhk8wwx\n" +
            "L20hQ5F9aUZXPtrNIUJvYiBCYWJiYWdlIDxib2JAb3BlbnBncC5leGFtcGxlPsLA\n" +
            "xwQTAQoAewWCXaWc8gILCQkQRHvvaGE2IENHFAAAAAAAHgAgc2FsdEBub3RhdGlv\n" +
            "bnMuc2VxdW9pYS1wZ3Aub3JnRDad7R7dr9jE9iOyMFJUMGV0MsemxDU9caUUh7vc\n" +
            "j/UCFQgCmwECHgEWIQQ1+/wUJNwezbxPcdxEe+9oYTYgQwAAaX8IAKCen/rWA3mW\n" +
            "peTK72K5HuKQp9ES8QWu2ZhMs8DN0nLZ8iULMOoNK5kh62lzeNJExzDqpgVTx2MO\n" +
            "iQd/zAAgY6/3Eis2YonK2JRc14dZiu4ddzPGoIRokRIZGHZNmuz081kGqZoJIj9g\n" +
            "ewyeEypIf0JUYwO1sAcMlwj+OAbvGPUxSo7vyVYCIdlZiC2xg8hGL+5C6XPNZ4YX\n" +
            "Sdm9Z6MMzBk4K2SxjqnAFEBB9xvbrOCxj0GKyCgSkoltAkQenhhJ/LAFJ4lzy21G\n" +
            "9FnfpkVqH6De3kSIf/oXWN8QI8peWYoiFMAiLFvhkdcQuoiRB1qGY5qVq9YOOJ8+\n" +
            "Ki7F1REeH7TOwM0EXaWc8gEMANYwv1xsYyunXYK0X1vY/rP1NNPvhLyLIE7NpK90\n" +
            "YNBj+xS1ldGDbUdZqZeef2xJe8gMQg05DoD1DF3GipZ0Ies65beh+d5hegb7N4pz\n" +
            "h0LzrBrVNHar29b5ExdI7i4iYD5TO6Vr/qTUOiAN/byqELEzAb+L+b2DVz/RoCm4\n" +
            "PIp1DU9ewcc2WB38Ofqut3nLYA5tqJ9XvAiEQme+qAVcM3ZFcaMt4I4dXhDZZNg+\n" +
            "D9LiTWcxdUPBleu8iwDRjAgyAhPzpFp+nWoqWA81uIiULWD1Fj+IVoY3ZvgivoYO\n" +
            "iEFBJ9lbb4teg9m5UT/AaVDTWuHzbspVlbiVe+qyB77C2daWzNyx6UYBPLOo4r0t\n" +
            "0c91kbNE5lgjZ7xz6los0N1U8vq91EFSeQJoSQ62XWavYmlCLmdNT6BNfgh4icLs\n" +
            "T7Vr1QMX9jznJtTPxdXytSdHvpSpULsqJ016l0dtmONcK3z9mj5N5z0k1tg1AH97\n" +
            "0TGYOe2aUcSxIRDMXDOPyzEfjwARAQABwsK8BBgBCgJwBYJdpZzyCRBEe+9oYTYg\n" +
            "Q0cUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmdUIRfuKIW7\n" +
            "qT28vY2xnlsGmF6fJWTfx4wDijIW6xACLQKbAsE8oAQZAQoAbwWCXaWc8gkQfC+q\n" +
            "Tfk8N7JHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnRn08\n" +
            "63PC8uNyHKkFl9lppIVyVxwWD/x8mh5xV1aLB0AWIQQd3OFfCSF87i87N2B8L6pN\n" +
            "+Tw3sgAAlHAL+gIJEIVStzC2zRoQ20PS705y4q+uGJPLEXtk6FZxP87eZdzZp/1U\n" +
            "oBRrnQ5YzoIjvHs02DaDwp+AtzAb+pDi6i96Y7sW8X74rSvOlEBwjGgVRw9TsAlw\n" +
            "0Th85ujoOtn8GINAykoFOTqtb3az299LLdZr0x3nf51Fka4/3qL6MeCAqh/Uc0x4\n" +
            "dZRGXsKuCgkAQArCsFP79m1tJkqSHkOF8oQ4lpRh9REJzri+Iada8mwnnCuTtMRv\n" +
            "QpNCCxfUFke4LSOSon6hj2k11FrF8zE1RO5MA0CN1pBQQ1GeeMT98VFEwG07oCiw\n" +
            "bKjCkW1qez+EplzPIrpeJxyPMt/oKFc2BslNVECB5qqhsUpj7qkqQTv+i7kqH7ra\n" +
            "occY9+C7KdcsXjfGgSf7mNv/CS30c65PAO0a/IqrLeD8XCV1G4AQwW/pDLHj334s\n" +
            "/lQXVY3JqMjW7cHG5xuYXGpMYllMv+gsWFxMJNg2Cc3Ze/234bXCRWpgpOjitbx9\n" +
            "+/IO2VuNfsqJcBYhBDX7/BQk3B7NvE9x3ER772hhNiBDAADfCAgAkf8qY9naXmqh\n" +
            "//V0mhydfNIZBnHlh876s91QbLz7+hcFnb0epIBnemF5zgW0HULnbWYQfcn/tuVx\n" +
            "/D5fdHQR8m6Sidc82x4A0/p7sFxcCfola8e1wL5aEbBK342EDqFSpZv8nsOrLzyR\n" +
            "jb42+TVZGiTGFuOqnPKKWbeo30fC70SiBpoVceF0xXHRZdvz1dB+gJyk0NF1HpIt\n" +
            "MhRxHMDgFNyj5A5SIY5A42Y7tyJ6hHh1QEk5+69Q5u9GblI6ZblSp48uEhz762fg\n" +
            "gig5pXpGHwgJHf1+bbc6ZOvZ4XqdIGzr30wE8oP6zdIj+Xvra3ZPNVlOQCbxB/wr\n" +
            "ltx3QXLHQw==\n" +
            "=oJQ2\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";


    private static File tempDir;
    private static PrintStream originalSout;

    @BeforeAll
    public static void prepare() throws IOException {
        tempDir = TestUtils.createTempDirectory();
    }

    @Test
    @ExpectSystemExitWithStatus(SOPGPException.KeyCannotSign.EXIT_CODE)
    public void testSignatureCreationAndVerification() throws IOException {
        originalSout = System.out;
        InputStream originalIn = System.in;

        // Write alice key to disc
        File aliceKeyFile = new File(tempDir, "alice.key");
        assertTrue(aliceKeyFile.createNewFile());
        OutputStream aliceKeyOut = new FileOutputStream(aliceKeyFile);
        Streams.pipeAll(new ByteArrayInputStream(KEY_THAT_IS_A_CERT.getBytes(StandardCharsets.UTF_8)), aliceKeyOut);
        aliceKeyOut.close();

        // Write alice pub key to disc
        File aliceCertFile = new File(tempDir, "alice.pub");
        assertTrue(aliceCertFile.createNewFile());
        OutputStream aliceCertOut = new FileOutputStream(aliceCertFile);
        Streams.pipeAll(new ByteArrayInputStream(KEY_THAT_IS_A_CERT.getBytes(StandardCharsets.UTF_8)), aliceCertOut);
        aliceCertOut.close();

        // Write test data to disc
        String data = "If privacy is outlawed, only outlaws will have privacy.\n";

        File dataFile = new File(tempDir, "data");
        assertTrue(dataFile.createNewFile());
        FileOutputStream dataOut = new FileOutputStream(dataFile);
        Streams.pipeAll(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), dataOut);
        dataOut.close();

        // Sign test data
        FileInputStream dataIn = new FileInputStream(dataFile);
        System.setIn(dataIn);
        File sigFile = new File(tempDir, "sig.asc");
        assertTrue(sigFile.createNewFile());
        FileOutputStream sigOut = new FileOutputStream(sigFile);
        System.setOut(new PrintStream(sigOut));
        PGPainlessCLI.main(new String[] {"sign", "--armor", aliceKeyFile.getAbsolutePath()});

        System.setIn(originalIn);
    }

    @AfterAll
    public static void after() {
        System.setOut(originalSout);
        // CHECKSTYLE:OFF
        System.out.println(tempDir.getAbsolutePath());
        // CHECKSTYLE:ON
    }
}
