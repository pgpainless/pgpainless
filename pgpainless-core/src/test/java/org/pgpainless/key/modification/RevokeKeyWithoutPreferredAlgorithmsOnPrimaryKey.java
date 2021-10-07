// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.JUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.util.DateUtil;

public class RevokeKeyWithoutPreferredAlgorithmsOnPrimaryKey {

    /**
     * This key has a primary key which does not carry a signature with preferred algorithms.
     * We therefore have to guess a suitable algorithm to create a new signature with the new expiration date.
     */
    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: FlowCrypt Email Encryption 8.0.1\n" +
            "Comment: Seamlessly send and receive encrypted email\n" +
            "\n" +
            "xcLYBGAIUhoBCADEnk3EACyTc/GVkwMI5MHls6oIlJT42qB2Wh6PF7FXpnS7\n" +
            "0hBqZLSC0N+UxCROf/EUxYq7wUpwVp63Pd4hVyn1ppf1XOJztluGiXDPkVR6\n" +
            "fQMMYXeIXnnJMcIBZLYYKUe+wMGMIz8oYzbU8dJHE8TCbsRukHtk5aFMTu1I\n" +
            "+MCgq2jU/WVUYMJHILMF/e0hKix1lZBDyhg2g47xhdRvJgmHX81CKjOC4Jt/\n" +
            "vz26jW276+koIqUK318EPBgYObsjEr7UcAKbOuUDbExZKdcgBCPswwcLaM7+\n" +
            "kLBpvREYugyXlj2WT7laQB2iHc3aBpeYbPJ3Fn2UyXSICQaOAaM+b0+3ABEB\n" +
            "AAEAB/44AlRqyhXopzWhgzBxHyEw+v4r1Y+eWEEvlbpwzrIBIvTL8Com9KsL\n" +
            "PM8EBN/G0OFvJlq/427+E17BGkmlu7vDM4LELYKArejiqVJOfrrO7b+pjjZL\n" +
            "zYXpz1fRp8vLlC7Q4v3/mqbKLYEYJg7dmn8JWB5y1IuiEVvibfVgPSQ6YDnu\n" +
            "ZAbqxjxjrDa5d8pwFAuh+zkDrU5CY9Eoyuzi+Y2+K4XTchC/BZbEm+oClUiu\n" +
            "KHxgyrby8BobLvhxr/duH6eUpDX8Czcw71ceWlBn+2fkh4JgnozKL/qED+I6\n" +
            "URRE+GAEbaMT3f14HxyJvDcfZjwKEHhvSOPuzGCBI9dPtcepBADallzOOiQ+\n" +
            "2+dy02Do766rr42KlRVa+WG2MTOqsCeA0wh/Hx8e7ufRVOfKczBZzDO9P2C6\n" +
            "mEXIr87GxNsSD4MhzP9k9JNAIQXMb/bYGzB2o+sGPM1GeDpQsjaM2Cv1VrHt\n" +
            "9XgP3uAUkllxpPgRP5Wjto7UXDu788V6Jf5yYgJ2dQQA5kVY14NeWo5/cKKH\n" +
            "PfrYTMnw/7SECHTYaIhtZpAM040snjf/YYSfdIeVhoY+0wdbjKlLX8p4K0kZ\n" +
            "cWdweLJ9EHic1I150D3Ql9RyNuS99Ti52bl2uSAukgOY6jdSgG2giy9Hl0BC\n" +
            "Yls4J1/z+q0SjbrVDEUqKi2pgtBqTZ9ZH/sEAOFllvNtcEi47+hVd1ue8GfD\n" +
            "uMHK7wj0dP6yQcS7DjooNLojlAQkrDWiIhR4ccvnr89e3k90HIfBP4dIJmfe\n" +
            "Ey2GG9fCDts1QHdKErceQjorx68DvoYIKCMZwCeBJdXLdi8FVwBlNpyEgKsl\n" +
            "FaynAXcbc+YJGHz0peLvIUiN7UyUP9vNFnRlc3Qta2V5QGZsb3djcnlwdC5j\n" +
            "b23CwGIEEwEKAAwFAmAIUhoFiQAAC7cACgkQ9FHRAKrO1DL30Af+P9R+651n\n" +
            "TTh40QUij44jnbZy/sBPWDGCCepLB+dAk+v7itd/vDT+CApnpewL7gFR7JoA\n" +
            "cW+kV/8I8U2bAJwwakae36eTd+CGFPP4QHAHl/i6UBuC25Xr1UPUV6OQej+P\n" +
            "1HGXPQN34oP5LyNQE3jAwkYKcBQan5LZ+7UzRCy0VHoHzY1bL24CYJpEmUrC\n" +
            "un31P4McG921WfeFLfzqMyoDty/j1bt8BmGp/BFBSnvZJzHofRdRC3AfWncx\n" +
            "lUQc9mth/DqQhipbu4FuRLQLNM0l1XcPjCcOaSdOylHQUMWhXhSdGM3/r74L\n" +
            "kfYX60rotxuHuenXnt1QQxsbg+eIQ/DSpc0ZdGVzdC1zZWNvbmRAZmxvd2Ny\n" +
            "eXB0LmNvbcLAYgQTAQoADAUCYAhSGgWJAAALtwAKCRD0UdEAqs7UMjxkB/4p\n" +
            "cqeul3RrjpxkDwCsFdT9fwwE65PfzlImPDKI8T4DUeKOBthc/v6F+zAqpmgi\n" +
            "nqSFZRD48dzFQHXA5NU+P9fVf0JQP/P5tiGZv9xsGVpteAH+t/7OYNboafbB\n" +
            "h1HDx+A+M44J9O6xDdI+qiRKjgo4SmWBMxKS64Bde35lkesulujefWKpOw5j\n" +
            "2Xg3vrt8mE+TDJpWJQ1fgt16mqgIkeqAQW5A6lMxr7KEesXmPou98ZLBEJjX\n" +
            "uzS0Yodjk5BnanooOk6FytXh1XTHuXW4vzc2gveKODF2YjMi+KxGi6yk1tIy\n" +
            "UjgkaoCVDnjvU2eChr3Ij3TinBhyDHHSRW1kMULjx8LYBGAIUhoBCADN0iMq\n" +
            "+ZYNVW4vRJSvYEs9bFBS1tcyZfBtkbQ08kMexpoxLwW1l1cyil+cSewU0WpL\n" +
            "XSFOcJYaNfKiA0u4lMh5e2+H7eNvX3qpmoifmWO2lhmBopo3I5F02Kb+MS17\n" +
            "95LtN7GHZQ9F1BGzG13FIUTCZiQwmJBKay4qTd7/GIr7U6x7JUkAqbcPvbmP\n" +
            "hM5ePLP1sTPyGtY7wgixCKKeifFHvQ79zMcErgiWuuS1LyMwv7awLPjVQtkO\n" +
            "rBOKb3zoMtFJrXfnXYajXpNgYsQ+ZcDvjdi8h83RahbQmSUinCR7VVi57kvK\n" +
            "mIaZSSnlOuqCaPjvXQRdUYAdgyIMNz4eA53lABEBAAEAB/4orHyZL0oVN/sG\n" +
            "mcu1TbcIvCkyebT8x3LoQElHxlF32UEa86Mx8+a+POSwntYp9gmGu7CLjwnG\n" +
            "w77/f928rCBjC37qspsFxS1ZK4oQ2i//ovGG8hJ+T4fc+ryjkqXdr/sH6H/r\n" +
            "lQ/b2ZEm30NcY9rx/Nvtg5TONBijMRDewiOjD1cERLLBke6ohKv4teKxUEdE\n" +
            "WYQnY2fEdaYxC4NzVgjKY2/F0MJrunJwZanI1lIuJF9avXTJTSt2qBWtmoSx\n" +
            "my0cyWGzSq+qw9Aa4uG4CDFLb3ZibmeB2lZVUzam+GRbBGAezeKpqt2w7OlM\n" +
            "aIfNqIRpP9vjGhDXlbe+CBk3hfY5BADcjj7GxHlEc+1QqOi/TSVPcqVzlyUK\n" +
            "QZ5o4yC2WslQoQgBs0lG1m01QbJ7dQIY3iZ32PF/vK8I1/zqPykCFdRiL+dN\n" +
            "Fq2a89BmqVbenZbuyOmQX8b2pYa+yOH+dT3FSV88fFa8gOJhnvB+qZJlc0yA\n" +
            "OOe0868HeKTosuOaO09KKQQA7uWyPaj5myzfmHTMHOtJ5O6PT86gj5QYut2c\n" +
            "fAJV81c1BEC5RUbmTojS5lo4l+zXCRBe9UxYt2KtrBW1l0SkJVfNIBLaRWMF\n" +
            "KAWBMFye0lEBiMxMp5arXdkgAew/7hfrYmIXM70Y9Gat4KaDmMmB3LDmBoyl\n" +
            "mbSQ/XdvI+fH5V0EAO1EtvBWUx56Ax0oyVMuNZxUanwdMedjfPyKkwLq9I2+\n" +
            "/O0bx1V30EfmRvhy+EJTx+uCEgY9Pv81f28z676XOUdLoEyKAzAb9PWWgiCr\n" +
            "VbmAsFdu5qE87d88c0p6/dmx/DKPTpFkkEZl2We7OVSQOaECrXHYqudsE5ZI\n" +
            "LdetYlBhTQ3CwHkEGAEKACMCGwwFFgIDAQAECwkIBwUVCgkICwIeAQUCYAhS\n" +
            "GgWJAAALtwAKCRD0UdEAqs7UMnmFB/9WD8+esxTjjVh/P+Rzhc0VQGt1o5TH\n" +
            "bBVw8O2gA+mC78nqz26LfhGudVVZHWq7u3lIFuO/O6Ctp5BEqXFWRT+ikNHg\n" +
            "zXAjQc0DxACt63xqaVXduvA4FDlmJnbrOnkH5MJUo4pcAfSTELDQWLuMIQsD\n" +
            "ogYChjA3PG4bLEP0kz2NJuF5bHz/MNpexTaLoxNfA08MjkJCEhOArKQZj3kW\n" +
            "OgbD1QvNflR5YA7I2pEkCCOLqjkWAOgowfb+ipUb55eZ2/4hM1S1kbrRXN80\n" +
            "6GN3Hs+/BxvHo+JufAuSelNoln3zuX+GzAQaeZgkcN+RXcFiFOBEMNUmlGRl\n" +
            "zqyz7qFrSCvY\n" +
            "=3Zyp\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testChangingExpirationTimeWithKeyWithoutPrefAlgos(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        Date expirationDate = DateUtil.parseUTCDate(DateUtil.formatUTCDate(new Date()));
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        List<OpenPgpV4Fingerprint> fingerprintList = new ArrayList<>();
        for (PGPSecretKey secretKey : secretKeys) {
            fingerprintList.add(new OpenPgpV4Fingerprint(secretKey));
        }
        SecretKeyRingProtector protector = new UnprotectedKeysProtector();

        SecretKeyRingEditorInterface modify = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(expirationDate, protector);
        for (int i = 1; i < fingerprintList.size(); i++) {
            modify.setExpirationDate(fingerprintList.get(i), expirationDate, protector);
        }
        secretKeys = modify.done();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);

        JUtils.assertDateEquals(expirationDate, info.getPrimaryKeyExpirationDate());
        for (OpenPgpV4Fingerprint fingerprint : fingerprintList) {
            JUtils.assertDateEquals(expirationDate, info.getSubkeyExpirationDate(fingerprint));
        }
    }
}
