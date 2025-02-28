// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.util.CollectionUtils;

/**
 * Test for v6-style self-certifying revocations.
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-09.html#name-openpgp-v6-revocation-certi">
 *     OpenPGP v6 Revocation Certificate</a>
 */
public class SelfCertifyingRevocationTest {

    private static final String SECRET_KEY = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 8139 D35E 40CB 1A6E 0E0F  B769 7FD2 60B1 95C2 A78F\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lQVYBGSIp4gBDADhFvBqIHyyYdyhiXH0UZNDDIcKY3g3KLRFN0DZU1LNUkm1E9Cc\n" +
            "y81hyvEFDrSQGyn8bKmTQF/P3RzU4WTyQerwSmegycsOVr6c9b/s+Pz+EWaP7hHS\n" +
            "RN2Hr83GUcVRXZO4Q6wFJItkiJxgbigb7Xlkd45/synVqcLuDQNUvREITKvqLtTI\n" +
            "ZIWoRI5RYUqr4qIX3zDGd8c2/6W2z1LwFpiK5j68q40mDsK/z0lei3Up9SWho3Vk\n" +
            "qPOcWVPWQBoxOtfFTNeZntuL48KicEnwFB5HOXMbo98/j1mhk/je6HedxkkKIndw\n" +
            "1T7//eqi/+fVOBkGTzLby1ZaDVZXKEU7Sg8WhLPAD/s30PhUR8s7av3rj+ZbJcho\n" +
            "L7TeC80ndQw0OHbHnCTAZFYpeZZq93lAm544CrRlkzSQyjpyvfViHcWcB37iWZld\n" +
            "TV1Y7mwM4h7Lcc7U6ZvgDFzNWImol6G3vpSGtSdaD3ZUsBQsyJKa3kczB+r0MGJw\n" +
            "XgmCufWgj/sB+zMAEQEAAQAL+QGFZzPTeda2nKqVaSkUF5Yscp1UKl7sv2D4NkYE\n" +
            "KkALpuQYB6+uV9LbKtAvlw/w2/n4OPD96/QkdkVg8GdajWCgaBhVVzvpTZ6xE9gm\n" +
            "UJrAUoGJCKzzhEOUl4ZdEkFUn8BvEUFWkJ2ClDa5iRQ9FRiVIwWUv1YgkujGE6l+\n" +
            "XDXWQ2vr6VP50QGRI39hrQzaZDAcHFwn6oYm+IHBkK/1Dec7UXskE1adO51NX6dJ\n" +
            "kIPwV1y5KPKWFKBLISrywi4/N/ZwFbwJaMbnoWJIS8gqwZzvGTZpifj1KhzEg9+h\n" +
            "yw2/mlaiFZZ0Xw3O8rWG438Qa3z25Dp3Mofoyc9NBjG7QM7r0WYpOA+UpZD27yHV\n" +
            "xIJMwck/0frgdJLQqeQ8Aqpetn2rEafV9F0wKYictzF+8k0ZpMp+wkWoyGPLx45v\n" +
            "lO/XbcWVleAeNR2evCImQxIRLKMCVT49v3Bv051dMNGKbHgXih7Y8JMy81LQf9xa\n" +
            "IQmgatJ9Va4M542Rupwf//WCrQYA6FeyJvLSdZYzIdSxjo3vjkNrlKVoxXtWiplG\n" +
            "/Uk/iGHimIQVAmHZ4aGmsrHNnuhzZq+/8TZvvISB08u6NVotSMh4EMj/7TZF1WST\n" +
            "thO4nKIDNnqGvHyNJuSw6bInjRZzQ8pEMILNvxwdA9CW4m3GbXTWdMLVBi1RO+5w\n" +
            "PBw53PuYrP35xTR1NrsEtsG5AWizSv42s/8GzRI+N4BhVVym6Um2TV85Ow2ixyXb\n" +
            "wKwTeVvx+5gWGfrC4B1AkikDT4oNBgD4Ai+JnwEOxoNNkhCnjgB7O/mgTdpMx4Qj\n" +
            "+liw4doQKoZdoeciG6QQdt3oquKBDwLMJ/l6wPdnyxwufLzUlydmWc4uwNbybIDg\n" +
            "X8VFdcB6dg1hUp5xC4iI1xE6jMWenyX/o5TDD9C4US9pitFZc6g7jiBgz8B5qap5\n" +
            "hP7JtVeGAqyZGxuHxo7n1u2d+UaV5MYmt1aF2hN83SzDQtqVjb3UXzPSVuOgJRYu\n" +
            "oAi6rV0bS7dDVjGdTZtU4dVxj0UUij8GAM3Ulwad/nthRW0hagJmwl3NN/+JpY0x\n" +
            "iUg3mJ/5b0UAVzhyjljm9jGwWAkBrAFnl/vkavVUw7GGwuFVzWQugJDFLAgFda9/\n" +
            "l6aVTGqWWApzz02Swkzz/u5C/DQgIO54lW4UnfYfyPxbk0fS/uJq5kNeisz9SFgO\n" +
            "DGhyTtL499QywwX5Xy847fDVdkV0gQ6FPbEZWpE7PdGjKmu7vszx7QYfGZ1YYLmM\n" +
            "gym1RMcTS5ZxCU/GebbMyRPPAFeaU4n4fOJHtBxBbGljZSA8YWxpY2VAcGdwYWlu\n" +
            "bGVzcy5vcmc+iQHTBBMBCgBHBQJkiKeICRB/0mCxlcKnjxYhBIE5015AyxpuDg+3\n" +
            "aX/SYLGVwqePAp4BApsBBRYCAwEABAsJCAcFFQoJCAsFiQlmAX4CmQEAAGU7C/9e\n" +
            "uw53qZdEmFETyjITdUNBESyUMKo+t5rycua3iFIRwyrb+I3zSrjwefRzLGopovxO\n" +
            "9eyZnuSnSCK3UgcGhfsLB02y3w9FfEV9H4USmH/ensGODN9OJ9LZjgMfYWQgFmeV\n" +
            "AZq93Nh2IwzLyfW8JjnpnwZis2XMTU+oW82choWUnKCkEPg+JRlkEux0hpQyPuy7\n" +
            "cW9rrzp+Sk/Z/9B9a7lBAREfD3gAcDke6JhCTKMstYZHpRLE4Q7w91Cu4dR/7ozZ\n" +
            "uPgYALTNvP94C+SfmRXK770/P387QxAVjz3pZSVjzsmeGXZwpHqDYhEftLQcYLw4\n" +
            "9LIWw2LKw2j+s0grZFcePrnw78ap7aQd9+btVWxrf+y6F+b5jsseTNVt5twLwFgA\n" +
            "bunas8OeHl4/42iJBMBHui7ET6UZ68CCmpuaGbpSJPF2E4qy6p/ALWaoSFYWGpjM\n" +
            "P6Wcif6M38LoOWQc3mOFBHZslIh379waHX7g+Cahn73owf6A+YCxbAn80BznsrSd\n" +
            "BVgEZIinigEMAM8twCelWoNEs61GDrxydtp8cOeskMJ22tDopJreNNUsgTEJnO7Q\n" +
            "04Xuqc2wmVPRgUAf9F4h5q2doufGHKrYd9M+XcJZ2QMVpg76nP4KT3Aq1WK/obFd\n" +
            "rjg3BgF93ZPZYD5mmR3c0OZLs6wwzArshCdBj2Y700rhD8wS7iRwRI+RqPu1OM3Q\n" +
            "dMQ0yH7C3/4L1REfyXsHpf/kE7+xMiagBoMakV7fWJ3GyZsGLlgwoTpzhw3hefle\n" +
            "0UsxBRd3Zz9Lyop+VLlD4/mPx0P03mF2/1xl7llA7NaCGADlNf5RkRnF9xHd6QcG\n" +
            "xCmg2VAHCJ0KBSrZXbdaa0fsySP9Eft8Fz3u44LZTjGrWJOZlj5hiNANbMHwaShc\n" +
            "bousamNYGXneic0E3jKriQG07P54UUN3WWss4nc87YhTscvpOj/tkdQv1ViasWfS\n" +
            "ceSJPbidQ/pDE2F/LEHL+BKNkO0ffcvoOvnHb3T7dGGF5RkV7poJNWPAQZS8VE01\n" +
            "14QlamnAo1UxmQARAQABAAv+KCh61OR7CzNDraxE+neofJi+7NU4+Qy/RNu3XlKA\n" +
            "hKqb/ySZH/xn58/XZ6iZy9Kx/jtDa4SgOVpzI4B1+ZK8hTyTQXMXer7VQZWH3UEj\n" +
            "3T7cPkgdYCsjtD9MIXlje/9YZbgO6WguMNmPIesSffKS+iX91Qf3II5H+NtZgEQn\n" +
            "sfl+uw2JTXGg1JBTpaiB8PUbr3ZNIFUe8t8jidZfvXdq07pQX8akn26TEQLNdGg2\n" +
            "tEUE8maYdUMRCAVgMoiBQZZfuo3EFVMV5ev69hMXDQPKFtOfH28f+fL2gqTEMmDL\n" +
            "Z+92CSq65fi44LclVR2ihRp3TjAVG/lXZeAwNnN4n1jGEEb8eA3KNDDiUSVXoR2r\n" +
            "QgNcfQTa9XGSvxgASgWG+tqxQJTPbigN++9w7RY6yzYcPs7GG7ZFRITtsMTY5gp/\n" +
            "ZMpQSGyi7Cp582xIzJivPegkTdITGCJNIwIjT5Zd+QLtiAHoOf0VhYDI4MFQDcCh\n" +
            "v24IQDYVXfLbV+pJAhlEGbFlBgDfHOUvO70AvyUyGmW88YVfyBXvxkzVZOtmCxCF\n" +
            "8X3FNNjG8Uz4p5Sor0dFfIsVzgo+N81fimqB8dgmIE2b9eD52/KcdFEv4SKlSL5v\n" +
            "NtpDUfq0hqPIZQFtFJFaKy+1N0Nlsvs6WFtSAONY8Afn8CmGNgInBTSnAjbp3v4b\n" +
            "prS73fSoKk65cVSpiOWV7l54rZXQns8b5ltncCOse0c73sDX/Hzzddnnj9Sa48Br\n" +
            "c+BoWGLaOi+BqF6D0rSROeBiej0GAO23lYjZeuGKnwkkOzTI9ux+2iOTX7Y/0mqC\n" +
            "3q/zVoIt5iFvcn4x02I1+0qe+PJEw21BbR2ZNiCWoFltADWE0sH8FVRcSZIzHQmD\n" +
            "X9vBg7J66vGM+kDqikBZLSqSUIhEv4dV6rWM7VmqGGXFtpbfoafpmkJVzMjo7O+k\n" +
            "XI8YppEsluGuzirlxkpT1f6ClbYSsVAUPiEgwjYDq7M0Lhx3J72TlYpTxYUf25J4\n" +
            "b2x+GKjtPVBIpceIY22BevppfHs2jQX/TmSZ3PMbUBd6cax6hv8TtJwje0KhgdIu\n" +
            "6LKek2qRx6Xkd8vDwkamqq+ww/SRsmOA2e5fi6OOa+89HgJKn2a1E8jji/DkDyJ6\n" +
            "SWvnY8GAMoCfqzNu1pl6rlJmnSbTMJ1oKTBySJxq5xcX8iJfwSBE5FAvYS5OW9K3\n" +
            "b0vQoc364NVojrLV4uZgPRAA+aaTWbqQqTbgnxCEX25oxJIdxbEeDKOkmRLomn+Y\n" +
            "b+1owl+e8kRAl3DjKiYVI0ROE5r3F6yg5jOJA1IEGAEKAbwFAmSIp4oCngECmw4F\n" +
            "FgIDAQAECwkIBwUVCgkIC8DdIAQZAQoABgUCZIinigAKCRBF2Kvk0Q8YjP+SDADN\n" +
            "x82Dc9qy2fjydKzOEWEKlQdG6e5sIVi6sCCDJCA5bejd0dcgi7yFHYn2KqfDVdVJ\n" +
            "uWMItgVEmP5zdJLSwjuZCZBffQY5TFpE7++Oe6PY3aOtsC87mMPgxcpJRfsnrTyH\n" +
            "xvqBQGr/MgZLBMndl5fas/N6sZw/CLOjOS2UKZV2uqn1dLZ2BUM8T8FwAfns7SQT\n" +
            "aeGR8neQdEB64BIZaUaWza+yXq25ZJWEUi9bwmSks3B94WteDZRBu9ZKpeEYHlTt\n" +
            "7NQWVJ94WBbXWul8dG1o580vz0qcHbO9WlZj9KdPj7TAwFYj/08AjoSkLliXgr07\n" +
            "WP0frjwFE060zaPp9K/V1G017WTfWpU+cLX7qjAIQ2+Indah3Ffvfd+PP4H7BoKZ\n" +
            "IrbouSlckUDBQVZcuNtw3pY9W6FzZNCVSc66eRtNtpDqj4eNnWM9XLoHmwamKfwW\n" +
            "CyCRELuOsSH4w2PxtogDigZwGdft9Gd85/6ygf7OB2pTGTzKpI5avEJ97K5zDb4A\n" +
            "CgkQf9JgsZXCp48vPAv/dU4YyeXYMAHx95PQjdi+Mo78iVsk7yKdkk27YDCNAKMm\n" +
            "5dntuFLTCxw6gpgWp7zJdKkGgXZTbI/2PUCEfHHeUJwC6bauUWDG0GGdPud5PD7P\n" +
            "K2UWhR7BD9UtaDKyDVFfOHV7mGimaeRkkHVNrUCk6Kcd4/f8hhXLoEROkZS7PS7x\n" +
            "Qn4EGrUPSJbIiq/Ug4mG15mWuv3aw7NDk3CIXIJuLlSA9dHcO4UyxBPR61ZYj0pR\n" +
            "0MF6x5REJw+KSoExLK6oXd+lDRbqhbi3A2+NjuafVcv2gpPz1Jf4Y3MRXgZiOrz5\n" +
            "r6y+BKwOye5ycJoOc9I89yfMwCmP+VgwaYBbavnExyK0GVloigDkkE52Bk2z9h+b\n" +
            "rJfQtJ8Yel6uhHkudUVEHkhh2WZR14eMS1STMoNW1oZL8nSbOwGrGUjW7s1hpask\n" +
            "2LLiCDB0UFjn8HLQt7xSfP4t/cbemenHX16CVGQnyKvWbAhHkeYe91MaWduqPT5m\n" +
            "sI1nYaqkdT6UC4PRnl3P\n" +
            "=isPD\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static final String SELF_CERTIFYING_REVOCATION = "" +
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 8139 D35E 40CB 1A6E 0E0F  B769 7FD2 60B1 95C2 A78F\n" +
            "\n" +
            "mQGNBGSIp4gBDADhFvBqIHyyYdyhiXH0UZNDDIcKY3g3KLRFN0DZU1LNUkm1E9Cc\n" +
            "y81hyvEFDrSQGyn8bKmTQF/P3RzU4WTyQerwSmegycsOVr6c9b/s+Pz+EWaP7hHS\n" +
            "RN2Hr83GUcVRXZO4Q6wFJItkiJxgbigb7Xlkd45/synVqcLuDQNUvREITKvqLtTI\n" +
            "ZIWoRI5RYUqr4qIX3zDGd8c2/6W2z1LwFpiK5j68q40mDsK/z0lei3Up9SWho3Vk\n" +
            "qPOcWVPWQBoxOtfFTNeZntuL48KicEnwFB5HOXMbo98/j1mhk/je6HedxkkKIndw\n" +
            "1T7//eqi/+fVOBkGTzLby1ZaDVZXKEU7Sg8WhLPAD/s30PhUR8s7av3rj+ZbJcho\n" +
            "L7TeC80ndQw0OHbHnCTAZFYpeZZq93lAm544CrRlkzSQyjpyvfViHcWcB37iWZld\n" +
            "TV1Y7mwM4h7Lcc7U6ZvgDFzNWImol6G3vpSGtSdaD3ZUsBQsyJKa3kczB+r0MGJw\n" +
            "XgmCufWgj/sB+zMAEQEAAYkBtgQgAQoAKgUCZIinigkQf9JgsZXCp48WIQSBOdNe\n" +
            "QMsabg4Pt2l/0mCxlcKnjwKHAAAA35EL/3Qubi7A9rkFxcz+YF2AoLOqRJA4p5VA\n" +
            "oxUGQSIyOvRKBgoZJugvM330DP2shJmJWSgsZqt/obXkZNbPCdjQ0hXR+Ih1/tdh\n" +
            "Mf4lCD9vPx9V88xFo37BYZCnaEk93NTDGrJ6sjvo9GQkm9x2Rlrzek//jmQ2wqvV\n" +
            "GviYDBADhWzuJzyibdo1Re/4ESRlGpzN0bFf0j1/uSvEBq41Yq3UXXZqg/NX01id\n" +
            "t4P0dxGYfQTXwzTxyYxn7rbdFJUAc5uxoGyDZzzVgoXwgNu8aE92faztALajagxF\n" +
            "P3NpfT+TlZ51hsNZcIz8tnQFUyYLNeAycYI4iCC/Vd5RPhK8t9Py9Sow2Tk4Pdf4\n" +
            "5l8MSIBsrtHiL/ElwFlnMP5Ffwuqfhnb/29yK0tWVpbRkE199tvU3C8iggyhdZYC\n" +
            "/8NvYSU/RysdDwgDH1j1WWxuFTnaRCpzP/jPZ9sA6NFQtbOYjN6FLO+78gDZbuDv\n" +
            "Il9nFzjaEHbjZ7QVqINZxSCQe8NYmjfeDQ==\n" +
            "=zlRL\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    @Test
    public void parseSelfCertifyingRevocation() throws IOException {
        PGPPublicKeyRing revocation = PGPainless.readKeyRing().publicKeyRing(SELF_CERTIFYING_REVOCATION);
        assertNotNull(revocation);
        assertEquals(1, CollectionUtils.iteratorToList(revocation.getPublicKeys()).size());
    }

    @Test
    public void selfCertifyingRevocationIsRevoked() throws IOException {
        PGPPublicKeyRing revocation = PGPainless.readKeyRing().publicKeyRing(SELF_CERTIFYING_REVOCATION);
        assertNotNull(revocation);
        KeyRingInfo info = PGPainless.inspectKeyRing(revocation);
        assertTrue(info.getRevocationState().isHardRevocation());
    }

    @Test
    public void mergeCertificatesResultsInRevokedKey() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(SECRET_KEY);
        assertNotNull(secretKeys);
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);
        KeyRingInfo info = PGPainless.inspectKeyRing(publicKeys);
        assertTrue(info.getRevocationState().isNotRevoked());

        PGPPublicKeyRing revocation = PGPainless.readKeyRing().publicKeyRing(SELF_CERTIFYING_REVOCATION);
        assertNotNull(revocation);

        PGPPublicKeyRing merged = PGPainless.mergeCertificate(publicKeys, revocation);
        info = PGPainless.inspectKeyRing(merged);
        assertTrue(info.getRevocationState().isHardRevocation());
    }
}
