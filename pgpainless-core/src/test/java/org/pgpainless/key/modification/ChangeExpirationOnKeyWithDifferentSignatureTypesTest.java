// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import java.io.IOException;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.JUtils;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.DateUtil;
import org.pgpainless.util.ImplementationFactoryTestInvocationContextProvider;

public class ChangeExpirationOnKeyWithDifferentSignatureTypesTest {

    private static final String keyWithGenericCertification = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 8204 4993 BF17 BC95 F1BF  4E80 9E47 B575 6733 80C1\n" +
            "Comment: Test Key\n" +
            "\n" +
            "lQcYBGE7mxUBEACzbhVnKC34xXZ3WctNZgWZp3/r0X+O61Vul6TnTfi3mOaAeAgd\n" +
            "5V9X9n/wwQ/T547RGQf9VHsgUlXgfn4IHROWf4cgqDu1jHOfio/IFynq0tVDAOjj\n" +
            "94Pv4f5Ek1TforiCnsN3bjB98YrTC8tRbV/XsAi3j3niL6r4xOMWmHH6xFJ6YV/e\n" +
            "zzUSqCNTLxw1rqlJaKNIzMTEdHQJFQlo7XIf4NSpX6p2l+Xewga+WCn2GKW1zg2F\n" +
            "7bA1/Iv/UGhnGcXPU3bEz6s2fUlPAKS6kCzLCe6ZpFSOm0U70kuLbpZubdsgY4zO\n" +
            "K96H5yC+eVupo1RPgzK6txSMf6IIMJYJqwgdFYjSoGegokQz6Kwxxt8hHUPZSitJ\n" +
            "DXoVWDtUVA7Bmp0e9Dh0SzSZwFpdivcuQtKFAVh1gYDcknXhAIpll81faRExx7zz\n" +
            "mvNlW/yRbTvOnBeoM8IlE7guS4M5bYUXYtsZP4BaYILv8v/Vn8EkJrGYLGiZYO+b\n" +
            "OakWZiLhoFEC+yZ64NDHDbneoas13trJbhal2bCCtFk5Aj8WV2nUuTKLhIpsMxlM\n" +
            "2VYnDL8ucfsVvrxLm67gGgl7A0AXvqL8r5yHVdfB3Sz70fgVpsdraknJxHD4KiWC\n" +
            "0zqg5QgySuPgc2JIuTkconK1Piz61gNsUIh2i2snMBwnz23RvBaJyJ71XQARAQAB\n" +
            "AA/7BG6A83335LURKqbPxqbxFyJz87cbl2695XAJZU0ftNPUnZ0EAPkGqdLaG3Ap\n" +
            "RpU+3xs8f0f0N+V7XtgWSiJYYYHfgdxQh+Ni17CXFzIQmaQrcEQ4Jv6YsPa7+Pr1\n" +
            "QFtx2IgN+90qMBzPI6H0RkaVShZ8S0xX46ZEasXcy1S95putYyhp3cRFuKLpJxzQ\n" +
            "GDiq0GKtOxcTpREwlyjV2qmYBVbgPxlbHyK7+AyCw3YZ/eIN9beTze2uSdG7A3X7\n" +
            "niWcz8oX8jR5iMGqFdwbisq/eyRQ/ap5YYGkQXNS5QFjkHFWKtlKmQJXCgmYssZR\n" +
            "5UFgy7X0gs1oIdrlKElK62I2CQyKFlflejj1KhMrzit704FFWtTHfPVQKbloojbW\n" +
            "Kf1BVhlAYtRT7hW1d0njOPsgdOczykcYPFerJm4SqiVC3nJ+/nTIgCX3UaEaaS4J\n" +
            "6SzJldGlGFAcUCTXnQHdVmlHuPyes4CBo4tL1NjBC/F18DIr20c4Pw614Z9R2YrN\n" +
            "Y+KSwE0Wm8xObVFCUnf4S0leKvr5JErYqyIkZS767ulbUR5GE2Q9qovAQ4hlOqjY\n" +
            "Jib8Yy8eOows/re8NvC5xgokPy59FuNM5+tsXJgbRGKc7iAzGtZDWz3t+yOcJ3RO\n" +
            "VGL+9YI09SF0W8PENbZakyhFBZFeKr1hSi5wdp97Gv9B/gEIAL9evLSYV3yzwW/z\n" +
            "Xs8Du8HYTfuCgxADg95hecRruETvJh+E/d+zf5SfmYcZJdkcEaP7pDS/rOvpm2GB\n" +
            "gqcu460uWWj5PDa9tTWC5+BBzs004xsdumQf3GnEnfzHJEudD4qQ0icaeutWH1kq\n" +
            "+ZKXv3a9gbXY+7fYD+LhdOC4Lwf6L/OFpwMkH4Rg8OLfMISD7OMENoV0rbggn42d\n" +
            "CXRRXV7jHYB9Ku+12GIxyWo/k2bZZU5v+dI4Jjehvtrpyu4Mw+bYbjJECaC6jMpp\n" +
            "gAM8MoQbgWJSbD6hcX94JMcCIVoBRGXDlu7cyXvs1yJRR7Fvs9DGaaqVlBgG7n0z\n" +
            "jSTHBI0IAPAHC+hA0nY2+qR/QSgKyp0TmAs8HBxIwAqPDa0ZaqOZMp9g/5XgCQqx\n" +
            "ilaN3n/Wf6Y3DE9PMVpKx79WCBC443p/lY8CMsira1bCQ2q/gDmSpcxEXuWwvaqI\n" +
            "wL348081PpTuq1rBpgP3Sm1MdhinSpBV4Z642Jua/UFV9DyaTP8ylgXtW3fjF08c\n" +
            "+Y0MX7a7yacnkEwNWewk5Zhv6+iWI8YLa26KnGqobwlTIdsBQYf8SG+a/6B07tQC\n" +
            "7qvwo24drsHT4VAOZNry4fxxB/6seOryS4vM8htdIM5Ef1BbhYgw26drFVistplY\n" +
            "XetSKutnjCgg7XYglXI9LXtYQx6gSBEIAI9TQb2HAbkbU0ocG4kMbe2vgpJjWIll\n" +
            "vInuwDuarSZqJ7b101z6qR3CVy1/xPyOeZ/Er3QEzFjxAJmPKrTbbB2ADyba2q9Y\n" +
            "LEm/hurZfWzlHgOws42IMl9O13hYLqz4KElXabcRc3tlAtjQMTcS+ikMJn7GYnWR\n" +
            "xHtzhYRNLcqvoN/LJ7fq5kvbkGP4TSV7uF5fFuSK2leA9tTV7KvEkpCDLGAbUoXB\n" +
            "2+NYbz58sWcp++0AU0MCiEzPNm7Z230FpN+FjpbsHDThu+SloF6vXdSP7tA0yKdy\n" +
            "heXjiAId+//zrlyHScc9sgZ0Leec4+yaOU0aL0sPf/iZHipyeX85DUx+ybQIVGVz\n" +
            "dCBLZXmJAjYEEAEKACAFAmE7mxUCGwcFFgIDAQAECwkIBwUVCgkICwIeAQIZAQAK\n" +
            "CRCeR7V1ZzOAwRlBD/42VkD/yUBIPNfZGSdNykdSapqaUz9Ym8Z4B7HYsWxvG59k\n" +
            "dErsP1MOiWPX+z0yG/b2lKtFiAvMsPkf4qhvP3AFicfz4Vkn85+kC167cUg+hUsE\n" +
            "lVi2sAm6gERkflTSVm4B9s5eElMSuZRAd51FBBRnp4QZnxcP5LFLqg7JJqViJKag\n" +
            "vnoQDozlyCYV/o1S3tifm96xCC97HgACMMa5DpXj+w2efoJyPkPVJEDAC6HrajOY\n" +
            "iX3eZoBsP3uDesWVInDOR8dRZFvz/7DZKdapjtJY2z1hv/r2HIbbHYnfrtoy1YFw\n" +
            "uNJS3teIOZBBcz698M5oeFDwKdChsEZjYAHUgeWqDYmllecR3eJY/uL6lUv6p/Aj\n" +
            "aPTNq4K77ozSbEtPhD6LHP0KsnHnRWzFRCAk9ym55Pb89iOiSjwmvRjxDObluood\n" +
            "qwV2qNqenxYYOqVVzQl547y31i71f7hToEsfmkP+Wb0WJbuaJAHnL5nDKaZ0ekEA\n" +
            "S1pVc6SnlL1D/f22C/deUnlDTwfY9Hy6IG72CKoQcsGWBNAbPbpPKp9o9tF2HSQR\n" +
            "6iCmt4GJ5eJaJoTN8cJKZfq37Aj+3fF2sRgbtUppUUgovp3ffF97UoWwDzC/Lat/\n" +
            "lwBTgW8Q9pk2JKbNWLPlO1CtJG54ppUcYgrGSK2UPQ+7KyO5HhMJ3vODLooLBg==\n" +
            "=gbUk\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static final String keyWithCasualCertification = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 2077 4DD5 1456 73A1 ACB8  416E 4999 42A2 27CD 977C\n" +
            "Comment: Test Key\n" +
            "\n" +
            "lQcYBGE7mxgBEADb3ivOtMZ8P58H+/eU9H7BbSdKztwn6LzhS/BMmv4IJZG1tzZP\n" +
            "fsVwlVHMhEbst0A8kEfo5UmYy2ENldyqoKABH7fZrhcTdYm82046jAIsTKel/Bjv\n" +
            "hA+La10Lz/SSIXGkHR+JfLvdnZo8mfMIp/0Tr/FCn3s/2QriOhYfDjWhLh8WMHwe\n" +
            "g8/O9ipTTf0T7cRKqs2ThkA0i81FkP7C9Id/+fYby1hXqimmZvyQAF5b2a2NE74b\n" +
            "OZ1PDPJ/97CLBTUeo2rKUh+hSusGR7wXos9ZaP11/AykAGcIejCcPLMlVKF8JveI\n" +
            "E17BUkp04szKxe1IhtHica7xnqBlP253bccd91rVtVlObZ8qeRhmVruKVFhGCik4\n" +
            "18wUET9xP/Xmf7a+YJfIeNLk+HfKbYnWB1orOul0dAqpRPK85dHa8skrtCRgD0pk\n" +
            "HmfbMk8+8cAOAtlmUQql2u72M7GMDX0CUXKbmvfBi6fWjtvtT63zhJHu3+379M1y\n" +
            "3pnnPinyLhqnY7WYlk8S/oZTh0XOCHpgMrESjqh0ILXIguF61UR16fP9k9R/VvO9\n" +
            "k204+j58j702UbK+H8Xm5P+aleyxnNzt95y4SUqnY9IcX666SjwnoC9ipaq/vn3s\n" +
            "40yIMrflUf6nd0N+OgtrjClnCbXF6QX50Ddpq73BwGbVUa7uFDp1K1k8JQARAQAB\n" +
            "AA//UEIqdZsRtTs4Hx8AAlS5jHv+0tTuEndns0oYHq6ZOnoUVWPapGwfQHiRUnma\n" +
            "tkAyZ6k3RrGkCu16sQ3abkKSBbcBUqm07LqEG/dl+AMxq+ATdoiuxYfMcNUxMuWn\n" +
            "XkxtAj5LS9HHdh9YtPRxfeBshmo8RFiZEfZ1fZ08g/uY4gxG9r+eHzl4exDq5Fvc\n" +
            "nRC3DZaJ0mc4OrYpqVJDXQEMEVA6YWz6A44vA/omCZ7I0viD3LKvO5rtbHTKdKIC\n" +
            "xMyS1mtKyS3vM954KmO3Kl2ZGQc1NoNaTeeDtNl9sxqJPoBFLl+/DeIcPa9/VGmR\n" +
            "3hcgBdCI/wMGnFaOMEdWWKwu+XkQhFAT5Myh1AdDzEJAVVIf4Ic/Cjqcg6fOOVND\n" +
            "Er8uLEAHMK8+BAd+nY68jngmQ+4mjmErmKZYyDD0mUt2vRaG3QnHA73jj0tYkGJq\n" +
            "KLjtdPK0845EOgBUfc4pZu1b7XJja/gqKgnuIXuuyaJq8rY68A8zYc1y66Z8pFVY\n" +
            "CQ/KR/tqk5wig3VeiepKNP0zal+KVd47Ff3WgQqXVGiHG3YN3zGZQOmWdiC6hyjC\n" +
            "R/LKVmdB0RMVK/T9Vg62fzugQJI6hIq+AaUUpqKxIbQ5utZxTwgFHNeRriRQKC5+\n" +
            "5kaI/W8i5ZRCj3UBiOh+7CenrhZNBNWVlJ/AUGjDlRmbjQUIAOZmOwj0rdzIIpKw\n" +
            "fWIVJlLBhG9keNHRts5ynORGBMpoziQsPdL3e9J+27XEMmfiKOi1bi2W4tZXWpnW\n" +
            "SkEPSzR377wkxU9VLmPpR4TugqsbnV+cfCMMR1T6ghm9YNRqOfAtybFFatxwqdWN\n" +
            "kv81pn09X6BWz7vDlC25lCBI947BhE4nTFPxOlENzAEQf8NknKBcgRbemDXBgHPx\n" +
            "gAvwzF5l3TTo6zqbW7KB54PCTNl19sarruh8sJodMp5mr4G3a80vggipM0DCgxUq\n" +
            "yRAU4ksCiHkQ/OznQ0ktEAR8kcP2krapY2kBcOb+ywwfJKryXiQB1d+tG6laYc9S\n" +
            "7nVkn1cIAPRMXqflfW3EHXjky7WVJ+pKa0c9vb9t1f80BJJX7hjmRfLpA43IdNQP\n" +
            "Xza0wDKe/fCgVZgMMP5DZQSGDguKCZ6sxnCIBWv6fSJhmnc5i7zdJqDqxfYU/w6r\n" +
            "7ga4HiWbbQ9xpiUIf34nTA+uRNXTZOmXJl8QOokezSBLcK9AGyosKmSzHQxCgzTZ\n" +
            "XYDAOxQccyjmAd0s0454egKNUtxF/OwCUK7BcH+rzdCz0b1jJJIOTVxq2OCBFW2P\n" +
            "G49N/4QUfPHIsnpj4TN8o63923NQLUqHdH+w4SUfCqf2oTmHTHEqWyfHYk1heL71\n" +
            "y7QJUKEB0vnDRYN+cz3Nb3YTWSeSXuMIAIVwWOowjCIMDAn0Jcx5Rk/QuF62GF9u\n" +
            "NaW3UnRkx8Ziu+w6LBe9BKV5t5fflW6cYMc0LVHIgoRmqeYnTL5hWgxTKP5C2xUO\n" +
            "GmjgRSjZG0tXvNfBKFqd7vBthTaQ0aPDc7k5fQz3T0jqD2hqS166/1fNAYRjoW9R\n" +
            "kXDQpu7DDrxK0lEQp5auPj4D59PHCA2SCDn8lXJzXc1qU6WjiZIbrYJgjLVrlMxQ\n" +
            "FVonR8qhaubbQCvngku6rT3g6q2DR1qAdGQNtRnQtTF+8loybPL06+jcKry9cdQa\n" +
            "Z7qmaPsOhkX4yCKT4H0dJJ/kq271t+1VfFtbNmClVETWTyO+S73VSg1ow7QIVGVz\n" +
            "dCBLZXmJAjYEEgEKACAFAmE7mxgCGwcFFgIDAQAECwkIBwUVCgkICwIeAQIZAQAK\n" +
            "CRBJmUKiJ82XfBGOD/9XjZGRFmdszR7dpO+cMwNAuCHY69HoOt5xovZpeRJmacTR\n" +
            "fTbM4XwT+HM9HoHmqu5Ac5eorkpu1xwSdJwPd3NhxDWRb6EEjpivNLyfGM+TXFp/\n" +
            "ldLgVYecX5iieAsh9JfPBZ0nM2ZgQDKCEmLq7Pep/qDhBe5QOals5Yf6IyVN2lSe\n" +
            "NAsk5EVCFS7OX21egOGruY+sq8TEVfaJRipe1v9l/oyMLqr8zp4lU/10wIP6uo7X\n" +
            "6B7CpYo1q/b4gdkQCZVFaKWP30+RE1R74ka0KB6j3D9Hg8IF7EnGWXc32jyExgX0\n" +
            "f5ve4NH9ojJNXWEfAuvdXA04iNyRTCMmrFb9hfxU1S3s+WcW2OoWBKdZp9rpZEAX\n" +
            "yERaBJpVWdrZg6lgHGtRBvMnavnf57W1U1EC+jfbp5de6EGjyGDqdi6lZfhRSkv8\n" +
            "lHKW6/iEXqkkn92KQvZWSQMg7u39Ew567qlUA6aHl55DgyQMOoRZTYDPJXpzo4O3\n" +
            "Oj0jFWWTAy/N23VWDLkfrzsTK9hvEwjOznHu7zNUxBgEhzs+AV3NJrKHMjCwWR1u\n" +
            "R0iI6tyZvNdn3dcyPo6i8V8AOa5aj1OEGhbza2Aaud1LrMyDzUXoZkamns/4Nhjf\n" +
            "Bbwi+J0UaPsB2rJlPMsdoG1WVtX7dfjNbRfwhO3cfMBngmrp7K7mW327E52ihg==\n" +
            "=GIQn\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @TestTemplate
    @ExtendWith(ImplementationFactoryTestInvocationContextProvider.class)
    public void setExpirationDate_keyHasSigClass10()
            throws PGPException, IOException {
        PGPSecretKeyRing keys = PGPainless.readKeyRing().secretKeyRing(keyWithGenericCertification);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        executeTestForKeys(keys, protector);
    }

    @TestTemplate
    @ExtendWith(ImplementationFactoryTestInvocationContextProvider.class)
    public void setExpirationDate_keyHasSigClass12()
            throws PGPException, IOException {
        PGPSecretKeyRing keys = PGPainless.readKeyRing().secretKeyRing(keyWithCasualCertification);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        executeTestForKeys(keys, protector);
    }

    private void executeTestForKeys(PGPSecretKeyRing keys, SecretKeyRingProtector protector)
            throws PGPException {
        Date expirationDate = new Date(new Date().getTime() + 1000 * 60 * 60 * 24 * 14);
        // round date for test stability
        expirationDate = DateUtil.parseUTCDate(DateUtil.formatUTCDate(expirationDate));

        PGPSecretKeyRing modded = PGPainless.modifyKeyRing(keys)
                .setExpirationDate(expirationDate, protector)
                .done();

        JUtils.assertDateEquals(expirationDate, PGPainless.inspectKeyRing(modded).getPrimaryKeyExpirationDate());
    }
}
