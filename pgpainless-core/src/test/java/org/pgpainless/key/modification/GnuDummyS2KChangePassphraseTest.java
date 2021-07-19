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
package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.util.Passphrase;

public class GnuDummyS2KChangePassphraseTest {

    private static final Passphrase passphrase = Passphrase.fromPassword("password12345678");
    private static final String KEY_WITH_GNU_DUMMY_S2K_PRIMARY_KEY = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "lQIVBGDrOkgBEADHJ44MXyjlmjwZ0UVIjnkwKN1s/tKx17yiq0ogvTzOxCj+HtUO\n" +
            "MudBivkjYQxib9Y6ILcsKMBzmygYLAJJlRX0eeunVKhs5FchgaCkxEKjyxOXn3Ie\n" +
            "QnWrKTIPCcc0UDJ/QIP60ABmrdKa0yI2gYojFIgtowkTS03+9xtfiYcmEjRdnN26\n" +
            "h0pvpNhIn1dQqMxy+zMZcaU/z8LbibpCsRG6vA4azFL0AZV3XRkcWUMjWqRtyp94\n" +
            "biKPPUgIU+AK9sDDJMi9t9uIrbRSssi/kxZsuHKwtOj9KeYQBWHLX+LAXWvLh1Uc\n" +
            "U5GmYm4c+d6uor1V2JorvjGgPDVUNGFmDTYcelfljP1ooZ2zr0utNWCbQkdkqJXk\n" +
            "VfmhASss1hPrD87wWqf5O4xVjWJmM5HVB5FxgTja4ha6D4nAF5shbWzuoyDBOlcb\n" +
            "VOzQD9evqTmBDnvwPkIXXwYY5mLfeYcGWBoZ7CRqUXeHB1mYONN+WPOsE0/xMAdV\n" +
            "fzpk9mpZht98xaP7xpA9AGMGEFIGhgTM9iO0TB/vyVb+RrROMetJ79H2k3cfZ8NM\n" +
            "ZEUIRzDhcaKihByul0MDwJVUtFUS6t0npFza0C//R/YOZb9DBfdWxsD+3coYKhZi\n" +
            "xgKMf/m1tihSCe6KbNNcevTSFikxo1CsIdq/dGGcC6mgBGjD9gK7i3HpsQARAQAB\n" +
            "/wBlAEdOVQG0HWFhYWJiYmNjYyA8YWFhYmJiY2NjQGRlZi5jb20+iQJUBBMBCgA+\n" +
            "FiEE/Ls8XzsRmIMDHTCZJp+pDpjnPgYFAmDrOkgCGwMFCQHhM4AFCwkIBwMFFQoJ\n" +
            "CAsFFgIDAQACHgECF4AACgkQJp+pDpjnPgbKgBAAm6yk8Wlb9g/oaJyQEpzNRVep\n" +
            "7W50ZrRV6n+Wetd+kM2HU+RWRJKTWBMVfktqwzDk8R/NKvNg3PT6OaGPjfRQa60q\n" +
            "LXCttf7zd3Cd4D3Edkx86haxQ/PdtNYtRLpgF7/vFVj/nW2vKz4den7OHT8u4Tqe\n" +
            "MFXRidhm7mlP1QTexO57fqClecaBkdhh5iZrziDL5NhkVg2MZwS/nIPrHRBb1MRh\n" +
            "EVfSJcAzYMx2ciYxzMcjsvt2y+eGjkb6N3Z+qajU+AImwqVrV8a3hos1nQ2DFM8g\n" +
            "MSovoFSxAJootn13UzY/a71IcXVASu1E+GsPsdqX71kQYrcmYYyz0OwKblPbHT80\n" +
            "24Q+WxLviunE6Hu4mXlQJeSWQof6R4sMo+dzy/ktzRVPUYRLPf7g0uHcQZdRA0YC\n" +
            "Qvpcu9Tcah+NlHTfNOBdeqXeAgx0H7lZcDVgsIlxykCH+ArELaEK41F3uHVoNhzj\n" +
            "G28YO+dc5TwAaPz8irdLSlOngKcIKi/wQV1pKaQuPS9Ee1Ue8QsYhCFkJrxzKVVh\n" +
            "1Klh/DbVwHSYX12wMiDKE9YrBwZq/NvhgUT4m85TacVolWfoCdCJ7ARz4g7C+871\n" +
            "NmF58pLF1+5lN/uV53JWEOobJ/M01YLBv4mA9sANdlFh/H9I3VnEnBSgkIZyQVIQ\n" +
            "PystbQ45mom3peo7Sr6dB0YEYOs6SAEQANjvlOohz9My737nalq1fYK9Medqu95h\n" +
            "SsIUDneQe0BDUtephz+UPsc4qMCHTVAr1XjzwcxHTjvI8Gqrbv3LKlwFESfG8vIE\n" +
            "L0UOhke+LbJYE4q7NsgnMqkHqDibBNEZjVuZZ1h5rl8iFpftLar9PWs0izrAfoi5\n" +
            "3MPKdx1ZBjXTVGacZLnh9apx4TqTt1iYnxCFKYXygVPy1NpeiKHiwplar7vdWit7\n" +
            "yoZPfXFYGzdWIqb7ho+dXjGm8NWbQda7E4CbJ5Gi0Zziv1EboRZrzxPMarLj5j5q\n" +
            "m8Rg65ctZSUEyANi/cttsZ6M1KzMHspA7rhnyraGQuQuQ54gx9EYhiddLEv017i0\n" +
            "KwxXoZ4QBjBKlgVjjCQAVpLnuZ+Q3DuU+oWPShHABY/CGEjL0Ghh4woWFX6q+EvJ\n" +
            "E0wQXSUQoqrcbWwj84igEroPlzc1T0oGhwH4IOUGQrHuRib1u0aAq2NcrI0RUzLp\n" +
            "9J0PFBnS/+0EBr3Jig07bdMcWptSzkBRgMh58HZ3/L+DGS6ZVknGIxJy3KYye6iM\n" +
            "KCJNVGCEGFFdXqJtEQNKHTo1wj2RmQ5Iltv7Fr3Bf0ufM08Ka0y6H2A0a7QUuyBH\n" +
            "68JtA8GVfidZEI4CIALhtwktJ74vAec9lAPEKuYGlq6JJpr4hGNDOnsXGC0/I/1S\n" +
            "AIuKsWzMak4lABEBAAH+BwMCjACmqRCZxCb3zkH9SLkE2BifRS89cjH7WhvNZEQV\n" +
            "/M75KuXXWHY7CCtloCpc5vwtGYIAAwyD1IOrA1ps5euBfEN8i0XKA1vJgIhxihbS\n" +
            "QSdgaQKAXK0S1qTngzSRFFKlstrhpql59O1/08IunP5mkekscCMrH/rqd7t/Js7+\n" +
            "Zv3JFk4tIfyPZefESYqkwBXYwYpjmI0/vbV/lNrhACQKm+6MysjbSevMa8jvc1dA\n" +
            "/oJ/JycxeA4XarbH8r2+z757B8V/GKj39Qw5bleE4CnWv1+NVsEp+64Rhjjbi0Dw\n" +
            "/KFt1iBo8xrOmHy3xpl0Gtu4u45iRLtaYRG4Am/esxx0Ub5TPlg1BUz8Xl0YCh7Z\n" +
            "gvIpa7ScPjBwLHndWXfbhLge+glzjdX21UJdMsIy0SGWqCygpvLuMlizwUFs9BoP\n" +
            "1YGhaDvIwFK7W1HZhDyilaCwmBciQ8Uy3dDsvpqBZH67Iih1zTmINPfHZiFjQNX6\n" +
            "sRFwQV8Uhse2mm95lp4ocvpQ/fn9pTzqRZn7RsU3ifrXTIwGzYTKBW6VPQu755se\n" +
            "6nb2CouQtwOVP6hWEGTrOzgFBKAsw0Ix2zA/i4m4dA7uta0F0iJ4qh/hWCkG9/Ku\n" +
            "u2CztyDuYOtybIQMxv/3HRGk0b8/dYNWYwi5UbI/bAIgucFKO4riMZ/A1gEAFS8Q\n" +
            "7U22PGWN41inPOrs31upPBaxuNOuKva9PccGgCVROZPirm8cgH1lEfwY5xxCxtrM\n" +
            "LsWi4D5UM77oLOPa52/NWGFWlCdUVT9x0bD9xEXIIYtr4MG9vO52ii+NNSlr+m/7\n" +
            "6PIZqjXlVsW2B8dbhBHKgE41xS5lmxvSt8V0l/4rHfiCF2OO6WVRmUel1rtgbhNd\n" +
            "MGizi9NjwZeq8aur4ASghn5cdpZ5C8XFt4nxdK75Ez7Kr1Gl23mx1cV6i7x75hRy\n" +
            "jSWPOS54K1KeT9gBfRu1jfPlIC5rQ+8+zM4xYA1e678luk/uOUZ0vcwutEaO/H02\n" +
            "fLAbnq7kBH789SLm/kIuRlKEAJ6vMsIJ1pAlsDTGomOwHz80+wTClUTEMDjuTdlp\n" +
            "xHujngUc/gSvFi2KxR2JKZ8qDY5BsJ8bdZt4+pBrpyaivGo7zGtaMfCmzh3GgLb7\n" +
            "bDqDTinubg3NMEJNCehQ37EZ4ZIngdM8ByOnFTPZPqoLFIjQ098z5gw5KzP9tIf/\n" +
            "wqTUla6eo8wBgktKM7QV9PM771vjFNai7eqc+4VQxbFlneCRnVrQCYzlgbfnyY3l\n" +
            "6BV0phB4onEWkfhIrov2Fj1/jeeXFRM1FaIN8oPUZV4fN7e1OGYmUA4Dw54/EjYI\n" +
            "+ZW7WyT9sLE0zRZzBGETedNSbTOz//UkEozNLHGeMFulvXF1srzfPFGSOjUhwBU7\n" +
            "exMa9K+/Dgg3J/v76s/tRJd3wnoRa7b+h3Wg1p33WhYkmZXh0cC7wJXcjyrlHmok\n" +
            "UPs+pSNOavYgqpA/lyHWAGQWuDlFyaHFeHP/80RW4vD7PNfbGWX8nMXCP8vK5Axk\n" +
            "IwRVUK61xeGRn8wan3Obvtp+utOtZZLabKBtLYFuuecyoFek3Lb6mHGJTM7l6gR2\n" +
            "gfOQVS6wSeqRUjgWMv3In4oNuNywdoIsR7PLiGw5NZDhz1x4FW3YQChiYomPdG42\n" +
            "tMD//L4RPAtj4IYGNjCzcqledH+L7hPB4Xd/aIwlhT2Thb29K+l31omn0ZTAGgYE\n" +
            "iFjmW7D/b5IuLlpTthk1uIyHthqo/DOtifGiNZTwYgaEotK6u0mVe1FkLbxILSea\n" +
            "VfqL/YEFZIkCPAQYAQoAJhYhBPy7PF87EZiDAx0wmSafqQ6Y5z4GBQJg6zpIAhsM\n" +
            "BQkB4TOAAAoJECafqQ6Y5z4GApgP/1dJEkVCdZ1j5tZ9PhRxjslH7sT/W6hiMuQG\n" +
            "lQuCQ2CUd22UbWj7dpBQSOuJ+CFPjBmEMHinr4/cu7IVAb9m0ZQQOib9lPtf7FBJ\n" +
            "v+74DieNmdA5jeFw062m4n9bwqnhxXKyo/BeB0tMMw6gSjeix5RfNgcwpavyFxQR\n" +
            "2eWAawcg2zXgZO/towSLBMtii8A197bS3R0Rr7XWRZ/tQfXcRaKrwG8BIILpWxcK\n" +
            "pnNYnIAIx+qroSBUzBbFBVMcGjghWxGMDuuYD5+HDqOzFaf6VUniKP0vIwylBmBc\n" +
            "qKFtcw/UsgPTy9uCndEAhl+9kFB8IeVjIlj0KjqwFdZlvQh3SKBFL7eRp2auJBWM\n" +
            "+UY3QTkCJepQR2eYDZQNRHJx4EdjtE+eF57AwpRyUTks3xhGcSg2MMrZg48X7o/2\n" +
            "0Uqo2nPaR9uuzjMMU8yXJeji7SNA6hYQOOgOCT8toK/LlyIZhE8Lz/xM977s3UrF\n" +
            "jVHx6LsxUojLp8ucCaptjF9W9FE0kbojgStZtTx64ROGAh82YM9ssTwNlVm0P36H\n" +
            "cf9zHNLaJZ97OtrnN6IzF3MUB1hMlocadzSQVR7s/FnF8XHY3QnW1P7prPLkIwOZ\n" +
            "V58PC9avyjVCtW0juLCUXtqEY/OcLFcWUn5C+OS7HMC24+wED2Z6woLYPy5FlZWC\n" +
            "+tUA7+g1nQdGBGDrPIABEAC7hvsaILYdzaYjs1uEuBH/YaZJO5S/6OU+y0wJURFi\n" +
            "LysNX64lpmRpd5v8GAAn/lCSexfIcWxkpK6O8L4gkBI300bpgNPF/BoCHRhw3jdO\n" +
            "Rl1juWEV3pFkVHFoXC4eG8cuVYC1xfHknjyyBurwSq/VKb7VM28rKNXXfC8rXehR\n" +
            "i+lAJAN2HbqGhCYmjRuxH2UWZHKLbQElhnf+JGeaWTApr3UzO+wp4mv2+9ovqixe\n" +
            "Z1SteBe6jWTPLVlJyqo3KnUckGgXSe9iAn6W7oOpEqvji7ci2+JsPyQRJOfbfJ2o\n" +
            "8qUkpBTjxRW5nBDg0R119TjOZOqN+6/cl7utdznClOyCBCJHHueL+94EoTYIrNPl\n" +
            "dHbAZbiJ2e4XryDctRBVyDFnRP8XAu86cWC7DaFI4QP4vtB0v3TeoOU3Q/vtC0hR\n" +
            "8g2yruWlrNx94x59JJP/KEeHD7cs/ltQlnKQEqmXNF3yO3XN92qFzNHiWFtVeB0K\n" +
            "efGRcpmJAo8/or9fTQWv/m0Z40SlV5rDeDxVlrkK6g+6/l1LH2d6yjsF4JHuA9VY\n" +
            "Tx4hxmYy6Jmt7xnmp6wcYYOKWsN3woI3zssUKtqp+l+L7iwOTykuzqX9GpzO6MIH\n" +
            "ZGlpSQbPTRcwa5RRuma0edgjwDSm77zj8L1N/qj9xBDhkTJ4ONl/RW+GTQDSNtc8\n" +
            "ZwARAQAB/gcDAnHKEpiEuGrK98T9MKXkBGjVL2z1U21DuqhSp1UbPbA1c4QSfbuY\n" +
            "5UjHU2h1DiSQt1Cd1Jq8Aqu1KKVlUVHm0qp0sUFi+7o3+nIMdulLntqtXRslnx2s\n" +
            "l0Xd7WgxQZnWKgupGJvxyB/Hni5wThy8viYCH/+l9XvRFN3Wa8CHKEyCxiEGodSI\n" +
            "J5oKCN5Kf4apTrApQA7g3RUv9UmiAjORRYNILikgr/xHyWNcud97OxQyiN4kQ8yZ\n" +
            "TOvnKy5V31e78pJseTxWaz4Dl+hlPbLk95WUTo+MNtXl2Kie+mVVQ+UwgNxFdpby\n" +
            "RHZMmbmQd7lNBDxoXXzunWSbZxThqlrCXvAb6itaUom4Y38zicDhlDqjAy/zp8WK\n" +
            "rsGNM3Ppf0otxjxoHDwFA3H+QTU+qXvOJWMFF2uL4SLlM4Ydo+UpHvsnna7ZlhuJ\n" +
            "S6cYZwPQmgVTnH/0yhKMY3UfJnv9/7zTcJHLm9eoxWQ5sbAHxCSgMJ2weXDktnud\n" +
            "hCUCag9cCjdWzcdkqoRTHwXck+6HChWfsWmiJ2eXLD/DParK75PiQ4j6Jvw6l9mZ\n" +
            "md2VG9aiaR6G8bJNK7TboweGAaHZVconYQqW2g6IyZwSzFvMcIoJWGFga0NdtoOX\n" +
            "ztUZ7UjSNkfoWmdYK21cQ/B1hZP7l++jT7Ti4el28tFomIQDyxdkWeaUzHt8ITTm\n" +
            "1RxHEbY5IWaer9jsiaKUKU/zZD/UUXItDMQz45CE2DNMkM0xrAdrdcyv9DWkxCr+\n" +
            "nFBPJScnmfo7I93QgunN87EyASPLFxLldAjUw8I2M5YXgClx6zqA0tfg4LmrWV1h\n" +
            "WB7LjsEHQ0nIqf/amhZexcSDSkhH2JdjMxh7dygICbK3T2O3zZiLU1CH6Sd65Bnj\n" +
            "A2dbeZusrG33eTEK7faBJNgvSS5LemixP4y/ViG1B9cWjANse8CawitOKTcrAA6M\n" +
            "12P2vxw9/Op6yCTvT3vw0FniqIGOz/ggMbvLnHjYHmy96qYlZxqgp1oIEasn7ugG\n" +
            "Q+aNXpLerygKd7S1YtPNsKBDyoZfk+WX0i7CFXftTNQOhWr4a0cQT0Ce61ldm4ql\n" +
            "4jJRwbnC/RRXUhHg+xbkGaQBVbdK+teQYCZzYAJWAzUEXWutwiJ97zczrCjqWiVG\n" +
            "Y8M0Q0kqEeTJE8jNkJq08c6IdHuCza8IxUZtBOMfx8F2WsynUAHQ/0SUeFxGAE7Z\n" +
            "7AqfoLNLJW+KxQcDh2+KDSo5W7mYf7z7NR0NgFtNw2JlUbMD/k8uKCalhF51fUnQ\n" +
            "gbicCSOQ+oQEKLwkF1xsIZvOMxJZbny38/Ic0NQCzqmyOvfcY/swXtlUd7mZsBER\n" +
            "lsbo+agUftIMz8s3t2rs28nyhvtUSPEqhrhc807qtxINoWYK25SQ6HZ/aiS/6bzZ\n" +
            "oKWxPiPIpnV41OMmL6Xkcy7OtbMVlbLR+5uFFM/VPBRq0650h1Nt+F7vaVjO1S+6\n" +
            "x2SZUlDEbp9EoBr7ocHwlI/O/rg3XDODq2dSEwaN4e19YOFzNXCuafGB5RW/v6yc\n" +
            "7HtWQxgKGqX3T53bw1k0DkNBau1bSBzHJbPOo1U977oCsrusIEnYFhEZ7u5mquRH\n" +
            "hkrRsQ4syJ5T95RcSvPGUNflrAVDNFeOKGhNbET+m5kuvqDIOqtCyvHyfQLLILl5\n" +
            "lymYsV5iVNRm50DMtXOJYXnyBOUtbxBkFkpA5I/1mC8t0uBMljO51AhihUQLSBT2\n" +
            "Ca/Z84HROv/9mLGq8USHAFMPpcJV38FlR46Xu/Vq9phlaZGfNooVXvyNOkh0ViuJ\n" +
            "BNIEGAEKACYWIQT8uzxfOxGYgwMdMJkmn6kOmOc+BgUCYOs8gAIbAgUJAeEzgAKg\n" +
            "CRAmn6kOmOc+BsHUIAQZAQoAfRYhBCvd/XZOx7Gw7Iky5xYIcXVNmv7yBQJg6zyA\n" +
            "XxSAAAAAAC4AKGlzc3Vlci1mcHJAbm90YXRpb25zLm9wZW5wZ3AuZmlmdGhob3Jz\n" +
            "ZW1hbi5uZXQyQkRERkQ3NjRFQzdCMUIwRUM4OTMyRTcxNjA4NzE3NTREOUFGRUYy\n" +
            "AAoJEBYIcXVNmv7yZYYP/0PKwYIplNWp7ZjIu6RabRQ9Z+tpJTDF2Bu+MP4hTkpR\n" +
            "r2nNbiTMYjyyEsQAFQ8gFLjRsiapxFgx586PelZBRoZaAgR9jQXCq9QfDP9doWH7\n" +
            "U2vOc0OJyJ1wQtUT2WPn7BLFRoYwjjks5zCkbS5GfyU7O7dUgpUaO36b5wjDEeRB\n" +
            "arBrJaaQSCVeOJnffUEm8IkkoLVYu355pv2mY6MFL/3ogfDBrg49gVDVKoRfMvhz\n" +
            "h3ZHn1YbHC4UgN2caJPXuke7AS16KxPNXSKgwf8F5OnSC1zHzcRy7X/msyYpEXA4\n" +
            "3M5FfB/NM7fFRE/3fyboqIfaAMcDx+TfkSgX9bR1BExU1AEAFGpnJBH/9NVR7+eW\n" +
            "mdPcZ42ZnohduR1TcYOzDC0SRPiHf9asJUGJIZTPGCTrzgm6Wb3vMt7tpCgLMwE7\n" +
            "OsvM0mWDNb8/lZeevIDDpZNZWNagFG2DanJz3j+7MH5bMFU29jhIgZ8HmjWMrJ8e\n" +
            "RYbffDG0E+yaxG3LljN6Y1fDYeYQZumHRCZy+f9c5iDdNAq6Shx9+WlW0JiB89fI\n" +
            "Zs8m5lmRhVPHVS7gMbZv4ETfl4ZN1CfindgzI66JC/SMzfOM0u0qsIz1mMqMR4Gy\n" +
            "yYWLETEHc3o0GjC07SNl0KgfscmgFVLaWGtYx40000fWy6vY4fYUM4gDUrmWV3Pm\n" +
            "5B8P+gOyscNDbvLcgpLa4hyLzj6gg/gIb5x6kfNouWaACYHf/IhmLv0cR3TV1Txd\n" +
            "roYIrHUxUnxLvnYOVzlrKLZw+hMKytv0n8SKogXLJ+cFEwqTNiFmAGRbHtkdDuj+\n" +
            "Iu4qsUWcWNr4O1HKrh0bTch3q/enqdm1n3cbPmLCbMsPi803vXiCAesbQEHQoPNa\n" +
            "fRkEKqdTU1rfp2vqnkoqvdIQqDFy60ZuhwCMoCNfn1nIOUriS7hYTVA/4z1+UgaK\n" +
            "Rt1WYlrN/aPPZYLiCtbSHh7sLuaycfLrp0yng0bgIMfTHYyQhjO2rERXA35vmYs/\n" +
            "CV7n1q3uurcCxFpcR7pDvGtzMCdiT4MdD8V1+trWW6gv2DyEsbA+FydBX+e/Mcgw\n" +
            "tENffBaz8rldrQqyYGl0GMZxCyfpR0LL8SInIIMkabx3k/JvckUDbVJLVjQHvdB2\n" +
            "oKPanBCLqtICl9n6hktzRXi4mkuhByvXnX1Fv39esIhIK1xQSE2A5Oo0V8Wu2bgU\n" +
            "iSWdQKh+MTWHWw52xoWco604Y/29WGBqJXrVWWBwxBzDpIl+rRGXVNLo3ddN9l4E\n" +
            "K50lVr09I+KUxeLbC/nhKKpv35CogJ9+el+SW5o2mYC1X3XjbIcaa4LBxQj5KsK8\n" +
            "gfj3nXc67K1Qqf5pMDE6LW5mRKGW4cOktlsFB+vAH0A3Ik7B\n" +
            "=TGkX\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @Test
    public void testChangePassphraseToNoPassphraseIgnoresGnuDummyS2KKeys() throws PGPException, IOException {
        PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(KEY_WITH_GNU_DUMMY_S2K_PRIMARY_KEY);

        assertFalse(PGPainless.inspectKeyRing(secretKey).isFullyDecrypted());

        secretKey = PGPainless.modifyKeyRing(secretKey)
                .changePassphraseFromOldPassphrase(passphrase)
                .withSecureDefaultSettings()
                .toNoPassphrase()
                .done();

        assertTrue(PGPainless.inspectKeyRing(secretKey).isFullyDecrypted());
    }

}
