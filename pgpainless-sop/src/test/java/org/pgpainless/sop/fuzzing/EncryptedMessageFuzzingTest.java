package org.pgpainless.sop.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.Test;
import org.pgpainless.sop.SOPImpl;
import sop.SOP;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class EncryptedMessageFuzzingTest {

    private final SOP sop = new SOPImpl();
    private final String password = "sw0rdf1sh";
    private final byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

    private final String draftKochEddsaForOpenPGP00Key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: 015A 5712 B4A1 B9E0 7504  4359 DCCF 0A79 79D7 FCEC\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xVgEaG4qsRYJKwYBBAHaRw8BAQdA6Zj+CYg+8An51lmhdS74yBVJCb9F89fN6QB4\n" +
            "bPI5JdoAAP40iGbC9y9PDYNgWz+4aOA7n4z/uQrq0PG5+4ymzDMboBJUzRxBbGlj\n" +
            "ZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+wp8EExYKAFEFgmhuKrEJENzPCnl51/zs\n" +
            "FqEEAVpXErShueB1BENZ3M8KeXnX/OwCmwEFFQoJCAsFFgIDAQAECwkIBwknCQEJ\n" +
            "AgkDCAECngkFiQlmAYACmQEAAOdbAQCxZmiNa25K/rwr1+bbsH04BeloaD0n8yvr\n" +
            "2L9E0AwQoAEA8w/L223ea71Ed/6GC+lFRnbxfO8vJbvy3F+vo90CPQ7HWARobiqx\n" +
            "FgkrBgEEAdpHDwEBB0BFiPqvr2l/XW7CEL2yGgfJW20Skbl6TT5qx/m7NNHaAgAA\n" +
            "/1Pn/E/7F8lymfTznRcEpbjta0h4ixVvpuMfyxqVCBuIEVrCwBgEGBYKAIoFgmhu\n" +
            "KrEJECYeAW88jxbsFqEEPT26IQxqpOidag2lJh4BbzyPFuwCmwJfIAQZFgoABgWC\n" +
            "aG4qsQAKCRAmHgFvPI8W7JpmAQDcbCGDrF2laIk9TAuOFSXE6eMPPymHyyNXQHx/\n" +
            "zRvRzgEAmrmbuDEBEDjavY7D3BpvBjeNd705IraIrz+P1FQHPwcAALLlAP9y8YqE\n" +
            "ejUZym5U7O38WBT1PpU7rbT+Zk1tZAGEa2Se7QD/btbhZc4KPjpsrExNRsPPhv7E\n" +
            "mXIQvy+oGnqIW3TXCwDHXQRobiqxEgorBgEEAZdVAQUBAQdAbEIG4ce4EEY8UOQP\n" +
            "OIN9tQMYgehkArtx1OImoTTslxgDAQgHAAD/WWzY2QXSnQ2pIGDU2Pc8OVvQ5tnS\n" +
            "ASZPsTDsBTUnOdAQoMJ4BBgWCgAqBYJobiqxCRBOSsimV0t1yxahBHM8Ont4ioLt\n" +
            "hxtXtk5KyKZXS3XLApsMAAD/0QD+Ndq3yXurDIZxFNemx5HJ3Omz+tBaJZf5DsJY\n" +
            "ymshOtgA/AqZacPh+K15PtPB6wd3I3nDou7ZFnaL4vczXu9QRBcO\n" +
            "=F7NV\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private final String rfc4880_rsa4096Key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: 0006 CDA2 AD82 9CC8 750A  B7CA A992 50AB 54CF 91C7\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xcZYBGhuK28BEACvTHGGsR9HPMxObmv9aYN5zXcSgrMncZ4jUtAb9i1OJF0k4rY1\n" +
            "AdSb2gnSydKEliFBjeSIprjjcLlmVJocyLtjmVaEh6N95sEMgwN4FYsX0mYBKzhh\n" +
            "p80JY4cN7GjSMyUJduxNw9siJzWna0jcP7AUa8r7BvUTMzpJM6YZ3JcMKL2bH3Rq\n" +
            "KCSrEoI/6sM90EBmdhxCxAJW9PWm1dqQSYNogX1nhbn+j7CMyDmVwb6nSriHbJT1\n" +
            "7eVyyqj1SUZQw1hMnmjjH6RCud3/K9hkjwylpGXqzQuprCsTP215JgYJRNM4tHTY\n" +
            "ZPjRAXQRernpzCNZpNDPwwSQ6tBB2hv8mCAM7h63qv6HR4wJ3DgSxYKFBgMiZJcC\n" +
            "PBNb+Gjlrj3V7cVZzbx+Em/bt0B/TRfJ1UbmCzjEhcnTQsoDJq7hAHozncS4FzWo\n" +
            "hbTaAvgWbXVUldTQc1orbWRZvMWaqV+9iNeQ+Vcg6PaON5K1jiwEibjYpUy44yKu\n" +
            "f6x3dKKVAKfH9zksJaoWOfOiAXLNSlrxOal4ut+5lRO+omYLqOxiXflQfZmcDqTg\n" +
            "exKJM+cHVbov/bwZUHhZc7quiMt3zXEZ1N1L+zhN8+InIFhrkOLX1yczNZ6+x5s6\n" +
            "nYwiCcEFDZxXP3dVD8uW2iDDQ6L6t5GGMOewJWP8nzjtG7mYlIgCfFOS9QARAQAB\n" +
            "AA/8CjeSo1bV+50xzD132laIxPPihYfsILeoz6a/Pe34gIYyjpiPJaJEbcwEyA4e\n" +
            "0L7+U7eNMyDChHEYwTvbmqNhdqHkjsdoEkm9hTjqnhhlWb9X1igaemihFPPB1qAp\n" +
            "kNzNwxI1Hig08LXn1Oj2H24v2VTaCQ0EAjk5Y7RYsUev3xPNz0mDS7+ouXbT9B0/\n" +
            "AW6Onloydfq+JyrSWYW73i6Gs/PeJwc+irV9xQrTfmTDM7VxcWU0/mt99NWWiOtb\n" +
            "J5BnKFoQQ3Kf7IqwQ3PfAidrRYlCLnAChsJj5VSMUSQT9HzYMcUkzUr/TJFA3lbw\n" +
            "mI2fHtWyHPXhIYAqILhxaqTEM1wASKntLrGOUF7ZW8biuvlm4mIRGG4Zong/OwDi\n" +
            "a8tk8NiGrAl6YrQlzhH0hWERSj8ru2mxkHNZp8U4DFjrzsrnITk1Wr512dJ8MeZN\n" +
            "62uOkyjcis+c96yi/trEgerdto8dMaNbjdocKn9IU/Rf9qqZuqBB0cIJpocW5Wpt\n" +
            "Gr1fzHm2EIiwJx79b7tc2VDlb1ZREyCHRcPD/eUMfaWqznM4VfJ1+wLMQ93S5lAw\n" +
            "DQVLUdv7+xIhveXhcoJj/lErLFfeaFerzG4iLPb3ycUoyi8aQyN09426tkhG3FR5\n" +
            "KI6lg6yqf//xN9zW/kfzlA9nZI85sXgsltJS0jpeGRKxBbkIAMkQqp1eSM4PLAjH\n" +
            "XXs0HcZepA5GBIUpCo6ubxPLNJzef5cFW6003WZJ5IuIqNCtOHItBKk7TDSfRrTQ\n" +
            "7TMr0nasymp4jtqPICcaxRES5vA3jCNJYE7KFA2l2bq0g7f2NS81J1OPLJTFJm26\n" +
            "ueHA2SiIEaFxgyhNe2s34+qAN/rNTatxWmjBgH5AV0nZmjVZIIBhZdPwZFVPb9dB\n" +
            "8A12/aZ/FQHfJI95WtKtHCUsW/pM97oQYy53MTda2fc3JtuuFn9LAmWzP4iW5Vy7\n" +
            "j3wstiTsMyXJcsjuGRdTgk5t9oLPDAJiZN1k8O6UlqBI3EMhu9kYuB4kj1OM5vQU\n" +
            "ctc1ZF0IAN8xj4Kv1b1cooCSQpGqWPbm109Dkgzl0q+Zo+JqaH7Pv3VLT8IKrS+r\n" +
            "pQsBy3GymvO+BG2W+qu1EwJ5miGS04IlPX1iPa///dQFo1wpes0bMyjt2P/BNVdI\n" +
            "ZuPSIqb3nT8Mj9bWCMXnTetss5zdmyds0zkEQabc7XozLpf0UICu1Qsu8vUwmiwv\n" +
            "Nlz0O9/BG2hbnVGflp3dJRtg+rkqAABrStRHgOyI7z2rxtNN/oxMwaC86AEmd8OV\n" +
            "4xigV4ayr06awzKf06Rh1GgTuvaYWR28iDMLgD1rP+vENfg7mHXhHReE7jNF/yGc\n" +
            "dylwX1YtTT4V6BNdHe80R8oVIj+xf3kH/1k77Kd453Nh+pmVA/pRHFVkt2Dp+g4w\n" +
            "vf/qumlcJK69/JwiB8WJN/CFZ/syQW5YioIJ86IXEgLq3zLW0r1sxU3U1/418v/P\n" +
            "s8+Lf7AVKJyhVHJTd9CDmi2AnyjU+s99BwMOlz8cKMzHF0EJ+UVOJ2+PVopiSTh/\n" +
            "O77NGLqGiElmS3pJgpTxN4pjpZu8r7cQqqK16zxppdJpJEWrVY8nmfqnIfON65CW\n" +
            "YvrbL2xvltswHbQZG0uhrfMB/5qX6x8SBiBLHJ12uTGkKoOEHrLyzd91/AboU1BI\n" +
            "V7+duUCzefbXiZNeYzCgPvEdL/DDAtGMt0eN6GTv+gJEGhRc4zoYybeCB80cQWxp\n" +
            "Y2UgPGFsaWNlQHBncGFpbmxlc3Mub3JnPsLBnQQTAQoAUQWCaG4rcQkQqZJQq1TP\n" +
            "kccWoQQABs2irYKcyHUKt8qpklCrVM+RxwKbAQUVCgkICwUWAgMBAAQLCQgHCScJ\n" +
            "AQkCCQMIAQKeCQWJCWYBgAKZAQAAhygP/RcuaZJiw9pm0toO0EgfadWhci9L9fzK\n" +
            "MWT3/mzc4KYJv1H7fL7qAkGi9WeIiOzeuaDGEa+Y7GjtthN3tW64vwocQOaiqWt4\n" +
            "6mOY1++vMUbkAd+tqf21L9b14MaXnqMQPSVLREVXvXwXUPi5RFntTh/9c7PSR/GU\n" +
            "Ex/WGbpqy4aRGddopT5Taqn1P6XTd2oISMpyH9FI8QrfqyZmTDb7uUgCS7lzn8Bd\n" +
            "Fpwqfe3fRnlUAMkMN8WGNLrqVbnKr9OBLdmtPTAfC2xwoUYNTnma+Yqf3hi3Wmge\n" +
            "iu9W8caTCCPsgtChclZ37yAz+QmK2iN2MZZrhTQk0SE8KmncRlbUI9QLjLPJYrzi\n" +
            "1whCuoPvNavJaKQHoISEOYQfcX4KxEWj3XmicoezgsrAV7t9shTJv4DdfXxRDhlq\n" +
            "soTeHUfRD5fBP4Yur5knVfMFyNamUujIv05sHr/U7MnC7rdrB3INdTWtWURmwOsB\n" +
            "L0SLPugiRLqXr2bc4NTnHqpQKN6aZnpYSlLgLAo9Nfml81x9KM+qDWcM15J9dAYS\n" +
            "qFAx1LeYCepTOUg1ooKKNkdUq0pPQAZKsePl8VRHaomFC0fl0V59tE/udaPQDtH3\n" +
            "8D7YHWjIrMZ5VIEu40zvM33zhrAxSu+iG/Mycs8QlBhutaaXCa9Q910wcGcgosz8\n" +
            "+HTt+oqXrXTQx8ZYBGhuK3EBEACua/FAq4a9671T23AIRyoAaJe3xIqzUpR9/ISf\n" +
            "BkpFNo1Ku0aKQnsDfcT8GVi24eBsV6VVhNKIk7b2x2h97oAh3R6wdLSVRDIQxipN\n" +
            "2We9YU2VD7EWVIy1ZJlrdtuNBZz9FwLYR1twv84EKi65hetmHLUQbpMXy4PFArr8\n" +
            "ThAT923LTBKS+N4vUp4FqzUKTZOOWwYgxnwmnsbnW+MFqwkqj5Z2nlhSmTCpMbVw\n" +
            "aSrmt0jZAk9sPowDMu84Je55/rjsxoeEG+tnHxtB1CZwLv8ceXBrM/j+VhhQoZrT\n" +
            "9/0I1fRmSmuiH2lsrgPtr35/1tFT6VloEKOgtw1muTHKyXuEsyXODTVgoG1pNLhF\n" +
            "3pLY8pSipPAaIWp3NY/lOjBQ5A0P/fjYVmKC26lzoG1qrafySVpttfq5y4YLSWO/\n" +
            "JMJo8TPeI9oWVuyVMv1/VHmSc2Y1x1D92LPIkRkLwwdIIFjHKqAHT/xwstl4NEG8\n" +
            "IdktRkQ3w1CJg9FQ7v0UWJNAwA+gnfwAZ/J5DwdNDnB5r+adsm4FsK1MVbRdIXd1\n" +
            "8WDD7EWljghyytmO8lduNqupTxVrWAJmW8LT1kSJrU5A0Uu/yzR6rajBbqWDw6uy\n" +
            "F2pRO1uoga9jdyhTBLJmhC5SsCr93uznllSSfbEebNZGmJ/LOwV4EHyFBdMrlWkU\n" +
            "hnONEQARAQABAA/+Kt2T1Zch/uhh5+s4wgwNPjr2OF9I0A/GNx05UaS32YEx4bEb\n" +
            "Qazbcwz0fZlUFGP4JeA3XYhOPmsBDu6MV1CnNEtVuLuByuJO5JDzAh1hMalpae4I\n" +
            "kSqXxxeRXdgA1oxP2+JNHG6TAiddP+hHAeiv5LE+7WojY7hsKp2Eay/bIzEOjmUk\n" +
            "dnLLlfk5pT6Bg0Xz8ssbezAUgGBKlT7fkPvK/ab6rS22mpwT2a0CAH2UIc3fDRgU\n" +
            "gU9w1PNuV4/45wnrFCOpV9YNuRLrvbaf+LeQEkUlE++arJTnll9U/+2FBeghD4eQ\n" +
            "IrCSFffBNueHkO7wFG13f8wBDqUWGc3/Nu1j2Z3X37tHfpU7cHonabucXsosTbvU\n" +
            "Xr42WDQJ5zkEihDt6VMC3wMc1c9C49IyHjW3/8E6+p2IbnCuc7/m+c3YfjHM3TiI\n" +
            "BFWwo36X0Gedgcoh+w+9kv1JZNVYDUT1bf/ByLsShGtCQseSYHIycdLCUEy204Nu\n" +
            "Ruu46tsH9R5VEooyCtFWv7UwKAqZrjJgZprplIlao1MgygbwPaEwDYzMaW9dC+9J\n" +
            "pNTouyb65CqAbwLPC+OEU6IwVVQr2Jv7KbK2WYDdVgOBgDeKcd4TgwP0+6E6nHSD\n" +
            "gvUxLavfywT0bF5vjBeROmTQtgSuqTE8Lf6VVE0AN+Rk4dEFdz72peCXUF0IANEh\n" +
            "FKeycpLxlOisPDoJ3zBp94iVbglFvDqbpgYiVSanRQxkWnD2JWhWiETgnUrFx0fs\n" +
            "e4zF3wEFSnatncrfK/GWEdqfUcoCI0HK2WxZATWWTKjXXb/urgnLbEFMwdBczsN+\n" +
            "qvlfbbJ9RXoijAR0QGRWL5cCh99sD/PyMaQnmR8Mqjz4djHBulejw8Mdy9MFazPP\n" +
            "7zQE/ZpaK6/FqoTf4p3dCFNkGNx7eSWDnJBInKU89SJSE/tiFVBZoOR0GQOvs0PU\n" +
            "RErTdDA5IEuY+drCRhA+AZ3b31efqqsM0dpUSK6zlj3/LoJuE5kvOmFaNgPmrgHO\n" +
            "FQDE++/ynP3YccI03rUIANWDfkE7lPby8WTzjtuSah6firIlVE3RUVHfBxHCGA5p\n" +
            "eOXSr7e0kRsdTlrW9pxyJPI2+z2QAn9fICkK5GD94XYwJVQT5WOaQjUcJD2uNVJV\n" +
            "5dNL0WE072EXPxEnKvnaCS6FstLXbFgzy08Bw1V80FHcSkQcJ+RlqGwrlwnhx8mA\n" +
            "WoEEKLZPTm4OZZ0/1imFD9iCghSH9botBBw9M3mqJnqBDhsseC90TPdlYs3ChfRC\n" +
            "LDAxnOCjgjMa0JBuNJmlWAER/WYmpFtQHiUiQk79njNdfTJilR9+8sJcKXag+AkK\n" +
            "nWLErRi7CfZ6KP8kAYA53XIcOJf2un2s5VI9MkooEm0H/RRf6qV6M2Z5uAxmqvGg\n" +
            "As7eoH3AOc/rZE5eEza/pZOhVStZJNW9rwrVJBtFDsHeHUmSc6aT33JdIT3lKZfH\n" +
            "zQxlsPPMqghcuU2pdOB7+GN3+O0ZG0Sjri4GtktuSAWI1E0VxCKEWjQP10Zsp5jO\n" +
            "4Lm5R/+FzmH/sw0TEomRsE8+MBVxg12GUVKt3JafPjJ85e4QnePIGP/ia/Yauui4\n" +
            "fMYjXgok//jTY5UW6pD1PfKX86XiIDJjxEEsupNh3Wvf47UgCWmDBn3y3nTeTB5N\n" +
            "m7zX9QHUa++Ok3cXt0M6nT//4E3SLfPoWgv27uNO7eSVYsOIFBg6kDM0Ii7ZLFhc\n" +
            "pu9y78LDlQQYAQoCSQWCaG4rdAkQ9UBEnebWmWkWoQRVZVOr9yRN3mklV671QESd\n" +
            "5taZaQKbAsFdIAQZAQoABgWCaG4rdAAKCRD1QESd5taZae/iD/42gUiY2zidM7Em\n" +
            "dcmmeCkIkrKqJgzoAmtCOwVcljh55EQMBU2FrdMgfu+RTj7xLy2ZmxdMoZReVJKy\n" +
            "0RYZWgJCIdzALu+G+0PT0ZZBF6B8w0sa2LOr4O1OgWWSkRKapwaMXPaDeoks6Wl4\n" +
            "9VHD0VX4qkh/Sin1GfpogFogptiMtFnwgCMYLh9hKXBJ+o6/pupzeVO/V2NtOnc4\n" +
            "erxeGh8/qdvPO2h3HqlQwIFEywhEjosL+4stx2UQ90lIxmpo7vo2zOmBhKgZKP8o\n" +
            "exow104AGk6liz7ZRlvratkVkeDfK6AfVkjrYFnrKJ9notIqM04QdfwtroEOhTsk\n" +
            "Mp0MhPtJir7zEfldCjyveILfZj0sNoKEf4HnnsboyNmlsSGLzZ1/voyLiFpFF7PW\n" +
            "IQoh9KX0p5Gf5V8rP/bGw6cZ4OOh/60cMbDbw7EG9R6y1c2Fv8kYvtFwUNQxIJK2\n" +
            "igq9rbOxk+MrrC85W61dqOgWC1f6rWoaeIzR5gwpItyuxNkOKSrHsC6hwvHOQBKH\n" +
            "2R4/H6/LIRW3sHCVEjPW2ez4xhjtUn9O/GKW/ILkvkVSq/wfdh1w9wgFfmQSnGTk\n" +
            "ele4DQP52kKCfjuWBRTbEgdqK/8a/62jhUR+LIoMMwSQixZUkxwZJNqXwz/RtvJd\n" +
            "CfyE0VkhN1nvBbPQ5WNDkshdAe/Z6QAAAMUP/2Gj0wKfY0IVibBU31UnuR/ZbmE4\n" +
            "BtEfCmMQ0eT6cXoCg+W/yXbImGD+EWnWelfRgFNKGJnh64/7D++udAwgYvCBanB0\n" +
            "8S3FcmJ44saC3EISvq9K+CQO7+pZEOquUCWxcIzU9CuW2VcN38iy1U/1fPuvigFM\n" +
            "b8mPKcPYv6fDrP2RhbvXS5imCLDM/GN7kF6nvytCoSQRBb/wdsMdhONu//aEevYM\n" +
            "AtThkV17wO7gIfkCovtSqI93tRGBtHXSem6ItQ473fJgfqeqz7OPixcGEJkZKEF1\n" +
            "z3zz+sXA7T4IMlPc+TfWcX6qJNer4jdjFMv+E8yXNVSs8QxJobyH4EUhQO3e6888\n" +
            "M3DJmMDtA7N5kPrDiUfhuD3Tv/h4oEj4sXTqiNh24z8/H1qdwIi4Gw/YncmEWeVK\n" +
            "nP3WWAdsefSYkPbYBl1BPzJ6n+TboXbyPpBKPipWhDTPeiYZUy2WcAMCo16aRcDn\n" +
            "KtI+pCGTjVaojgIe0Vmy46MrernDkBRbqcjyuU3IxChA1BKjmO6vHCfoRLbDf95T\n" +
            "VW2BpD9HLlpdPkoBGz+Ch9Hp4dCBcxnl4UW0+SaqnGfHEm4dNAN0JmQ3Fhs1dmAi\n" +
            "FRTrycAXkpuLLv4LN4V+4DqkxHzAeKT/rHt8jM415fDRRqbh/QeFjuqNHxlIj3d1\n" +
            "k8bvxvGM5jNSwYKjx8ZXBGhuK3QBEADI5lfDxASsNZMLnDH93Bzq2YYneNaym0o9\n" +
            "rqoBx2yrHuL5jWOspDx2hTG48DHQt1IF0yXZCEeVtOsG9U86OGmt1hODHzfGeGnU\n" +
            "P9nQaIUDIJNXepQipaxwZZl7zqbxq60uYVKnFmarxMkw+P8hyuEWpVfuIcQgM2i9\n" +
            "SwelnY8RbvjTtx8UhQIrDKu+axWisrExFE6ty0QGBATPGLdW5cDBKs4oPMsG7t6T\n" +
            "ovcdgOdKpQDtoH81a+quEDsU/+lGsTmwReZqi4gBjqKHZA0MrUrLxAzIz/JagFVd\n" +
            "eWQtiv8CO2HyOmcwqmjhk+xXrXNxhOyWp6KMawBrMBGAoWz/chGN70aXh97SRPGd\n" +
            "tarA02B3KeC/7mpGXWtWiXBPdMvNcPP4dwKCQe/2LkGlCEGpmTyJrVcLSHE7zjkE\n" +
            "dPNjMfr/AEXDXI1D5Cqg277/sCTui4Y1eli1mGNSBvtL4KUHkE/eUXtUcv3KMXaD\n" +
            "Sb6EYLZosYRtzJxVuucJ35/p1PbYkEUHsNm/9TALWVoQFFbfq0FovxMQFUAbptBm\n" +
            "Ldt3/aZB12Xh7dx4xMUnkt2otn9NJxqm/ThP8YC0zCLKVtKHL4AdYRYnv98EI0IP\n" +
            "eu71z0Ib2r0SQjym1Db6nUNCX3ZGKlAfqVlfu26Ob7sAIRF7gQAl8oddDgos6Gna\n" +
            "onmcr7OEvwARAQABAA/42ZyodH749ypENwJ58QFit83nnKbH6OLmobaqPQ/g8q4C\n" +
            "Lht5KQhXQtc3HmkPjLifoEkwnGZ1JAFUk7TxaZ8YDOfwB5gV6/+CouYgibitjs86\n" +
            "ZDqvoaTTpIWcO2XqCUOf04PLUJhzN89w67TLDbYBgWyYUnNA5NOXukALiHM8OL+u\n" +
            "+z9GuAz0zEZtW7wJM3/CPE3chWSOlyjDP/cF1DRwr//Hgs5XHRHUoEoyyUKK4DZ0\n" +
            "5Iqoc4Ik/2bImKnOuN3ZUmP+fzc+aAr/AkJ3ecPVwRW1KdAVziVn6/IR3g/+XR/C\n" +
            "eLj9pzlVyJyMGGzjH5PCsjqvvmopI4uhA2dxkA5L86DTCwvm/yBvyy7IgZvoCqsh\n" +
            "b+HqEsvuRmbcRWsaLGk7jVeeQtGbHuyqqls71t7Rx4bTFZRIxi2mEs9mOweQGVNX\n" +
            "nceBYbtL2pt/EqpyMKcXK1Mikm37EIE3LTFG3SdOhmtdaOMqwkRISVeiyPgoHkz0\n" +
            "PmE7ORaS/26ephmvHLRZ7b/gil+c8OzlQZOlPz7+SnrXA7iMziRz3rxiWjalRYS7\n" +
            "c6nxHBjjOLp8FN+toqrxZ3AbcnyF8ScNlIVn5jsMAtloaacnu6blcZx17RyqM+4k\n" +
            "PCxxLoHYE64UGPPeRnPsebvsf01HqjmQzS/mnjYNJ/I9HOSr5vvar4eozOQdLQgA\n" +
            "4cQInhOLS9jW26xst23N84eAYwldt+E/Iicw0awKaVyKOwuacK5FRtfZtc8QmSJX\n" +
            "gn2bx2ymaj6rJfBAhm2NzDUUHEaXw9VZy0zaE6s9w9rvBz7c1M8N1OPU0uEgnWxW\n" +
            "oQQfq8bQg/xHpk5tMWoYYaeTaDFGg6VkOwzH6HM71bGhVDCNW9J9tnA5xWmcQV65\n" +
            "f3hvnK1z5dJ12+5Ae2WKvTWCYTueClz9wmtlrQwkdYbqjR4euvKlhR8RrJzCHOVm\n" +
            "Rxjw14B85N37zoRIa6ESfAzZtzm9n+ppDjHUKlz87rDTXSTqT4F6sN5h7UiRmIyy\n" +
            "ZLKjhBG3gy0o/VZ00rLhvQgA483TEkeu5a3aUBcsJG3zvJsRAPH7eDT/7KdPTwvU\n" +
            "GKo0juTmfaVze9+aL+vQ8ReoSvj/nDBLG8N2tDf/GcmD9GtlMQX+Kdy4+3FtMXXa\n" +
            "mf076UPa0971LyfqQp1aaVxlI1HKSVA6XKkU7x5c+RGEmpL1CoXUTGZnIyCswLmD\n" +
            "0DZP1d7AckPgCqVaiM8lO7BWL4MXOqjhRoYY8282ZzSLAdA0WQcrAmsCApHTXprY\n" +
            "+uXtA+TwIl1KA7f9X7jAVKlymsGcljwy25Uxwzcg/2ELxlJFuwnIqZzO7bxs+oIK\n" +
            "zlFa1KcW9KvWoEaq/GQwbbH7Q8vOviUlHo+f15gYfeaiKwf/WLvdFiRYXeBWPgMQ\n" +
            "SBzskaj0ti6QsZjLhYIMXQa+EyOYU7mlK9u9OD/sbVnY6P+n+FXvn33JbKE7kP/M\n" +
            "yWqllntsrjeul4p03hqXhdMDwVY780DYLm7g/Dkxg3r4nLIubjQ8gbDxuj4d3hwl\n" +
            "/FO7Wc4lLzc2M5VqkJ5mYQSKgBSI7mQCkEYUGFW/hInFja+BsuSrDZokueRh9dXe\n" +
            "Um5qsHpy5BQN54+C/g/Dyd/PXl1OBJbYIJb6z4t9qZ/zDs9uae21KvWh4hnBoRTZ\n" +
            "d6JQK634lOtsFCqko8pCjv4CTexT3wrpew0KlJQImxqUIXmZxOxU+pm01DPggwCr\n" +
            "d+Cp6464wsF2BBgBCgAqBYJobit4CRA12yfjNj3dLBahBJiaVmuF4trEwRpuozXb\n" +
            "J+M2Pd0sApsMAACSeQ//TVNzDsv6N2oQM83vNggoPwS31jeDToJJCaU6EI0kPa1s\n" +
            "GzWx1Z0fSbs8cwsQDGB8As5NsbPNSbBUOZwUeiqfxPyFSgzsaelsicTf0ZDoXyXX\n" +
            "K16q/zDP4dCNZK53ZN2u1sWZRCv/X5rSbjDu8+JrO8hUWaFrmJRwTJHV1E05+Wmd\n" +
            "d5dUO0qKx6AFek5JxzWME+BBkYcv06tX6fqVcS8yl0ubO0kXnWxQICnKk+oynMGQ\n" +
            "Hy6iNeSKHDyWpDthYZuLg9PRQyaAZu0TA3frHTTImNN57FdM29MkdX3hAPhmXUYE\n" +
            "fTo64JemFHqJyF74MO66xUIIsIeptvn/zWwbI1TCZAzlUDkBd9i/YDnlpzIcsnRq\n" +
            "jz2GF5KDqHPMEsqlmviO5Xh/c28vL9I00CM5HTEacmYnj8lIkc3g/MCRFmN7KUnL\n" +
            "tlrliQlch8M0IrW5K45LhV61Cyf4eJmZwnWGGbbeXG8yRrSOIhjBfVj/YW64M7hp\n" +
            "5Tm70ke3smDdlU01GeaXYB/JWmc4F4MpEShwOzVClfSmlYkRepAJ1tPWXwGmWm7N\n" +
            "0dJuKflydyGDUgFxhS7WUq+hCYffylLJF4ZZgFcK8xMQgWXPjJ/Ff7hvzbJGvdwN\n" +
            "II7FA0UkvweXdB2MCgVHZ1dJHxoYVZw+PVmegliz//xcpKdJ1lVWh5Bn5U2n1Nk=\n" +
            "=y73F\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private final String rfc6637_nist_p256Key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: 676E A02C 0524 D5A1 7E2E  35DA 88BF B5EA 7283 A28D\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xXcEaG4r2xMIKoZIzj0DAQcCAwRbPwcrdsS/qStWtWMqgvEMecs85/AO+9hQmGMX\n" +
            "JEwJ0m7FVuRax9tNy7AsNtELwhqX86oHV5M4jXgJJftIQU6LAAEArRyV6Vgzpr7I\n" +
            "OqYVAgAMGWqAkkwwXOEq+ukxy1thY2IN2s0cQWxpY2UgPGFsaWNlQHBncGFpbmxl\n" +
            "c3Mub3JnPsKfBBMTCgBRBYJobivbCRCIv7XqcoOijRahBGduoCwFJNWhfi412oi/\n" +
            "tepyg6KNApsBBRUKCQgLBRYCAwEABAsJCAcJJwkBCQIJAwgBAp4JBYkJZgGAApkB\n" +
            "AAC5kwEA/csN9PMen64EB89uxa1lSkbCvFNHEFEdvbL5pHYJnO8BAKkdfG/2pfkl\n" +
            "maj+yrz8jZJSxUOpk70ChPJMM4XSYQryx3cEaG4r2xMIKoZIzj0DAQcCAwT32mVR\n" +
            "AVXGPEcOwy8Cp6oQDoVOEX+uSzeuiHllIIMsA+4/tqL6UCcrmy2exvuAKzZATdTr\n" +
            "XNpJCveYhkgGQrZ5AAEAprKnzjgtXFCUUJcDxiMgMkRTTin2mkt6CbvYfkVe6wcN\n" +
            "qsLAGAQYEwoAigWCaG4r2wkQKQ/gNDNFyqEWoQTg31jM2Fu4SJ69chspD+A0M0XK\n" +
            "oQKbAl8gBBkTCgAGBYJobivbAAoJECkP4DQzRcqh4HcA/1duhOn9b9+Slp7mU0cI\n" +
            "8MasqP670nJqYSnCK+FQein5AP9ypyOVaaBUzpvcssM0tQ5eAqowGr8AeWaWVgWd\n" +
            "ooAvEgAAreIA/j1T1rhE6HT5Qx9VqhOSNlLvocXn7FZE6R0mSbUM8fQoAQCKqboL\n" +
            "EFyQgHqtd/1cwE7XCoP9XGpeR/wrrlu+C8fEKMd7BGhuK9sSCCqGSM49AwEHAgME\n" +
            "NBcdejsLU0f8PySxVheQDbIBgBTb96AzFXP7R43JwGP5fwVqdFtm6+c8uIs9MGPu\n" +
            "fploeKB8rJy5pYCQdOLP7gMBCAcAAQCD5MOaoblzvaZY45owlK1Ql9+Pjy9guvYP\n" +
            "Aq8pVMv8FhF4wngEGBMKACoFgmhuK9sJEHCEoMs7Vp9lFqEECCC6yX4Ec3rhHBTY\n" +
            "cISgyztWn2UCmwwAAMMoAQDJ/7MYCcccQ9/3TTxT8pmSsDiNyw2EVw3gdx/Wgda4\n" +
            "+QD/ZiadfaINnG+cL/70xG3Nk6Zq7cj8HpplS+eioH8T0D4=\n" +
            "=vt0e\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";
    private final String rfc6637_nist_p384Key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: 94F6 9FC9 FAD5 1B28 C7E3  6194 30AE 6C4E C0DD 7A36\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xaQEaG4sORMFK4EEACIDAwSwoS/xK6vbTSP9+rvlW4bHyEOux6RXB8WozeIgJ4pG\n" +
            "0Da8tyDRaRRwIWDHZANUaOl6Iq6KVTZmEZCq65IvxOwC3lwFPILlTIBlgn3kBNFX\n" +
            "nVPrmEyHuR1kzyVzdegSPicAAX43CTFhi/T6NXA+KIMXLI8Gs03JHG8Xe2XgzHEW\n" +
            "vZG0QhiLK5c4fN2riZKvaSKviwUVJ80cQWxpY2UgPGFsaWNlQHBncGFpbmxlc3Mu\n" +
            "b3JnPsK/BBMTCgBRBYJobiw5CRAwrmxOwN16NhahBJT2n8n61Rsox+NhlDCubE7A\n" +
            "3Xo2ApsBBRUKCQgLBRYCAwEABAsJCAcJJwkBCQIJAwgBAp4JBYkJZgGAApkBAACt\n" +
            "ZQGA1f6gMWWf+jRIX/BP57hkTpNPpXWb391p/HmQeaq976nJu9pf/2NqkXcY2LXl\n" +
            "WiFYAX9gxaP1l1UwIvQza7bTfvurt3NKY73NHtYnkEdRKfrkF8BoLO0EPiWbnKAj\n" +
            "4uQvDnDHpARobiw5EwUrgQQAIgMDBC/URxDZzlFngKNcheVX7I38zD6WM5XI/EWD\n" +
            "lPZwU27qjNuDYm/MaRGNVUwwGBz/IVyuv2gkKhM77fdvCXiw7Cp048XJxRqQgbT2\n" +
            "eHMxV0WDktdOiQPmbiPl3f+WUIi26gABgKFPNs1Zc5B34skW4ekDjTG+AN3CaPyN\n" +
            "9JQw8m42NgU4zLFYBO/RPQM2BURW84+jVBfJwsBYBBgTCgCqBYJobiw5CRDIOxbO\n" +
            "vwEL8xahBEyydor1aZucFc968Mg7Fs6/AQvzApsCfyAEGRMKAAYFgmhuLDkACgkQ\n" +
            "yDsWzr8BC/MOLgF/WryQUQDFJbnOnL7DfIH9pSuQyzoXV2NMuI+boBY4vNGOKldD\n" +
            "ARHhD7JlYcojotZoAYC8g+LlQtiNM+pwvAyDrABZJlsJ8It61otVN6ZZ7s5XtFbc\n" +
            "ejdOPAjFQwLUnmFUkZ0AAHTLAYD/J4/idYykPWjVBkCYj5H1cjUB0s9SA/Gzg265\n" +
            "SivgRK7uftq/FKcTWJvgeyzZMDYBf1m1KR/8MXSxueFMXh5dOHtB7knidlJhoCx7\n" +
            "WAid5lRLjLNicmKgTrSn8WFPJcMno8eoBGhuLDkSBSuBBAAiAwMEgmwL/2Pnbtnj\n" +
            "I7yT0RXdqKqedkcdAWO4nYXFgSEIry6D91OsU7w2zjlY4A6OwH9CcEzCIFzxdd9b\n" +
            "e6lJMgt4Jo7jL0BHKQGI1g+wjAhFE1OPDUKyowG6Jg3f/ClIhRcnAwEJCAABf3vS\n" +
            "le9oR3yjGqDBUoQbjpjGOVqdY9U3KwmF4pVG4IO7KBfz4hb0ac8mKAQ+yT0kchcs\n" +
            "wpgEGBMKACoFgmhuLDkJEM01rTUhRvQBFqEEdXycZR2JfwMHDpXIzTWtNSFG9AEC\n" +
            "mwwAAL/lAYC6abLpSzdONnsbU/4l2pUDspW6nlwQCubpHEYK/wILu/VxsKOnkGY9\n" +
            "AoI8XJ4FD1oBgN0YaQbzLwcyokZDkv6Qs61J0vJdLIQqcs2Pg3Sgz9z2/RGmn3Cf\n" +
            "ulVQ7f+i2iXPiw==\n" +
            "=REc7\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private final String rfc6637_nist_p521Key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: DFDE 25E0 9BB5 1B3E BF54  2464 F66D 7C1B 5CA1 6CFA\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xcAaBGhuLIwTBSuBBAAjBCMEAAmlwVRUmU6UxKovM1Isxqo2lgc1FVYrZjfoRtHU\n" +
            "7g4hkTcJONQtneUqfkeriCT2cCfhFbW/ECRgyj6DtRd0zWMSAJAenK1j2Xuxkqow\n" +
            "NP8XW5VqMXTnF94k1Ap10UP29uTKJSEnMUQ1AGr9se5nAGHGkltDdUwhH1bblNbR\n" +
            "3CksSZ6fAAIJAdSVQ8GVU0pBS52yFUVBzWkLsGDSebghUeZ8VXPvZy5f9PLs3LUO\n" +
            "IapjWxhYYqcpSFT9OXR+G1JfllpMvQEPopq6Hh/NHEFsaWNlIDxhbGljZUBwZ3Bh\n" +
            "aW5sZXNzLm9yZz7CwCIEExMKAFEFgmhuLIwJEPZtfBtcoWz6FqEE394l4Ju1Gz6/\n" +
            "VCRk9m18G1yhbPoCmwEFFQoJCAsFFgIDAQAECwkIBwknCQEJAgkDCAECngkFiQlm\n" +
            "AYACmQEAAJlqAgkBI10R6r6c5DJZWE3c/lvReX5ijepN9kq7WuQS8LcG1ytmjmBV\n" +
            "3tXbwTwYpugTAORfb+/+SH6NxpbGCncIAMxMrgwCCNh0EkcWqBeqXnKUQWC5zXnD\n" +
            "vESwowUuW0QnXG8Ne9hDNUjymqnaowWXePzRkStW+nMrrlfp5dMExmTGt0gnig/4\n" +
            "x8AaBGhuLIwTBSuBBAAjBCMEAO1gtWTxso1k3/X8ADr2D+dhG28JWs8mEwLnlOBE\n" +
            "Joxy4nmK74FukAmBc/Vd1PWK8JYlRIljm3TnnzCph6RYSTl4AeBHm3j9YPCtEPSg\n" +
            "QR7CiOphIES+VyRpyYH71X/Rl2BDjKE+zhDFnXj1QXCe7tt/5858wPtrmHcjrTpJ\n" +
            "Zcr7LPsPAAIJAWcSyRYXZ0ei9WfV1r6NDwMciWkJ796NU4uri7CxTT+rqcdeyjGt\n" +
            "wmLSQrTYx2UoMzQDay3V9oTyD9ELygCriZRWH/DCwKAEGBMKAM4FgmhuLIwJEBbT\n" +
            "bO9xR0MrFqEEwIRfb9gaL/7D1calFtNs73FHQysCmwKjIAQZEwoABgWCaG4sjAAK\n" +
            "CRAW02zvcUdDK0k5AgkBRQNY7OGgQ3QsI3Oj+VMhwkMggmpFzRJFKkZH4gBpW3ZY\n" +
            "4owNCub5zXZTKdt6EfG2wKjsZsbcsF2QPV8raJQBGMkCCQGOBK7VMvtwLfjzgyKV\n" +
            "YZHX8G5C3/R5AYVKNdp7DhsXmYax2VJd5366piotQWsWBduYBSHOb5AOJuufN53X\n" +
            "GGy6ZwAAT6UCCQEug6uNr44EBxLGZOpY86yNCXIMifiX35bHLE++P8ekLC8sPG1B\n" +
            "uOGRubrrfY+EsYvbgdSM1VEYOToXzEb865AxWwIJAZ93WQ7ryjQoq/l8MIOfp29r\n" +
            "iYMe9lymUdPG8CA8WnEFv10SeOGTMW6p2D4Uv6WsjXU42eQ4DJFB56p8SN/oS2Jn\n" +
            "x8AeBGhuLIwSBSuBBAAjBCMEAFBOUkr2HwCIbTnnGessPh/QdF9BeHZaBdhppeJ9\n" +
            "xUT7vKrmraumPfwDb6XHqNe7tOuU01/00nNkrRmz+tdXRg+5ASOD7W9R6mJL9JoN\n" +
            "J4tRXapI2IZhvzFCurfizRKkvbIeAAgDJwv2/tMxM0K3l3feUcg/bFwzqu1EyXkP\n" +
            "vWECKOPRAwEKCQACCQGona31PD3qYbd9Ksjcg9M0gWRcokowqVl9+8/SMlVE8La6\n" +
            "GNHp4PLrWoZPHlSkwGJrP9Nl0w8MvtZk1I27laBRdiO8wrwEGBMKACoFgmhuLIwJ\n" +
            "EOXVJLmSPRyBFqEESts1UDF7UZ7QtXc45dUkuZI9HIECmwwAAMyNAgkBjCNM90/h\n" +
            "mh4qNdR8cILTXbljUanP8hLHonUFBTtoT5B1kZs8mfEZ4+ky2TosGJ2mBBxqwfJL\n" +
            "zi85OT9q3ny/L9oCCQFnv1K4mlCgmxVnLoJMLeFHhS8s3j9QZhyBKh/D0Xt2JLm8\n" +
            "OlXwObqzpIw/cSOfLL1iCQWM8vkmD9OnFHs3GAPR1A==\n" +
            "=k2f9\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private final String rfc9580_curve25519Key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: B314DED9 261228B2 B0D532BB F51BDBA2  A9D82A96 72E72026\n" +
            "Comment: 05753EE3 3D0384DF\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xUsGaG4s6BsAAAAg7gPWPUygdAOQ2UpKq9OVrAwgkwyyNAiWdOLaz5fVdyoA5yP3\n" +
            "L0YRfI1gpqf/xpPBDXqxJfG2WQAeONgURB9VGY7NHEFsaWNlIDxhbGljZUBwZ3Bh\n" +
            "aW5sZXNzLm9yZz7CwAIGExsKAAAAUwWCaG4s6CKhBrMU3tkmEiiysNUyu/Ub26Kp\n" +
            "2CqWcucgJgV1PuM9A4TfApsBBRUKCQgLBRYCAwEABAsJCAcJJwkBCQIJAwgBAp4J\n" +
            "BYkJZgGAApkBAAAAAIhfICpt+6KTUR1hPhrFhUBIhOIOCWYaq+T7LQvjZqVCJGCV\n" +
            "yQmNkiWif60p8yoNt98xeluWJR1JzlgELas6Yk3VwwCovCG5f6Wy+N24al/7QRcW\n" +
            "P8OoY/QC26iq6fa89OCaBcdLBmhuLOgbAAAAIC5xzZC2SfJ4EmHdm8gQ2kSK70gF\n" +
            "CNft4Cp1QHrrJ6ztADbMh1VLxMh6NDv7veidlpt/QYOLYu0q3GiSuMSedEdAwsB1\n" +
            "BhgbCgAAAMYFgmhuLOgioQY+0msPIWONP74ILxChN8KYq4YthwEyleVGRCOnFYJh\n" +
            "uQKbApkgBhkbCgAAACkioQY+0msPIWONP74ILxChN8KYq4YthwEyleVGRCOnFYJh\n" +
            "uQWCaG4s6AAAAABkmSAm81g4eLBFV/+NqyCC0zVeoogB6sHzyggIOa+N9SU91nKW\n" +
            "RpxbMjBngqAgJfGMQMPcJVrk+OZq5qtO/ymLF3ZstWDUFkz4TjUTE3Rnwcq1cZSF\n" +
            "aTM8b1tU9x/THu/QIwUAAAAAOoUgStz+zEYrGa9RJZflAOKqRnrV982sbwSSVxlX\n" +
            "ZM5lDxho4V/ml4FMLSimsaayKQvgLGG0D9CY/DAaFG6swR0a6vhJGIXmG/yFnjZV\n" +
            "O8Nag3ILTRQROo+EGsxF1GKVjXkBx0sGaG4s6BkAAAAg2DMyEKVzvpAmKIySltDq\n" +
            "yTecz3rJaB2wgMy/ezzMTAUAyEfaLkpWJQn1tas2LmLwQozm40gArZM/LWEhb06E\n" +
            "0mfCmwYYGwoAAAAsBYJobizoIqEGeK8FaQTzFASP/wgCezMGLDt/wWgRPECuIUpi\n" +
            "uvP1TX4CmwwAAAAAWZogQKL+ST9ooOeA4yY17pNcc4xIJCxHcOyBHnDTVLEaVvpA\n" +
            "sH4w8cwCObiCuWFlZV0OT98grtvKB9d8wvXHFgVdQIXFfxpH0U9A69stD40WnUcq\n" +
            "rSoALRT/UC0knHxQC1EC\n" +
            "=P0v2\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private final String rfc9580_curve448Key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: B1B2466D 4B443432 425AE494 229AD153  0DDBA981 DB39CE5A\n" +
            "Comment: B2A12078 D8489849\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xX0GaG4tJhwAAAA5TzpWwV5T+9yxlRTfE0vF4tVIy4Go/Ki5O8iuyJe7HytlQa2k\n" +
            "CICNWr/E/COtvaULPJpWc3HnNdoAAHQ4BZAMyYJr6mBnbOmAUEYc1ICMEBZhnYtN\n" +
            "og896p/k3NhZc9stwb1eNFlNPV/ggt8LBcGuyTfiDc0cQWxpY2UgPGFsaWNlQHBn\n" +
            "cGFpbmxlc3Mub3JnPsLANAYTHAoAAABTBYJobi0mIqEGsbJGbUtENDJCWuSUIprR\n" +
            "Uw3bqYHbOc5asqEgeNhImEkCmwEFFQoJCAsFFgIDAQAECwkIBwknCQEJAgkDCAEC\n" +
            "ngkFiQlmAYACmQEAAAAAwTkg/uSWDcdMxaU0dmX589uo6mDbA41RjbIV4WNM0rPp\n" +
            "c+ReYsDP0BdX1PMm0PNwmIDt6iiasgOY/+jMd1y9UN1aXToIMrizUophUvg4eVhi\n" +
            "F+0MT4eyIDjjdQAZv2evwLE3pkAPmi2D4LJ0d1cBLYAYAb4oMANUJXeDJsPWMf4Z\n" +
            "wIC9Wmr7TjSQRE5R6wXdh9cUEQDHfQZobi0mHAAAADm9lpUPfcAunOlcevNCNt6W\n" +
            "FAlmRn3QY+yT8cEFbfrflPzxB2uLwBDITX8mIKuTxEo651C4fNSdmQAALB7qjJSi\n" +
            "ew0rTFgqsZv6ud5aFR+vjpbHiQXkXQZ25BegJNut+tuvsj3SzxNNaAunKNgPXkx4\n" +
            "b8jZwsDaBhgcCgAAAPkFgmhuLSYioQbb/ck2OY9t+zdD+42TydVXF9yfj7Zns9sq\n" +
            "70urK/wNtQKbAsALIAYZHAoAAAApIqEG2/3JNjmPbfs3Q/uNk8nVVxfcn4+2Z7Pb\n" +
            "Ku9Lqyv8DbUFgmhuLSYAAAAAFg0giil1++wOpbPp08JikLQoO6n2B42gVIIuNo1t\n" +
            "ZH40/eI3tHLWtuWwvADiBtP+MWA/fCu5BjUNlrUSo/l58IvYAuL83r23hZbkB93P\n" +
            "S4x2zTIcPV/EmCd/KIA9hk8TjlN3FE2nqBUsytNb8fVDa6RfknvONhG6aSRaYHSm\n" +
            "cC5ijnZb5CMF6q9flVkdmULlBjyINAAAAAAAxeMgIVnKE/QZlRc9XKI9nOySipMe\n" +
            "y0YXUJAH9beCkGnj91KlCLAOvRIPGl+g9avbLVrEISSYLWXXWt5QpcL+v50dYixO\n" +
            "Dcw03lElwTb8tViclp8hoLdyGmre+QCLcn82w5bjSbJmUuSWUzaxdXt8mwhcsm8C\n" +
            "7nPWom+VKK2gmMhW+iIPCbZRq7mFXTlSyx5dewEmNwDHewZobi0mGgAAADgCf7RH\n" +
            "XYY4Iy6eJOjNMc+5Tb8FITtygbO6yD+wsNXgVeb02eolP2qhewtrOjGzBOa97bHt\n" +
            "PBEPUgAcV65IaTL7hDyHliS+1Sr07g8g1e9mQEZoZpfL0mAMhDp2cKVH4JP+EcZ1\n" +
            "Z28FVdMyCaMbZRnho8LADQYYHAoAAAAsBYJobi0mIqEGyDW+wOEE70nUm3kUGUr4\n" +
            "n/fvzk39E1FDfJM+CfjryzICmwwAAAAA2VsgR8S9//EIwf9HEHzqFc8KrpviwOBC\n" +
            "sqyKZrtH3wTzU9AIn2Ljhm40/RW5hKjXn/ChmQFgjplY+3vYz5ygmUooiNTt95LK\n" +
            "oRAFD/6/ZuugybGrqfgMGHs50gDKf+unENCOBzh5M68ERszNVDyqcKaYrqLEX/s1\n" +
            "s8z1wxR1F9ktlnwfqejv0XkUPIF+nRgSWv8ABgA=\n" +
            "=9CEB\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @FuzzTest
    public void decryptFuzzedMessage(FuzzedDataProvider provider) {
        byte[] ciphertext = provider.consumeBytes(8192);
        if (ciphertext.length == 0) {
            return;
        }

        System.out.println(new String(rfc4880_rsa4096Key));

        try {
            byte[] decrypted = sop.decrypt()
                    .withKey(draftKochEddsaForOpenPGP00Key.getBytes(StandardCharsets.UTF_8))
                    .withKey(rfc4880_rsa4096Key.getBytes(StandardCharsets.UTF_8))
                    .withKey(rfc6637_nist_p256Key.getBytes(StandardCharsets.UTF_8))
                    .withKey(rfc6637_nist_p384Key.getBytes(StandardCharsets.UTF_8))
                    .withKey(rfc6637_nist_p521Key.getBytes(StandardCharsets.UTF_8))
                    .withKey(rfc9580_curve25519Key.getBytes(StandardCharsets.UTF_8))
                    .withKey(rfc9580_curve448Key.getBytes(StandardCharsets.UTF_8))
                    .withPassword(password)
                    .ciphertext(ciphertext)
                    .toByteArrayAndResult()
                    .getBytes();

            assertArrayEquals(data, decrypted);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
