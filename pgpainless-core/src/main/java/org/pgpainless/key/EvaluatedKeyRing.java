package org.pgpainless.key;

import java.util.List;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public interface EvaluatedKeyRing {

    PGPSignature getUserIdCertification(String userId);

    PGPSignature getUserIdRevocation(String userId);

    PGPSignature getSubkeyBinding(long subkeyId);

    PGPSignature getSubkeyRevocation(long subkeyId);

    default boolean isUserIdRevoked(String userId) {
        return getUserIdRevocation(userId) != null;
    }

    default boolean isSubkeyRevoked(long subkeyId) {
        return getSubkeyRevocation(subkeyId) != null;
    }

    default @Nullable List<KeyFlag> getUserIdKeyFlags(String userId) {
        PGPSignature signature = getUserIdCertification(userId);
        return SignatureSubpacketsUtil.parseKeyFlags(signature);
    }




}
