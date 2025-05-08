package org.pgpainless.exception

import java.util.*
import org.bouncycastle.openpgp.PGPException
import org.pgpainless.key.SubkeyIdentifier

class MissingPassphraseException(keyIds: Set<SubkeyIdentifier>) :
    PGPException(
        "Missing passphrase encountered for keys ${keyIds.toTypedArray().contentToString()}") {
    val keyIds: Set<SubkeyIdentifier> = Collections.unmodifiableSet(keyIds)
}
