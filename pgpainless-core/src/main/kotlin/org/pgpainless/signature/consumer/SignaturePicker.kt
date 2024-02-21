// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer

import java.util.Date
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.bouncycastle.extensions.getPublicKeyFor
import org.pgpainless.bouncycastle.extensions.isExpired
import org.pgpainless.bouncycastle.extensions.wasIssuedBy
import org.pgpainless.exception.SignatureValidationException
import org.pgpainless.policy.Policy

/**
 * Pick signatures from keys.
 *
 * The format of a V4 OpenPGP key is:
 *
 * Primary-Key [Revocation Self Signature] [Direct Key Signature...] User ID [Signature ...] [User
 * ID [Signature ...] ...] [User Attribute [Signature ...] ...] [[Subkey
 * [Binding-Signature-Revocation] Primary-Key-Binding-Signature] ...]
 */
class SignaturePicker {

    companion object {

        /**
         * Pick the at validation date most recent valid key revocation signature. If there are hard
         * revocation signatures, the latest hard revocation sig is picked, even if it was created
         * after validationDate or if it is already expired.
         *
         * @param keyRing key ring
         * @param policy policy
         * @param referenceTime date of signature validation
         * @return most recent, valid key revocation signature
         */
        @JvmStatic
        fun pickCurrentRevocationSelfSignature(
            keyRing: PGPKeyRing,
            policy: Policy,
            referenceTime: Date
        ): PGPSignature? {
            val primaryKey = keyRing.publicKey
            return getSortedSignaturesOfType(primaryKey, SignatureType.KEY_REVOCATION).lastOrNull {
                return@lastOrNull try {
                    SignatureVerifier.verifyKeyRevocationSignature(
                        it, primaryKey, policy, referenceTime)
                    true // valid
                } catch (e: SignatureValidationException) {
                    false // not valid
                }
            }
        }

        /**
         * Pick the at validationDate most recent, valid direct key signature. This method might
         * return null, if there is no direct key self-signature which is valid at validationDate.
         *
         * @param keyRing key ring
         * @param policy policy
         * @param referenceTime validation date
         * @return direct-key self-signature
         */
        @JvmStatic
        fun pickCurrentDirectKeySelfSignature(
            keyRing: PGPKeyRing,
            policy: Policy,
            referenceTime: Date
        ): PGPSignature? {
            val primaryKey = keyRing.publicKey
            return pickCurrentDirectKeySignature(primaryKey, primaryKey, policy, referenceTime)
        }

        @JvmStatic
        fun pickCurrentDirectKeySignature(
            signingKey: PGPPublicKey,
            signedKey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): PGPSignature? {
            return getSortedSignaturesOfType(signedKey, SignatureType.DIRECT_KEY).lastOrNull {
                return@lastOrNull try {
                    SignatureVerifier.verifyDirectKeySignature(
                        it, signingKey, signedKey, policy, referenceTime)
                    true
                } catch (e: SignatureValidationException) {
                    false
                }
            }
        }

        /**
         * Pick the at validationDate latest direct key signature. This method might return an
         * expired signature. If there are more than one direct-key signature, and some of those are
         * not expired, the latest non-expired yet already effective direct-key signature will be
         * returned.
         *
         * @param keyRing key ring
         * @param policy policy
         * @param referenceTime validation date
         * @return latest direct key signature
         */
        @JvmStatic
        fun pickLatestDirectKeySignature(
            keyRing: PGPKeyRing,
            policy: Policy,
            referenceTime: Date
        ): PGPSignature? {
            return pickLatestDirectKeySignature(
                keyRing.publicKey, keyRing.publicKey, policy, referenceTime)
        }

        /**
         * Pick the at validationDate latest direct key signature made by signingKey on signedKey.
         * This method might return an expired signature. If a non-expired direct-key signature
         * exists, the latest non-expired yet already effective direct-key signature will be
         * returned.
         *
         * @param signingKey signing key (key that made the sig)
         * @param signedKey signed key (key that carries the sig)
         * @param policy policy
         * @param referenceTime date of validation
         * @return latest direct key sig
         */
        @JvmStatic
        fun pickLatestDirectKeySignature(
            signingKey: PGPPublicKey,
            signedKey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): PGPSignature? {
            var latest: PGPSignature? = null
            return getSortedSignaturesOfType(signedKey, SignatureType.DIRECT_KEY).lastOrNull {
                try {
                    SignatureValidator.signatureIsOfType(SignatureType.DIRECT_KEY).verify(it)
                    SignatureValidator.signatureStructureIsAcceptable(signingKey, policy).verify(it)
                    SignatureValidator.signatureIsAlreadyEffective(referenceTime).verify(it)
                    if (latest != null && !latest!!.isExpired(referenceTime)) {
                        SignatureValidator.signatureIsNotYetExpired(referenceTime).verify(it)
                    }
                    SignatureValidator.correctSignatureOverKey(signingKey, signedKey).verify(it)
                    latest = it
                    true
                } catch (e: SignatureValidationException) {
                    false
                }
            }
        }

        /**
         * Pick the at validationDate most recent, valid user-id revocation signature. If there are
         * hard revocation signatures, the latest hard revocation sig is picked, even if it was
         * created after validationDate or if it is already expired.
         *
         * @param keyRing key ring
         * @param userId user-Id that gets revoked
         * @param policy policy
         * @param referenceTime validation date
         * @return revocation signature
         */
        @JvmStatic
        fun pickCurrentUserIdRevocationSignature(
            keyRing: PGPKeyRing,
            userId: CharSequence,
            policy: Policy,
            referenceTime: Date
        ): PGPSignature? {
            val primaryKey = keyRing.publicKey
            return getSortedSignaturesOfType(primaryKey, SignatureType.CERTIFICATION_REVOCATION)
                .lastOrNull {
                    keyRing.getPublicKeyFor(it)
                        ?: return@lastOrNull false // signature made by external key. skip.
                    return@lastOrNull try {
                        SignatureVerifier.verifyUserIdRevocation(
                            userId.toString(), it, primaryKey, policy, referenceTime)
                        true
                    } catch (e: SignatureValidationException) {
                        false // signature not valid
                    }
                }
        }

        /**
         * Pick the at validationDate latest, valid certification self-signature for the given
         * user-id. This method might return null, if there is no certification self signature for
         * that user-id which is valid at validationDate.
         *
         * @param keyRing keyring
         * @param userId userid
         * @param policy policy
         * @param referenceTime validation date
         * @return user-id certification
         */
        @JvmStatic
        fun pickCurrentUserIdCertificationSignature(
            keyRing: PGPKeyRing,
            userId: CharSequence,
            policy: Policy,
            referenceTime: Date
        ): PGPSignature? {
            val primaryKey = keyRing.publicKey
            return primaryKey
                .getSignaturesForID(userId.toString())
                .asSequence()
                .sortedWith(SignatureCreationDateComparator())
                .lastOrNull {
                    return@lastOrNull it.wasIssuedBy(primaryKey) &&
                        try {
                            SignatureVerifier.verifyUserIdCertification(
                                userId.toString(), it, primaryKey, policy, referenceTime)
                            true
                        } catch (e: SignatureValidationException) {
                            false
                        }
                }
        }

        /**
         * Pick the at validationDate latest certification self-signature for the given user-id.
         * This method might return an expired signature. If a non-expired user-id certification
         * signature exists, the latest non-expired yet already effective user-id certification
         * signature for the given user-id will be returned.
         *
         * @param keyRing keyring
         * @param userId userid
         * @param policy policy
         * @param referenceTime validation date
         * @return user-id certification
         */
        @JvmStatic
        fun pickLatestUserIdCertificationSignature(
            keyRing: PGPKeyRing,
            userId: CharSequence,
            policy: Policy,
            referenceTime: Date
        ): PGPSignature? {
            val primaryKey = keyRing.publicKey
            return primaryKey
                .getSignaturesForID(userId.toString())
                .asSequence()
                .sortedWith(SignatureCreationDateComparator())
                .lastOrNull {
                    return@lastOrNull try {
                        SignatureValidator.wasPossiblyMadeByKey(primaryKey).verify(it)
                        SignatureValidator.signatureIsCertification().verify(it)
                        SignatureValidator.signatureStructureIsAcceptable(primaryKey, policy)
                            .verify(it)
                        SignatureValidator.signatureIsAlreadyEffective(referenceTime).verify(it)
                        SignatureValidator.correctSignatureOverUserId(
                                userId.toString(), primaryKey, primaryKey)
                            .verify(it)
                        true
                    } catch (e: SignatureValidationException) {
                        false
                    }
                }
        }

        /**
         * Pick the at validationDate most recent, valid subkey revocation signature. If there are
         * hard revocation signatures, the latest hard revocation sig is picked, even if it was
         * created after validationDate or if it is already expired.
         *
         * @param keyRing keyring
         * @param subkey subkey
         * @param policy policy
         * @param referenceTime validation date
         * @return subkey revocation signature
         */
        @JvmStatic
        fun pickCurrentSubkeyBindingRevocationSignature(
            keyRing: PGPKeyRing,
            subkey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): PGPSignature? {
            val primaryKey = keyRing.publicKey
            require(primaryKey.keyID != subkey.keyID) {
                "Primary key cannot have subkey binding revocations."
            }
            return getSortedSignaturesOfType(subkey, SignatureType.SUBKEY_REVOCATION).lastOrNull {
                return@lastOrNull try {
                    SignatureVerifier.verifySubkeyBindingRevocation(
                        it, primaryKey, subkey, policy, referenceTime)
                    true
                } catch (e: SignatureValidationException) {
                    false
                }
            }
        }

        /**
         * Pick the at validationDate latest, valid subkey binding signature for the given subkey.
         * This method might return null, if there is no subkey binding signature which is valid at
         * validationDate.
         *
         * @param keyRing key ring
         * @param subkey subkey
         * @param policy policy
         * @param referenceTime date of validation
         * @return most recent valid subkey binding signature
         */
        @JvmStatic
        fun pickCurrentSubkeyBindingSignature(
            keyRing: PGPKeyRing,
            subkey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): PGPSignature? {
            val primaryKey = keyRing.publicKey
            require(primaryKey.keyID != subkey.keyID) {
                "Primary key cannot have subkey binding signatures."
            }
            return getSortedSignaturesOfType(subkey, SignatureType.SUBKEY_BINDING).lastOrNull {
                return@lastOrNull try {
                    SignatureVerifier.verifySubkeyBindingSignature(
                        it, primaryKey, subkey, policy, referenceTime)
                    true
                } catch (e: SignatureValidationException) {
                    false
                }
            }
        }

        /**
         * Pick the at validationDate latest subkey binding signature for the given subkey. This
         * method might return an expired signature. If a non-expired subkey binding signature
         * exists, the latest non-expired yet already effective subkey binding signature for the
         * given subkey will be returned.
         *
         * @param keyRing key ring
         * @param subkey subkey
         * @param policy policy
         * @param referenceTime validationDate
         * @return subkey binding signature
         */
        @JvmStatic
        fun pickLatestSubkeyBindingSignature(
            keyRing: PGPKeyRing,
            subkey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): PGPSignature? {
            val primaryKey = keyRing.publicKey
            require(primaryKey.keyID != subkey.keyID) {
                "Primary key cannot have subkey binding signatures."
            }
            var latest: PGPSignature? = null
            return getSortedSignaturesOfType(subkey, SignatureType.SUBKEY_BINDING).lastOrNull {
                return@lastOrNull try {
                    SignatureValidator.signatureIsOfType(SignatureType.SUBKEY_BINDING).verify(it)
                    SignatureValidator.signatureStructureIsAcceptable(primaryKey, policy).verify(it)
                    SignatureValidator.signatureDoesNotPredateSignee(subkey).verify(it)
                    SignatureValidator.signatureIsAlreadyEffective(referenceTime).verify(it)
                    // if the currently latest signature is not yet expired, check if the next
                    // candidate is not yet expired
                    if (latest != null && !latest!!.isExpired(referenceTime)) {
                        SignatureValidator.signatureIsNotYetExpired(referenceTime).verify(it)
                    }
                    SignatureValidator.correctSubkeyBindingSignature(primaryKey, subkey).verify(it)
                    latest = it
                    true
                } catch (e: SignatureValidationException) {
                    false
                }
            }
        }

        @JvmStatic
        private fun getSortedSignaturesOfType(
            key: PGPPublicKey,
            type: SignatureType
        ): List<PGPSignature> =
            key.getSignaturesOfType(type.code)
                .asSequence()
                .sortedWith(SignatureCreationDateComparator())
                .toList()
    }
}
