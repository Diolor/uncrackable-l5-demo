package org.owasp.mastg.uncrackable5

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.SecureRandom
import java.util.Base64
import java.security.Signature
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

/** Attestation chain plus proof of possession for one server challenge. */
class AttestationProof(val chain: List<String>, val pop: String)

/**
 * Generates a throwaway EC P-256 key in AndroidKeyStore attested against the server challenge,
 * exports its chain, signs the challenge with it and deletes the key. StrongBox first; on
 * [StrongBoxUnavailableException] or a bare [ProviderException] (some OEMs throw it only at
 * `generateKeyPair()`) the partial alias is deleted and generation is retried in the TEE.
 */
class Attestation(context: Context) {
    private val hasStrongBox =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    private val random = SecureRandom()

    fun prove(challenge: ByteArray): AttestationProof {
        require(challenge.size == Challenge.SIZE)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val alias = ALIAS_PREFIX + ByteArray(12).also(random::nextBytes).toHex()
        try {
            generate(keyStore, alias, challenge)
            val chain = keyStore.getCertificateChain(alias) ?: throw IllegalStateException("no chain")
            val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: throw IllegalStateException("no key")
            val pop = Signature.getInstance("SHA256withECDSA").run {
                initSign(privateKey)
                update(challenge)
                sign()
            }
            return AttestationProof(chain.map { it.base64Der() }, Base64.getEncoder().encodeToString(pop))
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun generate(keyStore: KeyStore, alias: String, challenge: ByteArray) {
        if (hasStrongBox) {
            try {
                generateKey(alias, challenge, strongBox = true)
                return
            } catch (e: StrongBoxUnavailableException) {
                runCatching { keyStore.deleteEntry(alias) }
            } catch (e: ProviderException) {
                runCatching { keyStore.deleteEntry(alias) }
            }
        }
        generateKey(alias, challenge, strongBox = false)
    }

    private fun generateKey(alias: String, challenge: ByteArray, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .setKeyValidityEnd(Date(System.currentTimeMillis() + KEY_LIFETIME_MS))
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun Certificate.base64Der(): String = Base64.getEncoder().encodeToString(encoded)

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS_PREFIX = "attest-"
        const val KEY_LIFETIME_MS = 5 * 60_000L
    }
}

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
