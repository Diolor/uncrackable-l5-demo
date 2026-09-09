package org.owasp.mastg.uncrackable5

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypted persistence for downloaded flags: AES-256-GCM under a persistent per-installation
 * key in AndroidKeyStore. This key is separate from the per-attempt attestation signing key.
 *
 * - A fresh provider-generated IV is used for every encryption; the 128-bit tag is mandatory.
 * - `version || tier` is authenticated additional data (see [FlagRecord]).
 * - One record per earned tier in `noBackupFilesDir`, replaced atomically via temp file + rename.
 * - A missing or invalidated key, or a record that fails to authenticate, causes the record to be
 *   discarded. There is never a plaintext fallback.
 *
 * A stored record is a previously issued flag, not proof of current device integrity, and never
 * satisfies a new ATTEST. Encryption protects the bytes at rest; instrumentation inside this
 * process can still observe plaintext at the encrypt/decrypt boundary. That is the intended
 * research surface, not an oversight.
 */
class FlagStore(context: Context) {
    private val dir: File = File(context.noBackupFilesDir, "flags").apply { mkdirs() }
    private val hasStrongBox =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /** Encrypts [flag] and atomically replaces the record for [tier]. Zeroes [flag] afterwards. */
    fun store(tier: Int, flag: ByteArray) {
        require(tier in 1..2)
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            val record: FlagRecord
            try {
                cipher.init(Cipher.ENCRYPT_MODE, key(create = true))
                val version = FlagRecord.VERSION
                cipher.updateAAD(byteArrayOf(version.toByte(), tier.toByte()))
                record = FlagRecord(version, tier, cipher.iv, cipher.doFinal(flag))
            } finally {
                flag.fill(0)
            }
            val target = file(tier)
            val temp = File(dir, target.name + ".tmp")
            temp.writeBytes(record.encode())
            if (!temp.renameTo(target)) {
                temp.delete()
                throw java.io.IOException("rename")
            }
        } catch (e: GeneralSecurityException) {
            throw java.io.IOException("store", e)
        }
    }

    /** Which tiers have a stored record. Does not decrypt; says nothing about validity. */
    fun storedTiers(): List<Int> = listOf(1, 2).filter { file(it).isFile }

    /**
     * Decrypts the record for [tier] in process. Returns null and deletes the record when the key is
     * missing or invalidated or the record fails authentication. Callers must zero the result.
     */
    fun read(tier: Int): ByteArray? {
        require(tier in 1..2)
        val target = file(tier)
        if (!target.isFile) return null
        val record = runCatching { target.readBytes() }.getOrNull()?.let(FlagRecord::decode)
        if (record == null || record.tier != tier) { target.delete(); return null }
        val key = key(create = false) ?: run { target.delete(); return null }
        return try {
            Cipher.getInstance(TRANSFORMATION).run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(FlagRecord.TAG_BYTES * 8, record.iv))
                updateAAD(record.aad())
                doFinal(record.ciphertext)
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            discard(target); null
        } catch (e: GeneralSecurityException) {
            discard(target); null
        }
    }

    private fun discard(target: File) {
        target.delete()
    }

    private fun file(tier: Int) = File(dir, "tier$tier.bin")

    private fun key(create: Boolean): SecretKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) return null
        if (hasStrongBox) {
            try {
                return generate(strongBox = true)
            } catch (e: StrongBoxUnavailableException) {
                runCatching { keyStore.deleteEntry(ALIAS) }
            } catch (e: ProviderException) {
                runCatching { keyStore.deleteEntry(ALIAS) }
            }
        }
        return generate(strongBox = false)
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).run {
            init(spec)
            generateKey()
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "flag-store"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
