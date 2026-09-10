package org.owasp.mastg.uncrackable5

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
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
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-256-GCM records for downloaded flags under a persistent hardware-backed AndroidKeyStore
 * key (separate from the attestation key), one per tier in `noBackupFilesDir`, replaced
 * atomically. Records that fail to authenticate, or whose key is gone, are discarded; there is
 * no plaintext fallback. The shipped UI never calls [read].
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
        return try {
            val key = key(create = false) ?: run { target.delete(); return null }
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
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return requireHardware(it, keyStore) }
        if (!create) return null
        if (hasStrongBox) {
            try {
                return requireHardware(generate(strongBox = true), keyStore)
            } catch (e: StrongBoxUnavailableException) {
                runCatching { keyStore.deleteEntry(ALIAS) }
            } catch (e: ProviderException) {
                runCatching { keyStore.deleteEntry(ALIAS) }
            }
        }
        return requireHardware(generate(strongBox = false), keyStore)
    }

    /** Check this AES key itself, including when loading an existing installation's key. */
    @Suppress("DEPRECATION")
    private fun requireHardware(key: SecretKey, keyStore: KeyStore): SecretKey {
        val info = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        val hardware = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        } else {
            // API 28–30 cannot distinguish TEE from StrongBox, but can require secure hardware.
            info.isInsideSecureHardware
        }
        if (!hardware) {
            keyStore.deleteEntry(ALIAS)
            for (tier in 1..2) {
                file(tier).delete()
                File(dir, file(tier).name + ".tmp").delete()
            }
            throw GeneralSecurityException("Hardware-backed flag storage required")
        }
        return key
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
