package com.airchat.mesh.crypto

import android.content.Context
import com.google.crypto.tink.subtle.Ed25519Sign
import com.google.crypto.tink.subtle.Ed25519Verify
import com.google.crypto.tink.subtle.X25519
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// ---------------------------------------------------------------- identities

/** Long-term identity: Ed25519 for signing, X25519 for Diffie-Hellman. */
class IdentityKeys(
    val edSeed: ByteArray, // 32 bytes, secret
    val edPub: ByteArray,  // 32 bytes
    val xPriv: ByteArray,  // 32 bytes, secret
    val xPub: ByteArray    // 32 bytes
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IdentityKeys) return false
        return edSeed.contentEquals(other.edSeed) &&
            edPub.contentEquals(other.edPub) &&
            xPriv.contentEquals(other.xPriv) &&
            xPub.contentEquals(other.xPub)
    }

    override fun hashCode(): Int {
        var r = edSeed.contentHashCode()
        r = 31 * r + edPub.contentHashCode()
        r = 31 * r + xPriv.contentHashCode()
        r = 31 * r + xPub.contentHashCode()
        return r
    }
}

/**
 * Pre-key bundle exchanged out-of-band via QR scan or a BLE handshake.
 * The signed pre-key is authenticated with the Ed25519 identity key.
 */
class PreKeyBundle(
    val ed25519IdentityPub: ByteArray,
    val x25519IdentityPub: ByteArray,
    val signedPreKeyPub: ByteArray,
    val signedPreKeySignature: ByteArray,
    val oneTimePreKeyPub: ByteArray? // consumed after one session; null when exhausted
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PreKeyBundle) return false
        return ed25519IdentityPub.contentEquals(other.ed25519IdentityPub) &&
            x25519IdentityPub.contentEquals(other.x25519IdentityPub) &&
            signedPreKeyPub.contentEquals(other.signedPreKeyPub) &&
            signedPreKeySignature.contentEquals(other.signedPreKeySignature) &&
            (oneTimePreKeyPub?.contentEquals(other.oneTimePreKeyPub ?: ByteArray(0))
                ?: (other.oneTimePreKeyPub == null))
    }

    override fun hashCode(): Int {
        var r = ed25519IdentityPub.contentHashCode()
        r = 31 * r + x25519IdentityPub.contentHashCode()
        r = 31 * r + signedPreKeyPub.contentHashCode()
        r = 31 * r + signedPreKeySignature.contentHashCode()
        r = 31 * r + (oneTimePreKeyPub?.contentHashCode() ?: 0)
        return r
    }
}

/** Private halves of our published pre-keys (responder side of X3DH). */
class PreKeyPrivate(
    val signedPrePriv: ByteArray,
    val oneTimePrePriv: ByteArray?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PreKeyPrivate) return false
        return signedPrePriv.contentEquals(other.signedPrePriv) &&
            (oneTimePrePriv?.contentEquals(other.oneTimePrePriv ?: ByteArray(0))
                ?: (other.oneTimePrePriv == null))
    }

    override fun hashCode(): Int {
        var r = signedPrePriv.contentHashCode()
        r = 31 * r + (oneTimePrePriv?.contentHashCode() ?: 0)
        return r
    }
}

class X3dhResult(
    /** 32-byte shared secret that seeds the Double Ratchet. */
    val rootKey: ByteArray,
    /** Ephemeral public key the responder needs to complete X3DH. */
    val ephemeralPub: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X3dhResult) return false
        return rootKey.contentEquals(other.rootKey) &&
            ephemeralPub.contentEquals(other.ephemeralPub)
    }

    override fun hashCode(): Int =
        31 * rootKey.contentHashCode() + ephemeralPub.contentHashCode()
}

// ------------------------------------------------------------ double ratchet

class RatchetHeader(
    val dhPublicKey: ByteArray, // 32 bytes
    val previousChainLength: Int,
    val messageNumber: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RatchetHeader) return false
        return dhPublicKey.contentEquals(other.dhPublicKey) &&
            previousChainLength == other.previousChainLength &&
            messageNumber == other.messageNumber
    }

    override fun hashCode(): Int {
        var r = dhPublicKey.contentHashCode()
        r = 31 * r + previousChainLength
        r = 31 * r + messageNumber
        return r
    }
}

class RatchetMessage(
    val header: RatchetHeader,
    val ciphertext: ByteArray // AES-256-GCM
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RatchetMessage) return false
        return header == other.header && ciphertext.contentEquals(other.ciphertext)
    }

    override fun hashCode(): Int = 31 * header.hashCode() + ciphertext.contentHashCode()
}

/** Persistable ratchet state; maps 1:1 onto RatchetStateEntity in Room. */
class RatchetSnapshot(
    val rootKey: ByteArray,
    val chainKeySend: ByteArray?,
    val chainKeyRecv: ByteArray?,
    val sendCount: Int,
    val recvCount: Int,
    val prevChainLen: Int,
    val dhPriv: ByteArray,
    val dhPub: ByteArray,
    val dhRemotePub: ByteArray?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RatchetSnapshot) return false
        return rootKey.contentEquals(other.rootKey) &&
            (chainKeySend?.contentEquals(other.chainKeySend ?: ByteArray(0))
                ?: (other.chainKeySend == null)) &&
            (chainKeyRecv?.contentEquals(other.chainKeyRecv ?: ByteArray(0))
                ?: (other.chainKeyRecv == null)) &&
            sendCount == other.sendCount && recvCount == other.recvCount &&
            prevChainLen == other.prevChainLen &&
            dhPriv.contentEquals(other.dhPriv) &&
            dhPub.contentEquals(other.dhPub) &&
            (dhRemotePub?.contentEquals(other.dhRemotePub ?: ByteArray(0))
                ?: (other.dhRemotePub == null))
    }

    override fun hashCode(): Int {
        var r = rootKey.contentHashCode()
        r = 31 * r + (chainKeySend?.contentHashCode() ?: 0)
        r = 31 * r + (chainKeyRecv?.contentHashCode() ?: 0)
        r = 31 * r + sendCount
        r = 31 * r + recvCount
        r = 31 * r + prevChainLen
        r = 31 * r + dhPriv.contentHashCode()
        r = 31 * r + dhPub.contentHashCode()
        r = 31 * r + (dhRemotePub?.contentHashCode() ?: 0)
        return r
    }
}

interface DoubleRatchet {
    fun ratchetEncrypt(plaintext: ByteArray, associatedData: ByteArray): RatchetMessage
    fun ratchetDecrypt(message: RatchetMessage, associatedData: ByteArray): ByteArray
    fun snapshot(): RatchetSnapshot

    companion object {
        fun initAsInitiator(sharedSecret: ByteArray, remoteRatchetPub: ByteArray): DoubleRatchet =
            SignalDoubleRatchet.initAsInitiator(sharedSecret, remoteRatchetPub)

        fun initAsReceiver(sharedSecret: ByteArray): DoubleRatchet =
            SignalDoubleRatchet.initAsReceiver(sharedSecret)

        fun restore(snapshot: RatchetSnapshot): DoubleRatchet =
            SignalDoubleRatchet.restore(snapshot)
    }
}

/**
 * Signal-style Double Ratchet: a DH ratchet over X25519 combined with a
 * symmetric-key ratchet (HMAC-SHA256 chain KDF, AES-256-GCM message keys).
 * Out-of-order messages are supported via skipped-key storage (capped).
 */
class SignalDoubleRatchet private constructor(
    private var rootKey: ByteArray,
    private var chainKeySend: ByteArray?,
    private var chainKeyRecv: ByteArray?,
    private var sendCount: Int,
    private var recvCount: Int,
    private var prevChainLen: Int,
    private var dhPriv: ByteArray,
    private var dhPub: ByteArray,
    private var dhRemotePub: ByteArray?
) : DoubleRatchet {

    companion object {
        private const val MAX_SKIPPED = 1000

        fun initAsInitiator(sharedSecret: ByteArray, remoteRatchetPub: ByteArray): SignalDoubleRatchet {
            val dhPriv = X25519.generatePrivateKey()
            val dhPub = X25519.publicFromPrivate(dhPriv)
            val (rk, ckSend) = kdfRoot(sharedSecret, X25519.computeSharedSecret(dhPriv, remoteRatchetPub))
            return SignalDoubleRatchet(rk, ckSend, null, 0, 0, 0, dhPriv, dhPub, remoteRatchetPub)
        }

        fun initAsReceiver(sharedSecret: ByteArray): SignalDoubleRatchet {
            val dhPriv = X25519.generatePrivateKey()
            val dhPub = X25519.publicFromPrivate(dhPriv)
            return SignalDoubleRatchet(sharedSecret, null, null, 0, 0, 0, dhPriv, dhPub, null)
        }

        fun restore(s: RatchetSnapshot): SignalDoubleRatchet = SignalDoubleRatchet(
            s.rootKey, s.chainKeySend, s.chainKeyRecv, s.sendCount, s.recvCount,
            s.prevChainLen, s.dhPriv, s.dhPub, s.dhRemotePub
        )
    }

    private class SkippedKey(val dhPub: ByteArray, val n: Int) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is SkippedKey) return false
            return dhPub.contentEquals(other.dhPub) && n == other.n
        }

        override fun hashCode(): Int = 31 * dhPub.contentHashCode() + n
    }

    private val skipped = LinkedHashMap<SkippedKey, ByteArray>()

    override fun ratchetEncrypt(plaintext: ByteArray, associatedData: ByteArray): RatchetMessage {
        val sendCk = chainKeySend ?: throw IllegalStateException("no sending chain yet")
        val (msgKey, nextCk) = kdfChain(sendCk)
        chainKeySend = nextCk
        val header = RatchetHeader(dhPub, prevChainLen, sendCount)
        val ad = associatedData + headerBytes(header)
        val ct = aesGcmEncrypt(msgKey, nonceFor(sendCount), plaintext, ad)
        sendCount++
        return RatchetMessage(header, ct)
    }

    override fun ratchetDecrypt(message: RatchetMessage, associatedData: ByteArray): ByteArray {
        val header = message.header
        val ad = associatedData + headerBytes(header)

        // 1. Message we previously skipped?
        val skipKey = SkippedKey(header.dhPublicKey, header.messageNumber)
        skipped.remove(skipKey)?.let { msgKey ->
            return aesGcmDecrypt(msgKey, nonceFor(header.messageNumber), message.ciphertext, ad)
        }

        // 2. New DH public key -> stage the old chain, then ratchet.
        if (dhRemotePub == null || !header.dhPublicKey.contentEquals(dhRemotePub!!)) {
            stageSkipped(header.previousChainLength)
            dhRatchet(header.dhPublicKey)
        }

        // 3. Stage any skipped messages on the current chain, then decrypt.
        stageSkipped(header.messageNumber)
        val recvCk = chainKeyRecv ?: throw IllegalStateException("no receiving chain")
        val (msgKey, nextCk) = kdfChain(recvCk)
        chainKeyRecv = nextCk
        recvCount++
        return aesGcmDecrypt(msgKey, nonceFor(header.messageNumber), message.ciphertext, ad)
    }

    private fun stageSkipped(until: Int) {
        var cur = chainKeyRecv ?: return
        val remote = dhRemotePub ?: return
        while (recvCount < until) {
            val (msgKey, next) = kdfChain(cur)
            storeSkipped(SkippedKey(remote, recvCount), msgKey)
            recvCount++
            cur = next
        }
        chainKeyRecv = cur
    }

    private fun dhRatchet(remotePub: ByteArray) {
        prevChainLen = sendCount
        sendCount = 0
        recvCount = 0
        dhRemotePub = remotePub
        val (rk1, ckRecv) = kdfRoot(rootKey, X25519.computeSharedSecret(dhPriv, remotePub))
        rootKey = rk1
        chainKeyRecv = ckRecv
        dhPriv = X25519.generatePrivateKey()
        dhPub = X25519.publicFromPrivate(dhPriv)
        val (rk2, ckSend) = kdfRoot(rootKey, X25519.computeSharedSecret(dhPriv, remotePub))
        rootKey = rk2
        chainKeySend = ckSend
    }

    private fun storeSkipped(key: SkippedKey, msgKey: ByteArray) {
        skipped[key] = msgKey
        while (skipped.size > MAX_SKIPPED) {
            skipped.remove(skipped.keys.iterator().next())
        }
    }

    override fun snapshot(): RatchetSnapshot = RatchetSnapshot(
        rootKey, chainKeySend, chainKeyRecv, sendCount, recvCount,
        prevChainLen, dhPriv, dhPub, dhRemotePub
    )
}

// ------------------------------------------------------------------ engine

/**
 * Identity, X3DH and signature primitives. Relays only ever see packet
 * envelopes; payloads are Double-Ratchet ciphertext between the endpoints.
 */
object CryptoEngine {

    private const val IDENTITY_FILE = "airchat_identity.bin"

    fun generateIdentity(): IdentityKeys {
        val random = SecureRandom()
        val edSeed = ByteArray(32).also { random.nextBytes(it) }
        val edPub = Ed25519Sign(edSeed).publicKey
        val xPriv = X25519.generatePrivateKey()
        return IdentityKeys(edSeed, edPub, xPriv, X25519.publicFromPrivate(xPriv))
    }

    /**
     * Loads the long-term identity from app-private storage, generating it on
     * first run. Production hardening: move this into EncryptedFile backed by
     * the Android Keystore.
     */
    fun loadOrGenerateIdentity(context: Context): IdentityKeys {
        val file = File(context.filesDir, IDENTITY_FILE)
        if (file.exists()) {
            val bytes = file.readBytes()
            require(bytes.size == 64) { "corrupt identity file" }
            val edSeed = bytes.copyOf(32)
            val xPriv = bytes.copyOfRange(32, 64)
            return IdentityKeys(
                edSeed,
                Ed25519Sign(edSeed).publicKey,
                xPriv,
                X25519.publicFromPrivate(xPriv)
            )
        }
        return generateIdentity().also { id ->
            file.writeBytes(id.edSeed + id.xPriv)
        }
    }

    /** Deterministic node identity: hex(SHA-256(Ed25519 public key)). */
    fun nodeIdFor(edPub: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(edPub)
            .joinToString("") { "%02x".format(it) }

    fun sign(edSeed: ByteArray, data: ByteArray): ByteArray =
        Ed25519Sign(edSeed).sign(data)

    fun verify(edPub: ByteArray, data: ByteArray, signature: ByteArray): Boolean =
        try {
            Ed25519Verify(edPub).verify(signature, data)
            true
        } catch (_: Exception) {
            false
        }

    /** Publish a fresh bundle (call when the QR code / BLE handshake is shown). */
    fun createBundle(identity: IdentityKeys): Pair<PreKeyBundle, PreKeyPrivate> {
        val spPriv = X25519.generatePrivateKey()
        val spPub = X25519.publicFromPrivate(spPriv)
        val otPriv = X25519.generatePrivateKey()
        val bundle = PreKeyBundle(
            ed25519IdentityPub = identity.edPub,
            x25519IdentityPub = identity.xPub,
            signedPreKeyPub = spPub,
            signedPreKeySignature = sign(identity.edSeed, spPub),
            oneTimePreKeyPub = X25519.publicFromPrivate(otPriv)
        )
        return bundle to PreKeyPrivate(spPriv, otPriv)
    }

    /**
     * X3DH initiator side (runs after a QR scan or BLE handshake).
     * Returns the root key seeding the Double Ratchet plus our ephemeral
     * public key, which the responder needs for [x3dhReceive].
     */
    fun x3dhInitiate(ours: IdentityKeys, theirs: PreKeyBundle): X3dhResult {
        if (!verify(theirs.ed25519IdentityPub, theirs.signedPreKeyPub, theirs.signedPreKeySignature)) {
            throw SecurityException("signed pre-key signature verification failed")
        }
        val ephPriv = X25519.generatePrivateKey()
        val ephPub = X25519.publicFromPrivate(ephPriv)
        val dh1 = X25519.computeSharedSecret(ours.xPriv, theirs.signedPreKeyPub)
        val dh2 = X25519.computeSharedSecret(ephPriv, theirs.x25519IdentityPub)
        val dh3 = X25519.computeSharedSecret(ephPriv, theirs.signedPreKeyPub)
        val dh4 = theirs.oneTimePreKeyPub?.let { X25519.computeSharedSecret(ephPriv, it) }
            ?: ByteArray(0)
        val master = dh1 + dh2 + dh3 + dh4
        val rootKey = hkdf(ByteArray(0), master, "AIRCHAT-X3DH-v1".toByteArray(Charsets.UTF_8), 32)
        return X3dhResult(rootKey, ephPub)
    }

    /**
     * X3DH responder side. Mirrors [x3dhInitiate]'s DH sequence so both sides
     * derive the identical root key.
     */
    fun x3dhReceive(
        ours: IdentityKeys,
        oursPriv: PreKeyPrivate,
        initiatorEphPub: ByteArray,
        initiatorIdentityXPub: ByteArray,
        usedOneTimeKey: Boolean
    ): ByteArray {
        val dh1 = X25519.computeSharedSecret(oursPriv.signedPrePriv, initiatorIdentityXPub)
        val dh2 = X25519.computeSharedSecret(ours.xPriv, initiatorEphPub)
        val dh3 = X25519.computeSharedSecret(oursPriv.signedPrePriv, initiatorEphPub)
        val dh4 = if (usedOneTimeKey && oursPriv.oneTimePrePriv != null) {
            X25519.computeSharedSecret(oursPriv.oneTimePrePriv, initiatorEphPub)
        } else ByteArray(0)
        val master = dh1 + dh2 + dh3 + dh4
        return hkdf(ByteArray(0), master, "AIRCHAT-X3DH-v1".toByteArray(Charsets.UTF_8), 32)
    }
}

// ------------------------------------------------------------------ KDF/AEAD

private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

/** RFC 5869 HKDF-SHA256. */
private fun hkdf(salt: ByteArray, ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
    val prk = hmac(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
    val out = ByteArray(length)
    var pos = 0
    var t = ByteArray(0)
    var counter = 1
    while (pos < length) {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(t)
        mac.update(info)
        mac.update(counter.toByte())
        t = mac.doFinal()
        val take = minOf(t.size, length - pos)
        t.copyInto(out, pos, 0, take)
        pos += take
        counter++
    }
    return out
}

/** (newRootKey, newChainKey) = HKDF(rootKey, dhOutput). */
private fun kdfRoot(rootKey: ByteArray, dhOut: ByteArray): Pair<ByteArray, ByteArray> {
    val okm = hkdf(rootKey, dhOut, "AIRCHAT-Root-v1".toByteArray(Charsets.UTF_8), 64)
    return okm.copyOf(32) to okm.copyOfRange(32, 64)
}

/** (messageKey, nextChainKey) = (HMAC(ck, 0x01), HMAC(ck, 0x02)). */
private fun kdfChain(chainKey: ByteArray): Pair<ByteArray, ByteArray> =
    hmac(chainKey, byteArrayOf(0x01)) to hmac(chainKey, byteArrayOf(0x02))

private fun nonceFor(counter: Int): ByteArray =
    ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        .putInt(0)
        .putLong(counter.toLong())
        .array()

private fun headerBytes(h: RatchetHeader): ByteArray =
    ByteBuffer.allocate(40).order(ByteOrder.BIG_ENDIAN)
        .put(h.dhPublicKey) // 32 bytes
        .putInt(h.previousChainLength)
        .putInt(h.messageNumber)
        .array()

private fun aesGcmEncrypt(key: ByteArray, nonce: ByteArray, pt: ByteArray, ad: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
    cipher.updateAAD(ad)
    return cipher.doFinal(pt)
}

private fun aesGcmDecrypt(key: ByteArray, nonce: ByteArray, ct: ByteArray, ad: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
    cipher.updateAAD(ad)
    return cipher.doFinal(ct)
}
