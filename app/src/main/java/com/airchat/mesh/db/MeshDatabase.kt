package com.airchat.mesh.db

import android.content.Context
import android.util.Base64
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters

/**
 * Rejoin sync protocol (runs over the best available transport once a peer is
 * discovered):
 *
 * 1. HELLO  { nodeId, maxLamportClock, bloomFilter(messageIds) }
 * 2. NEED   { missingIds[] } — computed from the Bloom filter + clock delta
 * 3. DATA   — missing messages streamed (512-byte frames on BLE)
 * 4. ACK    — per-message delivery receipts; store-and-forward entries dequeued
 *
 * Conflict resolution: last-writer-wins on the lexicographic
 * (timestamp, nodeId) pair; lamportClock = max(seen) + 1 on receive keeps
 * causal ordering without any central clock.
 */
object MeshSyncProtocol {
    const val STATUS_QUEUED = 0
    const val STATUS_SENT = 1
    const val STATUS_STORED_FOR_FORWARD = 2
    const val STATUS_DELIVERED = 3
    const val STATUS_READ = 4

    const val STORE_FORWARD_TTL_MS = 24 * 60 * 60 * 1000L
    const val BLE_FRAME_BYTES = 512
}

/** Peer device, keyed by hex(SHA-256(Ed25519 public key)). No phone numbers. */
@Entity(tableName = "nodes")
class NodeEntity(
    @PrimaryKey val nodeId: String,
    val ed25519Pub: ByteArray,
    val x25519Pub: ByteArray,
    val displayNameEncrypted: ByteArray,
    val lastSeen: Long,
    val transportHint: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is NodeEntity) return false
        return nodeId == other.nodeId &&
            ed25519Pub.contentEquals(other.ed25519Pub) &&
            x25519Pub.contentEquals(other.x25519Pub) &&
            displayNameEncrypted.contentEquals(other.displayNameEncrypted) &&
            lastSeen == other.lastSeen &&
            transportHint == other.transportHint
    }

    override fun hashCode(): Int {
        var r = nodeId.hashCode()
        r = 31 * r + ed25519Pub.contentHashCode()
        r = 31 * r + x25519Pub.contentHashCode()
        r = 31 * r + displayNameEncrypted.contentHashCode()
        r = 31 * r + lastSeen.hashCode()
        r = 31 * r + transportHint.hashCode()
        return r
    }
}

/** One chat message; [ciphertext] is Double-Ratchet output. */
@Entity(tableName = "messages")
class MessageEntity(
    @PrimaryKey val msgId: String,
    val senderId: String,
    val recipientId: String,
    val ciphertext: ByteArray,
    val ratchetHeader: ByteArray, // serialised RatchetHeader (40 bytes)
    val timestamp: Long,
    val lamportClock: Long,
    val status: Int // see MeshSyncProtocol.STATUS_*
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MessageEntity) return false
        return msgId == other.msgId &&
            senderId == other.senderId &&
            recipientId == other.recipientId &&
            ciphertext.contentEquals(other.ciphertext) &&
            ratchetHeader.contentEquals(other.ratchetHeader) &&
            timestamp == other.timestamp &&
            lamportClock == other.lamportClock &&
            status == other.status
    }

    override fun hashCode(): Int {
        var r = msgId.hashCode()
        r = 31 * r + senderId.hashCode()
        r = 31 * r + recipientId.hashCode()
        r = 31 * r + ciphertext.contentHashCode()
        r = 31 * r + ratchetHeader.contentHashCode()
        r = 31 * r + timestamp.hashCode()
        r = 31 * r + lamportClock.hashCode()
        r = 31 * r + status
        return r
    }
}

/** Persisted Double-Ratchet session state per peer; mirrors RatchetSnapshot. */
@Entity(tableName = "ratchet_states")
class RatchetStateEntity(
    @PrimaryKey val peerId: String,
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
        if (other !is RatchetStateEntity) return false
        return peerId == other.peerId &&
            rootKey.contentEquals(other.rootKey) &&
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
        var r = peerId.hashCode()
        r = 31 * r + rootKey.contentHashCode()
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

/**
 * Store-and-forward: encrypted packets held by intermediate nodes for peers
 * that are currently out of radio range. Relays cannot read the payload —
 * only the envelope (destination, expiry).
 */
@Entity(tableName = "store_forward")
class StoreForwardEntity(
    @PrimaryKey val packetId: String,
    val destId: String,
    val rawPacket: ByteArray,
    val expiresAt: Long,
    val attempts: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is StoreForwardEntity) return false
        return packetId == other.packetId &&
            destId == other.destId &&
            rawPacket.contentEquals(other.rawPacket) &&
            expiresAt == other.expiresAt &&
            attempts == other.attempts
    }

    override fun hashCode(): Int {
        var r = packetId.hashCode()
        r = 31 * r + destId.hashCode()
        r = 31 * r + rawPacket.contentHashCode()
        r = 31 * r + expiresAt.hashCode()
        r = 31 * r + attempts
        return r
    }
}

class Converters {
    @TypeConverter
    fun fromBytes(bytes: ByteArray?): String? =
        bytes?.let { Base64.encodeToString(it, Base64.NO_WRAP) }

    @TypeConverter
    fun toBytes(encoded: String?): ByteArray? =
        encoded?.let { Base64.decode(it, Base64.NO_WRAP) }
}

@Dao
interface NodeDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertNode(node: NodeEntity)

    @Query("SELECT * FROM nodes WHERE nodeId = :id")
    suspend fun getNode(id: String): NodeEntity?

    @Query("SELECT * FROM nodes ORDER BY lastSeen DESC")
    suspend fun allNodes(): List<NodeEntity>
}

@Dao
interface MessageDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertMessage(message: MessageEntity)

    @Query(
        "SELECT * FROM messages WHERE " +
            "(senderId = :peer AND recipientId = :self) OR " +
            "(senderId = :self AND recipientId = :peer) " +
            "ORDER BY lamportClock ASC"
    )
    suspend fun conversation(self: String, peer: String): List<MessageEntity>

    @Query("SELECT * FROM messages WHERE recipientId = :nodeId AND status = :status LIMIT 50")
    suspend fun pendingFor(nodeId: String, status: Int): List<MessageEntity>

    @Query("SELECT MAX(lamportClock) FROM messages")
    suspend fun maxClock(): Long?

    @Query("UPDATE messages SET status = :status WHERE msgId = :id")
    suspend fun setStatus(id: String, status: Int)
}

@Dao
interface RatchetDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun save(state: RatchetStateEntity)

    @Query("SELECT * FROM ratchet_states WHERE peerId = :peer")
    suspend fun load(peer: String): RatchetStateEntity?
}

@Dao
interface StoreForwardDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun enqueue(entry: StoreForwardEntity)

    @Query("SELECT * FROM store_forward WHERE destId = :dest AND expiresAt > :now ORDER BY expiresAt ASC")
    suspend fun forDestination(dest: String, now: Long): List<StoreForwardEntity>

    @Query("DELETE FROM store_forward WHERE packetId = :id")
    suspend fun dequeue(id: String)

    @Query("DELETE FROM store_forward WHERE expiresAt <= :now")
    suspend fun purgeExpired(now: Long)
}

@Database(
    entities = [
        NodeEntity::class,
        MessageEntity::class,
        RatchetStateEntity::class,
        StoreForwardEntity::class
    ],
    version = 1,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class MeshDatabase : RoomDatabase() {
    abstract fun nodeDao(): NodeDao
    abstract fun messageDao(): MessageDao
    abstract fun ratchetDao(): RatchetDao
    abstract fun storeForwardDao(): StoreForwardDao

    companion object {
        @Volatile
        private var INSTANCE: MeshDatabase? = null

        fun get(context: Context): MeshDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    MeshDatabase::class.java,
                    "airchat.db"
                ).build().also { INSTANCE = it }
            }
    }
}
