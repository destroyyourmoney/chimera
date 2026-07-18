package protocol.chimera.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import chimeramobile.Tunnel
import java.net.URLEncoder

class ChimeraVpnService : VpnService() {
    companion object {
        private const val TAG = "ChimeraVpnService"
        private const val NOTIFICATION_CHANNEL_ID = "chimera_vpn"
        private const val NOTIFICATION_ID = 1

        const val ACTION_START = "protocol.chimera.app.START"
        const val ACTION_STOP = "protocol.chimera.app.STOP"

        const val EXTRA_SERVER = "server"
        const val EXTRA_PBK = "pbk"
        const val EXTRA_MODE = "mode"
        const val EXTRA_SNI = "sni"
        const val EXTRA_SID = "sid"
        const val EXTRA_TRANSPORT = "transport"
        const val EXTRA_TOKEN = "token"
        const val EXTRA_DNS = "dns"

        @Volatile
        var isRunning: Boolean = false
            private set

        
        
        
        @Volatile
        private var activeTunnel: GoTunnel? = null

        
        fun currentStatusJson(): String =
            activeTunnel?.stateJSON() ?: """{"state":"disconnected","transport":"","bytesUp":0,"bytesDown":0}"""
    }

    private var tunInterface: ParcelFileDescriptor? = null
    private var goTunnel: GoTunnel = RealGoTunnel()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val server = intent.getStringExtra(EXTRA_SERVER) ?: ""
                val pbk = intent.getStringExtra(EXTRA_PBK) ?: ""
                val mode = intent.getStringExtra(EXTRA_MODE) ?: "dnsLeakGuard"
                val sni = intent.getStringExtra(EXTRA_SNI) ?: ""
                val sid = intent.getStringExtra(EXTRA_SID) ?: ""
                val transport = intent.getStringExtra(EXTRA_TRANSPORT) ?: ""
                val token = intent.getStringExtra(EXTRA_TOKEN) ?: ""
                val dns = intent.getStringArrayListExtra(EXTRA_DNS) ?: arrayListOf("1.1.1.1", "8.8.8.8")
                startTunnel(server, pbk, mode, sni, sid, transport, token, dns)
            }
        }
        return START_STICKY
    }

    private fun startTunnel(
        server: String,
        pbk: String,
        mode: String,
        sni: String,
        sid: String,
        transport: String,
        token: String,
        dns: List<String>,
    ) {
        startForeground(NOTIFICATION_ID, buildNotification())

        val builder = Builder()
            .setSession("CHIMERA")
            .setMtu(1500)
            .addAddress("10.89.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addAddress("fd7a:1157:6d69:6d65:7261::2", 128)
            .addRoute("::", 0)
        for (server in dns) builder.addDnsServer(server)

        tunInterface?.close()
        tunInterface = builder.establish()
        val fd = tunInterface
        if (fd == null) {
            Log.e(TAG, "VpnService.Builder.establish() returned null (permission not granted?)")
            stopSelf()
            return
        }

        Log.i(TAG, "TUN established (fd=${fd.fd}), handing off to GoTunnel (server=$server, mode=$mode, transport=$transport)")
        activeTunnel = goTunnel
        isRunning = true
        goTunnel.start(fd.fd, 1500, server, pbk, mode, sni, sid, transport, token) { error ->
            Log.e(TAG, "GoTunnel failed: $error")
            stopTunnel()
        }
    }

    private fun stopTunnel() {
        goTunnel.stop()
        tunInterface?.close()
        tunInterface = null
        isRunning = false
        activeTunnel = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID, "CHIMERA VPN", NotificationManager.IMPORTANCE_LOW,
            )
            nm.createNotificationChannel(channel)
        }
        val stopIntent = Intent(this, ChimeraVpnService::class.java).setAction(ACTION_STOP)
        val stopPending = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("CHIMERA")
            .setContentText("Protected")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .addAction(Notification.Action.Builder(null, "Disconnect", stopPending).build())
            .setOngoing(true)
            .build()
    }

    override fun onRevoke() {
        
        
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }
}

interface GoTunnel {
    
    fun start(
        fd: Int, mtu: Int, server: String, pbk: String, mode: String,
        sni: String, sid: String, transport: String, token: String,
        onFailure: (String) -> Unit,
    )
    fun stop()

    
    fun stateJSON(): String
}

internal fun buildChimeraLink(
    server: String, pbk: String, sni: String, sid: String, transport: String, token: String,
): String {
    fun enc(s: String) = URLEncoder.encode(s, "UTF-8")
    val query = buildList {
        add("pbk=${enc(pbk)}")
        if (sid.isNotEmpty()) add("sid=${enc(sid)}")
        if (sni.isNotEmpty()) add("sni=${enc(sni)}")
        if (transport.isNotEmpty()) add("mode=${enc(transport)}")
        if (token.isNotEmpty()) add("tok=${enc(token)}")
    }.joinToString("&")
    return "chimera://$server?$query"
}

class RealGoTunnel : GoTunnel {
    private var tunnel: Tunnel? = null
    private var runner: Thread? = null

    
    
    
    
    override fun start(
        fd: Int, mtu: Int, server: String, pbk: String, mode: String,
        sni: String, sid: String, transport: String, token: String,
        onFailure: (String) -> Unit,
    ) {
        val link = buildChimeraLink(server, pbk, sni, sid, transport, token)
        runner = Thread({
            try {
                val t = Tunnel(link)
                tunnel = t
                t.connect()
                t.startFD(fd.toLong(), mtu.toLong())
            } catch (e: Exception) {
                Log.w("ChimeraVpnService", "GoTunnel ended", e)
                onFailure(e.message ?: e.toString())
            }
        }, "chimera-go-tunnel").also { it.start() }
    }

    override fun stop() {
        tunnel?.stop()
        runner?.join(2000)
        tunnel = null
        runner = null
    }

    override fun stateJSON(): String =
        tunnel?.stateJSON() ?: """{"state":"disconnected","transport":"","bytesUp":0,"bytesDown":0}"""
}
