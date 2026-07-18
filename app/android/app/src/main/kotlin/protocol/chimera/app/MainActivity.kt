package protocol.chimera.app

import android.content.Intent
import android.net.VpnService
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private val channelName = "chimera/vpn"
    private val vpnPrepareRequestCode = 0x43
    private var pendingStart: Map<String, Any?>? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName).setMethodCallHandler { call, result ->
            when (call.method) {
                "isPrepared" -> result.success(VpnService.prepare(this) == null)
                "status" -> result.success(ChimeraVpnService.currentStatusJson())
                "start" -> {
                    val args = call.arguments as? Map<String, Any?> ?: emptyMap()
                    val consent = VpnService.prepare(this)
                    if (consent != null) {
                        
                        
                        
                        pendingStart = args
                        startActivityForResult(consent, vpnPrepareRequestCode)
                    } else {
                        startVpnService(args)
                    }
                    result.success(null)
                }
                "stop" -> {
                    startService(Intent(this, ChimeraVpnService::class.java).setAction(ChimeraVpnService.ACTION_STOP))
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnPrepareRequestCode && resultCode == RESULT_OK) {
            pendingStart?.let { startVpnService(it) }
        }
        pendingStart = null
    }

    private fun startVpnService(args: Map<String, Any?>) {
        val intent = Intent(this, ChimeraVpnService::class.java).setAction(ChimeraVpnService.ACTION_START)
        intent.putExtra(ChimeraVpnService.EXTRA_SERVER, args["server"] as? String ?: "")
        intent.putExtra(ChimeraVpnService.EXTRA_PBK, args["pbk"] as? String ?: "")
        intent.putExtra(ChimeraVpnService.EXTRA_MODE, args["mode"] as? String ?: "dnsLeakGuard")
        intent.putExtra(ChimeraVpnService.EXTRA_SNI, args["sni"] as? String ?: "")
        intent.putExtra(ChimeraVpnService.EXTRA_SID, args["sid"] as? String ?: "")
        intent.putExtra(ChimeraVpnService.EXTRA_TRANSPORT, args["transport"] as? String ?: "")
        intent.putExtra(ChimeraVpnService.EXTRA_TOKEN, args["token"] as? String ?: "")
        @Suppress("UNCHECKED_CAST")
        val dns = (args["dns"] as? List<String>)?.let { ArrayList(it) } ?: arrayListOf("1.1.1.1", "8.8.8.8")
        intent.putStringArrayListExtra(ChimeraVpnService.EXTRA_DNS, dns)
        startForegroundService(intent)
    }
}
