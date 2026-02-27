package rw.qtopie.vlink

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.view.MenuItem
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.Toolbar
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.graphics.Insets
import com.github.shadowsocks.plugin.ConfigurationActivity
import com.github.shadowsocks.plugin.PluginOptions
import androidx.activity.result.contract.ActivityResultContracts

class MainActivity : ConfigurationActivity(), Toolbar.OnMenuItemClickListener {
    private val child by lazy { supportFragmentManager.findFragmentById(R.id.content) as ConfigFragment }
    private var oldOptions: PluginOptions = PluginOptions()
    private var isVpnRunning = false

    private lateinit var btnStart: Button
    private lateinit var btnStop: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvDownSpeed: TextView
    private lateinit var tvUpSpeed: TextView

    private val statsReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val downSpeed = intent?.getStringExtra(VlinkVpnService.EXTRA_SPEED_DOWN) ?: "0 B/s"
            val upSpeed = intent?.getStringExtra(VlinkVpnService.EXTRA_SPEED_UP) ?: "0 B/s"
            val running = intent?.getBooleanExtra(VlinkVpnService.EXTRA_STATE, false) ?: false
            updateState(running, downSpeed, upSpeed)
        }
    }

    private val vpnLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startService(Intent(this, VlinkVpnService::class.java).setAction(VlinkVpnService.ACTION_START))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnStart = findViewById(R.id.btn_start)
        btnStop = findViewById(R.id.btn_stop)
        tvStatus = findViewById(R.id.tv_status)
        tvDownSpeed = findViewById(R.id.tv_down_speed)
        tvUpSpeed = findViewById(R.id.tv_up_speed)

        // Load persisted options
        val savedOptions = Settings.getOptions(this)
        onInitializePluginOptions(savedOptions)
        oldOptions = savedOptions

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { view, insets ->
            val statusBarInsets = insets.getInsets(WindowInsetsCompat.Type.statusBars())
            view.setPadding(statusBarInsets.left, statusBarInsets.top, statusBarInsets.right, statusBarInsets.bottom)
            WindowInsetsCompat.Builder(insets).apply {
                setInsets(WindowInsetsCompat.Type.statusBars(), Insets.NONE)
            }.build()
        }
        WindowCompat.setDecorFitsSystemWindows(window, false)
        findViewById<Toolbar>(com.github.shadowsocks.plugin.R.id.toolbar).apply {
            title = this@MainActivity.title
            setNavigationIcon(com.github.shadowsocks.plugin.R.drawable.ic_navigation_close)
            setNavigationOnClickListener { onBackPressed() }
            inflateMenu(R.menu.toolbar_config)
            setOnMenuItemClickListener(this@MainActivity)
        }

        btnStart.setOnClickListener { 
            doSave() // Save before starting
            startVpn() 
        }
        btnStop.setOnClickListener { stopVpn() }
        findViewById<Button>(R.id.btn_troubleshoot).setOnClickListener { troubleshoot() }
        
        registerReceiver(statsReceiver, IntentFilter(VlinkVpnService.BROADCAST_STATS), RECEIVER_EXPORTED)
    }

    private fun updateState(running: Boolean, downSpeed: String = "0 B/s", upSpeed: String = "0 B/s") {
        isVpnRunning = running
        btnStart.isEnabled = !running
        btnStop.isEnabled = running
        child.setEditable(!running)
        
        tvStatus.text = if (running) "Status: Connected" else "Status: Disconnected"
        tvDownSpeed.text = if (running) "↓ $downSpeed" else "↓ 0 B/s"
        tvUpSpeed.text = if (running) "↑ $upSpeed" else "↑ 0 B/s"
    }

    override fun onDestroy() {
        unregisterReceiver(statsReceiver)
        super.onDestroy()
    }

    private fun startVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnLauncher.launch(intent) // Use the new Activity Result API launcher
        } else {
            startService(Intent(this, VlinkVpnService::class.java).setAction(VlinkVpnService.ACTION_START))
        }
    }

    private fun stopVpn() {
        startService(Intent(this, VlinkVpnService::class.java).setAction(VlinkVpnService.ACTION_STOP))
    }

    private fun troubleshoot() {
        val progressDialog = AlertDialog.Builder(this)
            .setTitle("Diagnostics")
            .setMessage("Running checks...")
            .setCancelable(false)
            .show()

        Thread {
            val troubleshooter = Troubleshooter(this)
            val results = troubleshooter.runDiagnostics()
            
            val message = results.joinToString("\n\n") { result ->
                "[${result.status}] ${result.title}\n${result.message}"
            }

            runOnUiThread {
                progressDialog.dismiss()
                AlertDialog.Builder(this)
                    .setTitle("Diagnostic Results")
                    .setMessage(message)
                    .setPositiveButton("OK", null)
                    .show()
            }
        }.start()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (resultCode == RESULT_OK) {
            startService(Intent(this, VlinkVpnService::class.java).setAction(VlinkVpnService.ACTION_START))
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    override fun onInitializePluginOptions(options: PluginOptions) {
        oldOptions = options
        child.onInitializePluginOptions(options)
    }

    private fun doSave() {
        val newOptions = child.options
        Settings.saveOptions(this, newOptions)
        oldOptions = newOptions
        saveChanges(newOptions)
    }

    override fun onMenuItemClick(item: MenuItem?) = when (item?.itemId) {
        R.id.action_apply -> {
            if (isVpnRunning) {
                Toast.makeText(this, "Cannot modify config while running", Toast.LENGTH_SHORT).show()
            } else {
                doSave()
                Toast.makeText(this, "Configuration saved", Toast.LENGTH_SHORT).show()
            }
            true
        }
        else -> false
    }

    override fun onBackPressed() {
        if (!isVpnRunning && child.options != oldOptions) AlertDialog.Builder(this).run {
            setTitle(com.github.shadowsocks.plugin.R.string.unsaved_changes_prompt)
            setPositiveButton(com.github.shadowsocks.plugin.R.string.yes) { _, _ ->
                doSave()
                finish()
            }
            setNegativeButton(com.github.shadowsocks.plugin.R.string.no) { _, _ -> finish() }
            setNeutralButton(android.R.string.cancel, null)
            create()
        }.show() else finish()
    }
}
