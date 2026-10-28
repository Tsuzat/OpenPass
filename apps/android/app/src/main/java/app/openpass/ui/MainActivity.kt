package app.openpass.ui

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import app.openpass.core.AuthRepository
import app.openpass.core.UrlConnectionVaultClient
import app.openpass.core.VaultStore
import java.util.concurrent.Executors

// Configure your self-hosted Worker URL here (in-app settings screen lands later).
private const val SERVER_URL = "https://your-worker.example.com"

class MainActivity : ComponentActivity() {
    private val io = Executors.newSingleThreadExecutor()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        val vault = VaultStore(applicationContext)
        val prefs = getSharedPreferences("openpass-device", MODE_PRIVATE)
        val auth = AuthRepository(UrlConnectionVaultClient(SERVER_URL), AuthRepository.deviceIdProvider(prefs))

        setContent {
            MaterialTheme {
                var unlocked by remember { mutableStateOf(false) }
                if (unlocked) VaultScreen(onLock = { vault.lock(); unlocked = false })
                else LockScreen(
                    onLogin = { email, password, done ->
                        io.execute {
                            val ok = runCatching { auth.login(email, password, android.os.Build.MODEL ?: "Android") }
                                .map { session -> vault.unlockWithMasterKey { session.vaultKey } }
                                .getOrDefault(false)
                            runOnUiThread { done(ok) }
                        }
                    },
                    onBiometricUnlock = { vault.unlockWithBiometrics(this@MainActivity) { ok -> unlocked = ok } },
                )
            }
        }
    }
}

@Composable
fun LockScreen(onLogin: (String, String, (Boolean) -> Unit) -> Unit, onBiometricUnlock: () -> Unit) {
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("OpenPass", style = MaterialTheme.typography.headlineMedium)
        OutlinedTextField(email, { email = it }, label = { Text("Email") }, singleLine = true)
        OutlinedTextField(password, { password = it }, label = { Text("Master password") }, singleLine = true)
        Button(enabled = !busy && email.isNotBlank() && password.isNotBlank(), onClick = {
            busy = true; message = ""
            onLogin(email, password) { ok -> busy = false; if (!ok) message = "Login failed — check credentials or approve this device from another device." }
        }) { Text(if (busy) "Unlocking…" else "Unlock") }
        OutlinedButton(onClick = onBiometricUnlock) { Text("Unlock with fingerprint / face") }
        if (message.isNotEmpty()) Text(message, color = MaterialTheme.colorScheme.error)
        Text("Server: $SERVER_URL", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
fun VaultScreen(onLock: () -> Unit) {
    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Vault", style = MaterialTheme.typography.headlineMedium)
        Text("Unlocked. Item list decrypts via OpenPassCrypto + SyncEngine (repository wiring next).")
        Button(onClick = onLock) { Text("Lock") }
    }
}
