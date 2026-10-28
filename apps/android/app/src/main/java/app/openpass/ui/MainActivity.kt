package app.openpass.ui

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.clickable
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

// FragmentActivity (not plain ComponentActivity) because BiometricPrompt requires it.
class MainActivity : FragmentActivity() {
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
                if (unlocked) VaultScreen(
                    onLock = { vault.lock(); unlocked = false },
                    loadItems = { done ->
                        io.execute {
                            val result = runCatching {
                                val key = vault.currentVaultKey() ?: error("locked")
                                val token = vault.accessToken ?: error("no session")
                                app.openpass.core.ItemRepository(UrlConnectionVaultClient(SERVER_URL)).listSummaries(token, key)
                            }
                            runOnUiThread { done(result) }
                        }
                    },
                )
                else LockScreen(
                    onLogin = { email, password, done ->
                        io.execute {
                            val ok = runCatching { auth.login(email, password, android.os.Build.MODEL ?: "Android") }
                                .map { session ->
                                    vault.accessToken = session.accessToken
                                    vault.unlockWithMasterKey { session.vaultKey }
                                }
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
fun VaultScreen(onLock: () -> Unit, loadItems: ((Result<List<app.openpass.core.VaultItemSummary>>) -> Unit) -> Unit) {
    var summaries by remember { mutableStateOf<List<app.openpass.core.VaultItemSummary>>(emptyList()) }
    var error by remember { mutableStateOf("") }
    var search by remember { mutableStateOf("") }
    var selected by remember { mutableStateOf<app.openpass.core.VaultItemSummary?>(null) }
    var reveal by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        loadItems { result ->
            result.onSuccess { summaries = it }.onFailure { error = it.message ?: "load failed" }
        }
    }
    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Vault", style = MaterialTheme.typography.headlineMedium)
        OutlinedTextField(search, { search = it }, label = { Text("Search") }, singleLine = true)
        if (error.isNotEmpty()) Text(error, color = MaterialTheme.colorScheme.error)
        summaries.filter { search.isEmpty() || it.name.contains(search, true) || it.username.contains(search, true) }
            .forEach { item ->
                Column(Modifier.clickable { selected = item; reveal = false }) {
                    Text(item.name, style = MaterialTheme.typography.titleMedium)
                    Text("${item.type}${if (item.username.isNotEmpty()) " — ${item.username}" else ""}",
                        style = MaterialTheme.typography.bodySmall)
                }
            }
        selected?.let { item ->
            val p = item.plaintext
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(item.name, style = MaterialTheme.typography.titleLarge)
                if (item.type == "login") {
                    Text("Username: ${p.optString("username")}")
                    Text("Password: ${if (reveal) p.optString("password") else "••••••••"}")
                    OutlinedButton(onClick = { reveal = !reveal }) { Text(if (reveal) "Hide" else "Reveal") }
                    val uris = p.optJSONArray("uris")
                    if (uris != null && uris.length() > 0) Text("URL: ${uris.getJSONObject(0).optString("uri")}")
                }
                if (item.type == "secure_note") Text(p.optString("content"))
                if (item.type == "card") Text("Card: •••• ${p.optString("number").takeLast(4)}")
                if (item.type == "totp") Text("Authenticator code is generated in the TOTP screen (Rust core).")
                OutlinedButton(onClick = { selected = null }) { Text("Close") }
            }
        }
        if (summaries.isEmpty() && error.isEmpty()) Text("No items yet (create them in the web vault).")
        Button(onClick = onLock) { Text("Lock") }
    }
}
