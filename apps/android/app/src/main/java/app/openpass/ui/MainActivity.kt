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
import app.openpass.core.VaultStore

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Block screenshots / screen recording on vault screens.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        val vault = VaultStore(applicationContext)
        setContent {
            MaterialTheme {
                var unlocked by remember { mutableStateOf(false) }
                if (unlocked) VaultScreen(onLock = { vault.lock(); unlocked = false })
                else LockScreen(
                    onPasswordUnlock = { pw -> unlocked = vault.unlockWithMasterPassword(pw) },
                    onBiometricUnlock = { vault.unlockWithBiometrics(this@MainActivity) { ok -> unlocked = ok } },
                )
            }
        }
    }
}

@Composable
fun LockScreen(onPasswordUnlock: (String) -> Boolean, onBiometricUnlock: () -> Unit) {
    var password by remember { mutableStateOf("") }
    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("OpenPass", style = MaterialTheme.typography.headlineMedium)
        OutlinedTextField(password, { password = it }, label = { Text("Master password") }, singleLine = true)
        Button(onClick = { onPasswordUnlock(password) }) { Text("Unlock") }
        OutlinedButton(onClick = onBiometricUnlock) { Text("Unlock with fingerprint / face") }
    }
}

@Composable
fun VaultScreen(onLock: () -> Unit) {
    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Vault", style = MaterialTheme.typography.headlineMedium)
        Text("Phase 2: item list, TOTP codes, sync. Lock to test auto-lock + FLAG_SECURE.")
        Button(onClick = onLock) { Text("Lock") }
    }
}
