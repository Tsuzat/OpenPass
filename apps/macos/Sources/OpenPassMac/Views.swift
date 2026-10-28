import SwiftUI

struct LockView: View {
    @EnvironmentObject var vault: VaultStore
    @State private var password = ""
    @State private var error: String?

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield").font(.system(size: 48))
            Text("OpenPass").font(.title).bold()
            TextField("Email", text: $vault.email)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
            SecureField("Master password", text: $password)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
            Button("Unlock") {
                Task {
                    do { try await vault.unlockWithMasterPassword(password); password = "" }
                    catch { self.error = error.localizedDescription }
                }
            }.keyboardShortcut(.defaultAction)
            if vault.biometricsAvailable {
                Button("Unlock with Touch ID") {
                    Task {
                        do { try await vault.unlockWithBiometrics() }
                        catch { self.error = error.localizedDescription }
                    }
                }
            }
            if let error { Text(error).foregroundStyle(.red).font(.caption) }
            Text("Server: \(vault.serverURL)").font(.caption).foregroundStyle(.secondary)
        }
        .padding(40)
        .frame(minWidth: 420, minHeight: 320)
    }
}
