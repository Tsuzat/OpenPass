import SwiftUI

struct LockView: View {
    @EnvironmentObject var vault: VaultStore
    @State private var password = ""
    @State private var error: String?
    @State private var mode: Mode = .login
    enum Mode { case login, register }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield").font(.system(size: 48))
            Text("OpenPass").font(.title).bold()

            Picker("", selection: $mode) {
                Text("Log in").tag(Mode.login)
                Text("Create account").tag(Mode.register)
            }
            .pickerStyle(.segmented)
            .frame(maxWidth: 320)

            TextField("Email", text: $vault.email)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
            SecureField("Master password", text: $password)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)

            Button(mode == .login ? "Unlock" : "Create vault") {
                Task {
                    do {
                        if mode == .login {
                            try await vault.unlockWithMasterPassword(password)
                        } else {
                            try await vault.register(email: vault.email, password: password)
                        }
                        password = ""
                    } catch { self.error = "\(error)" }
                }
            }
            .keyboardShortcut(.defaultAction)

            if mode == .login && vault.biometricsAvailable {
                Button("Unlock with Touch ID") {
                    Task {
                        do { try await vault.unlockWithBiometrics() }
                        catch { self.error = "\(error)" }
                    }
                }
            }
            if let error { Text(error).foregroundStyle(.red).font(.caption).frame(maxWidth: 360) }
            TextField("Server URL", text: $vault.serverURL)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
                .font(.caption)
            if mode == .register {
                Text("Your master password never leaves this device. There is no email reset — you will get a Recovery Key to save.")
                    .font(.caption).foregroundStyle(.secondary).frame(maxWidth: 340)
            }
        }
        .padding(40)
        .frame(minWidth: 460, minHeight: 380)
        .sheet(item: Binding(
            get: { vault.recoveryKeyToShow.map { RecoveryKeyHolder(text: $0) } },
            set: { if $0 == nil { vault.recoveryKeyToShow = nil } }
        )) { holder in
            VStack(spacing: 16) {
                Text("Save your Recovery Key").font(.title2).bold()
                Text("Shown once. It is the ONLY way back in if you forget your master password.")
                    .foregroundStyle(.secondary)
                Text(holder.text)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .padding()
                    .background(.quaternary)
                Button("I saved it") { vault.recoveryKeyToShow = nil }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(32)
            .frame(minWidth: 520)
        }
    }
}

private struct RecoveryKeyHolder: Identifiable {
    let text: String
    var id: String { text }
}
