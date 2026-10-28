import SwiftUI

struct LockView: View {
    @EnvironmentObject var vault: VaultStore
    @State private var password = ""
    @State private var error: String?
    @State private var mode: Mode = .login
    @State private var busy = false
    enum Mode { case login, register }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield").font(.system(size: 48))
            Text("OpenPass").font(.title).bold()

            // Server first: most sign-in failures are a wrong/unreachable URL.
            VStack(alignment: .leading, spacing: 6) {
                Text("Your OpenPass server").font(.caption).foregroundStyle(.secondary)
                HStack(spacing: 8) {
                    TextField("https://openpass-api.…workers.dev", text: $vault.serverURL)
                        .textFieldStyle(.roundedBorder)
                    Circle()
                        .fill(vault.serverReachable == nil ? Color.gray : (vault.serverReachable! ? Color.green : Color.red))
                        .frame(width: 9, height: 9)
                    Button("Check") { Task { await vault.checkServer() } }
                }
                Text(vault.serverReachable == nil ? "Enter the Worker URL you deployed, then Check."
                     : vault.serverReachable! ? "Server reachable." : "Server unreachable — check the URL.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: 380)

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

            Button(busy ? "Working…" : (mode == .login ? "Unlock" : "Create vault")) {
                Task {
                    busy = true; error = nil
                    do {
                        if mode == .login {
                            try await vault.unlockWithMasterPassword(password)
                        } else {
                            try await vault.register(email: vault.email, password: password)
                        }
                        password = ""
                    } catch { self.error = vault.friendlyMessage(for: error) }
                    busy = false
                }
            }
            .keyboardShortcut(.defaultAction)
            .disabled(busy || vault.email.isEmpty || password.count < 8)

            if mode == .login && vault.biometricsAvailable {
                Button("Unlock with Touch ID") {
                    Task {
                        do { try await vault.unlockWithBiometrics() }
                        catch { self.error = vault.friendlyMessage(for: error) }
                    }
                }
            }
            if let error {
                Text(error).foregroundStyle(.red).font(.callout)
                    .frame(maxWidth: 400).multilineTextAlignment(.center)
            }
            if mode == .register {
                Text("Your master password never leaves this device. There is no email reset — you will get a Recovery Key to save.")
                    .font(.caption).foregroundStyle(.secondary).frame(maxWidth: 340)
                    .multilineTextAlignment(.center)
            }
        }
        .padding(40)
        .frame(minWidth: 500, minHeight: 460)
        .task { await vault.checkServer() }
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
