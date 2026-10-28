import SwiftUI

@main
struct OpenPassMacApp: App {
    @StateObject private var vault = VaultStore()

    var body: some Scene {
        WindowGroup {
            Group {
                if vault.isUnlocked {
                    VaultListView()
                } else {
                    LockView()
                }
            }
            .environmentObject(vault)
        }
        MenuBarExtra("OpenPass", systemImage: "lock.shield") {
            Button(vault.isUnlocked ? "Lock" : "Unlock…") {
                if vault.isUnlocked { vault.lock() }
            }
            Divider()
            Button("Quit") { NSApplication.shared.terminate(nil) }
        }
    }
}
