import SwiftUI

struct VaultListView: View {
    @EnvironmentObject var vault: VaultStore
    @State private var selectedId: String?
    @State private var search = ""

    private var filtered: [VaultStore.ItemSummary] {
        vault.items.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.username.localizedCaseInsensitiveContains(search) }
    }
    private var selected: VaultStore.ItemSummary? { vault.items.first { $0.id == selectedId } }

    var body: some View {
        NavigationSplitView {
            List(selection: $selectedId) {
                Section("Vault") {
                    ForEach(filtered) { item in
                        Label(item.name, systemImage: icon(for: item.type))
                            .tag(item.id)
                    }
                }
                if filtered.isEmpty {
                    Text("No items").foregroundStyle(.secondary)
                }
            }
            .searchable(text: $search)
            .navigationTitle("OpenPass")
        } detail: {
            if let selected {
                VStack(alignment: .leading, spacing: 12) {
                    Text(selected.name).font(.title2).bold()
                    Text(selected.type).foregroundStyle(.secondary)
                    if !selected.username.isEmpty { Text("Username: \(selected.username)") }
                    Text("Full details decrypt on demand via OpenPassCrypto in the item view (next iteration).")
                        .foregroundStyle(.secondary)
                }
                .padding()
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            } else {
                ContentUnavailableView("Select an item", systemImage: "key",
                                       description: Text("Items are decrypted in memory only."))
            }
        }
        .toolbar {
            Button("Refresh") { Task { await vault.refreshItems() } }
            Button("Lock") { vault.lock() }
        }
        .task { await vault.refreshItems() }
        .frame(minWidth: 720, minHeight: 480)
    }

    private func icon(for type: String) -> String {
        switch type {
        case "login": return "key"
        case "card": return "creditcard"
        case "identity": return "person.text.rectangle"
        case "secure_note": return "note.text"
        case "totp": return "number.circle"
        case "passkey": return "person.badge.key"
        case "file": return "doc"
        default: return "lock"
        }
    }
}
