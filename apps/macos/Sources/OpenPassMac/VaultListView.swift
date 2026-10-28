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
                    if let details = vault.decryptDetails(id: selected.id) {
                        ForEach(details.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                            if !value.isEmpty && key != "name" {
                                HStack(alignment: .top) {
                                    Text(key).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
                                    Text(key == "password" || key == "cvv" ? String(repeating: "•", count: min(value.count, 12)) : value)
                                        .textSelection(.enabled)
                                }
                            }
                        }
                        Text("Sensitive fields are masked in this summary. Reveal/copy actions arrive with the secure detail editor.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("Could not decrypt this item.").foregroundStyle(.red)
                    }
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
