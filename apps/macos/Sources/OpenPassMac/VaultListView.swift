import SwiftUI

enum VaultCategory: String, CaseIterable, Identifiable {
    case all = "All Items"
    case login = "Logins"
    case card = "Payment Cards"
    case identity = "Addresses & Identities"
    case secureNote = "Secure Notes"
    case totp = "Authenticator (2FA)"
    case passkey = "Passkeys"
    case file = "Files"

    var id: String { rawValue }
    var icon: String {
        switch self {
        case .all: return "tray.full"
        case .login: return "key"
        case .card: return "creditcard"
        case .identity: return "person.text.rectangle"
        case .secureNote: return "note.text"
        case .totp: return "number.circle"
        case .passkey: return "person.badge.key"
        case .file: return "doc"
        }
    }
    func matches(_ type: String) -> Bool {
        switch self {
        case .all: return true
        case .login: return type == "login"
        case .card: return type == "card"
        case .identity: return type == "identity"
        case .secureNote: return type == "secure_note"
        case .totp: return type == "totp"
        case .passkey: return type == "passkey"
        case .file: return type == "file"
        }
    }
}

struct VaultListView: View {
    @EnvironmentObject var vault: VaultStore
    @State private var category: VaultCategory = .all
    @State private var selectedId: String?
    @State private var search = ""
    @State private var tick = 0 // 1s heartbeat so TOTP codes/countdowns stay live

    private let heartbeat = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private var filtered: [VaultStore.ItemSummary] {
        vault.items.filter { item in
            category.matches(item.type) &&
            (search.isEmpty || item.name.localizedCaseInsensitiveContains(search) || item.username.localizedCaseInsensitiveContains(search))
        }
    }
    private func count(_ cat: VaultCategory) -> Int { vault.items.filter { cat.matches($0.type) }.count }

    var body: some View {
        NavigationSplitView {
            List(selection: $category) {
                Section("Vault") {
                    ForEach(VaultCategory.allCases) { cat in
                        Label {
                            HStack { Text(cat.rawValue); Spacer(); Text("\(count(cat))").foregroundStyle(.secondary) }
                        } icon: { Image(systemName: cat.icon) }
                        .tag(cat)
                    }
                }
            }
            .navigationTitle("OpenPass")
        } content: {
            List(selection: $selectedId) {
                ForEach(filtered) { item in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.name)
                        if !item.username.isEmpty {
                            Text(item.username).font(.caption).foregroundStyle(.secondary)
                        }
                        if item.type == "totp", let t = vault.totp(forItemId: item.id) {
                            Text("\(t.code)  ·  \(t.remaining)s")
                                .font(.system(.body, design: .monospaced)).foregroundStyle(.blue)
                        }
                    }
                    .tag(item.id)
                }
                if filtered.isEmpty {
                    Text("Nothing here yet").foregroundStyle(.secondary)
                }
            }
            .searchable(text: $search, prompt: "Search vault")
            .navigationTitle(category.rawValue)
        } detail: {
            if let id = selectedId, let item = vault.items.first(where: { $0.id == id }) {
                ItemDetailView(item: item)
            } else {
                ContentUnavailableView("Select an item", systemImage: "key",
                                       description: Text("Passwords, cards, notes, addresses, passkeys and 2FA codes decrypt in memory only."))
            }
        }
        .toolbar {
            Button("Refresh") { Task { await vault.refreshItems() } }
            Button("Lock") { vault.lock() }
        }
        .task { await vault.refreshItems() }
        .onReceive(heartbeat) { _ in tick += 1 }
        .frame(minWidth: 900, minHeight: 540)
    }
}

// MARK: - Detail

struct ItemDetailView: View {
    @EnvironmentObject var vault: VaultStore
    let item: VaultStore.ItemSummary
    @State private var reveal = false
    @State private var downloadError: String?

    private var obj: [String: Any]? { vault.decryptItem(id: item.id) }
    private func s(_ key: String) -> String { (obj?[key] as? String) ?? "" }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Image(systemName: icon).font(.title2)
                    Text(item.name).font(.title2).bold()
                    Text(item.type).foregroundStyle(.secondary)
                }
                Divider()
                switch item.type {
                case "login": loginDetail
                case "card": cardDetail
                case "identity": identityDetail
                case "secure_note": noteDetail
                case "totp": totpDetail
                case "passkey": passkeyDetail
                case "file": fileDetail
                default: genericDetail
                }
                if !s("notes").isEmpty {
                    field("Notes", s("notes"))
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var icon: String { VaultCategory.allCases.first { $0.matches(item.type) }?.icon ?? "lock" }

    private var loginDetail: some View {
        VStack(alignment: .leading, spacing: 12) {
            field("Username", s("username"), copyable: true)
            secretField("Password", s("password"))
            if let uris = obj?["uris"] as? [[String: Any]] {
                ForEach(Array(uris.enumerated()), id: \.offset) { _, uri in
                    if let u = uri["uri"] as? String { field("Website", u, copyable: true) }
                }
            }
        }
    }

    private var cardDetail: some View {
        VStack(alignment: .leading, spacing: 12) {
            field("Cardholder", s("cardholder"))
            secretField("Number", s("number"))
            field("Expiry", "\(s("expMonth"))/\(s("expYear"))")
            secretField("CVV", s("cvv"))
            if !s("brand").isEmpty { field("Brand", s("brand")) }
        }
    }

    private var identityDetail: some View {
        VStack(alignment: .leading, spacing: 12) {
            field("Name", "\(s("firstName")) \(s("lastName"))")
            field("Email", s("email"), copyable: true)
            field("Phone", s("phone"))
            field("Address", [s("address1"), s("address2")].filter { !$0.isEmpty }.joined(separator: ", "))
            field("City", s("city")); field("State / Province", s("state"))
            field("Postcode", s("postcode")); field("Country", s("country"))
        }
    }

    private var noteDetail: some View {
        Text(s("content")).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
    }

    private var totpDetail: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let t = vault.totp(forItemId: item.id) {
                Text(t.code).font(.system(size: 40, weight: .semibold, design: .monospaced))
                Text("Refreshes in \(t.remaining)s").foregroundStyle(.secondary)
                Button("Copy code") { copy(t.code) }
            } else {
                Text("Could not generate a code for this item.").foregroundStyle(.red)
            }
            field("Issuer", s("issuer")); field("Account", s("account"))
        }
    }

    private var passkeyDetail: some View {
        VStack(alignment: .leading, spacing: 12) {
            field("Site (RP ID)", s("rpId"), copyable: true)
            field("Username", s("userName"), copyable: true)
            field("Credential ID", s("credentialIdB64"))
            field("Sign count", "\((obj?["counter"] as? NSNumber)?.intValue ?? 0)")
            Text("The private key stays encrypted in your vault and is never displayed. Sign-in happens through the system credential provider.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var fileDetail: some View {
        VStack(alignment: .leading, spacing: 12) {
            field("File name", s("fileName"))
            field("Type", s("mimeType"))
            field("Size", "\((obj?["sizeBytes"] as? NSNumber)?.intValue ?? 0) bytes")
            Button("Download decrypted file…") {
                Task {
                    do {
                        guard let file = try await vault.downloadFile(id: item.id) else {
                            downloadError = "Download failed."; return
                        }
                        let panel = NSSavePanel()
                        panel.nameFieldStringValue = file.name
                        if panel.runModal() == .OK, let url = panel.url {
                            try file.data.write(to: url)
                        }
                    } catch { downloadError = "Download failed: \(error)" }
                }
            }
            if let downloadError { Text(downloadError).foregroundStyle(.red) }
        }
    }

    private var genericDetail: some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach((obj ?? [:]).keys.sorted(), id: \.self) { key in
                if let value = obj?[key] as? String, !value.isEmpty, key != "name", key != "type" {
                    field(key, value)
                }
            }
        }
    }

    // MARK: building blocks

    @ViewBuilder
    private func field(_ label: String, _ value: String, copyable: Bool = false) -> some View {
        if !value.isEmpty {
            HStack(alignment: .top, spacing: 8) {
                Text(label).foregroundStyle(.secondary).frame(width: 130, alignment: .leading)
                Text(value).textSelection(.enabled)
                if copyable {
                    Button { copy(value) } label: { Image(systemName: "doc.on.doc") }
                        .buttonStyle(.borderless)
                }
            }
        }
    }

    @ViewBuilder
    private func secretField(_ label: String, _ value: String) -> some View {
        if !value.isEmpty {
            HStack(alignment: .top, spacing: 8) {
                Text(label).foregroundStyle(.secondary).frame(width: 130, alignment: .leading)
                Text(reveal ? value : String(repeating: "•", count: min(max(value.count, 8), 16)))
                    .font(.system(.body, design: .monospaced))
                Button(reveal ? "Hide" : "Reveal") { reveal.toggle() }.buttonStyle(.borderless)
                Button { copy(value) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
            }
        }
    }

    private func copy(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }
}
