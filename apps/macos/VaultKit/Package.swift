// swift-tools-version: 5.9
import PackageDescription

// Local encrypted-vault storage + sync engine. Pure Foundation (no SwiftUI),
// so it builds and tests without Xcode. Items are stored as ciphertext exactly
// as the server holds them — see Models.swift for the security rationale.
let package = Package(
    name: "VaultKit",
    platforms: [.macOS(.v14)],
    products: [.library(name: "VaultKit", targets: ["VaultKit"])],
    targets: [
        .target(name: "VaultKit", path: "Sources/VaultKit"),
        // Executable checks for XCTest-less environments (Command Line Tools): swift run VaultKitChecks
        .executableTarget(name: "VaultKitChecks", dependencies: ["VaultKit"], path: "Sources/VaultKitChecks"),
        .testTarget(name: "VaultKitTests", dependencies: ["VaultKit"], path: "Tests/VaultKitTests"),
    ]
)
