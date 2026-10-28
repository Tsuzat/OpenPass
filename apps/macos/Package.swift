// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OpenPassMac",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "OpenPassMac", targets: ["OpenPassMac"])],
    targets: [.executableTarget(name: "OpenPassMac", path: "Sources/OpenPassMac")]
)
// NOTE: The ASCredentialProviderExtension target (CredentialProvider/) requires an Xcode
// app project (extensions + App Groups cannot be expressed in SwiftPM). Open this package
// in Xcode, add an app target embedding Sources, then add the extension target from
// CredentialProvider/. See docs/NATIVE-INTEGRATION.md.
