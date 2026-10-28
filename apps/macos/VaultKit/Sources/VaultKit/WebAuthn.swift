import CryptoKit
import Foundation

/// WebAuthn authenticator data construction (spec: docs/PASSKEYS.md).
/// Platform code (credential provider extension) supplies clientDataHash and
/// user verification state; signing itself is delegated to the Rust core via
/// the injected signer closure, so no private key material lives in Swift.

public struct AuthenticatorFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }
    public static let userPresent = AuthenticatorFlags(rawValue: 0x01)
    public static let userVerified = AuthenticatorFlags(rawValue: 0x04)
    public static let backupEligibility = AuthenticatorFlags(rawValue: 0x08)
    public static let backupState = AuthenticatorFlags(rawValue: 0x10)
    public static let attestedCredentialData = AuthenticatorFlags(rawValue: 0x40)
    /// Synced passkey defaults: UP | UV | BE | BS
    public static let syncedAssertion: AuthenticatorFlags = [.userPresent, .userVerified, .backupEligibility, .backupState]
}

public enum WebAuthn {
    public static func rpIdHash(_ rpId: String) -> Data {
        Data(SHA256.hash(data: Data(rpId.utf8)))
    }

    /// authenticatorData for assertions: rpIdHash || flags || signCount(BE u32)
    public static func assertionAuthenticatorData(rpId: String, flags: AuthenticatorFlags, signCount: UInt32) -> Data {
        var out = rpIdHash(rpId)
        out.append(flags.rawValue)
        out.append(contentsOf: withUnsafeBytes(of: signCount.bigEndian) { Array($0) })
        return out
    }

    /// authenticatorData for registration, with attested credential data:
    /// rpIdHash || flags|AT || signCount || AAGUID(16 zero bytes, "none" attestation)
    /// || credentialIdLength(BE u16) || credentialId || COSE public key
    public static func registrationAuthenticatorData(rpId: String, flags: AuthenticatorFlags, signCount: UInt32,
                                                     credentialId: Data, cosePublicKey: Data) -> Data {
        var out = assertionAuthenticatorData(rpId: rpId, flags: flags.union(.attestedCredentialData), signCount: signCount)
        out.append(Data(count: 16))
        out.append(contentsOf: withUnsafeBytes(of: UInt16(credentialId.count).bigEndian) { Array($0) })
        out.append(credentialId)
        out.append(cosePublicKey)
        return out
    }

    /// Full assertion: sign authenticatorData || clientDataHash, return everything the RP needs.
    public struct Assertion: Sendable {
        public var credentialId: Data
        public var authenticatorData: Data
        public var signature: Data
        public var userHandle: Data?
    }

    public static func makeAssertion(rpId: String, credentialId: Data, clientDataHash: Data,
                                     signCount: UInt32, userHandle: Data?,
                                     sign: (Data) throws -> Data) throws -> Assertion {
        let authData = assertionAuthenticatorData(rpId: rpId, flags: .syncedAssertion, signCount: signCount)
        var signed = authData
        signed.append(clientDataHash)
        return Assertion(credentialId: credentialId, authenticatorData: authData,
                         signature: try sign(signed), userHandle: userHandle)
    }

    /// Validate that a request's rpId matches the stored credential's rpId (exact match, anti-phishing).
    public static func rpIdMatches(requestRpId: String, storedRpId: String) -> Bool {
        requestRpId == storedRpId
    }
}
