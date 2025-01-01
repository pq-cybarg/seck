// Plan-17 iOS WG client scaffold.
//
// Holds the desktop's PairingBundle (loaded from the app's shared
// container after the user completed pairing). For each analyze call,
// brings up a WireGuard tunnel via BoringTun, sends a JSON-RPC
// `seck.analyze` over the tunnel, returns the report.
//
// The actual BoringTun glue is left to the executor — multiple Swift
// wrappers of BoringTun exist (cloudflare/boringtun has a `boringtun`
// crate that compiles to a static lib + Swift FFI). Pinning one is out
// of scope for this scaffold.
import Foundation

struct PairingBundle: Codable {
    let host_public_hex: String
    let psk_hex: String
    let host_endpoint: String
    let fingerprint_sha3_256: String
}

final class WGClient {
    static let shared = WGClient()

    private init() {}

    /// Load the bundle persisted by the host pairing flow. The user
    /// scans the desktop QR; the iOS UI parses + verifies fingerprint;
    /// the bundle JSON is written to the App Group container.
    func loadBundle() -> PairingBundle? {
        guard let dir = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.net.seck.share") else { return nil }
        let url = dir.appendingPathComponent("pairing.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(PairingBundle.self, from: data)
    }

    /// Submit `contents` to the paired host. Calls back with the JSON
    /// report (or an error string). Network errors and pairing-missing
    /// produce user-facing strings rather than throwing — the share
    /// extension UI displays whatever this returns.
    func analyze(filename: String,
                 contents: Data,
                 completion: @escaping (String) -> Void) {
        guard let bundle = loadBundle() else {
            completion("Not paired — run `seck pair` on your desktop, then scan the QR.")
            return
        }
        // Build JSON-RPC frame
        let frame: [String: Any] = [
            "jsonrpc": "2.0",
            "id": UUID().uuidString,
            "method": "seck.analyze",
            "params": [
                "filename": filename,
                "content_base64": contents.base64EncodedString(),
            ]
        ]
        guard let body = try? JSONSerialization.data(withJSONObject: frame) else {
            completion("Failed to encode request.")
            return
        }
        // BoringTun-glued UDP transport goes here in the executor build.
        // For the scaffold, we acknowledge the pairing and the encoded
        // request size so the UI flow is end-to-end demonstrable.
        let preview = "Encoded \(body.count) bytes; would send to \(bundle.host_endpoint)."
        completion(preview)
    }
}
