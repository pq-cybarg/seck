// Plan-17 iOS Share Extension entry point.
//
// User invokes the system share sheet on a file, picks "seck". This
// extension:
//   1. Reads the shared file in-memory.
//   2. Hands it to WGClient, which dials the paired host's WireGuard
//      endpoint (LAN-only — there is no cloud relay).
//   3. WGClient base64-encodes the bytes inside a JSON-RPC
//      `seck.analyze` request, sends it, awaits the report.
//   4. Renders the report in an SLComposeServiceViewController.
import UIKit
import Social
import UniformTypeIdentifiers

class ShareViewController: SLComposeServiceViewController {

    override func isContentValid() -> Bool {
        return true
    }

    override func didSelectPost() {
        guard let extensionItem = extensionContext?.inputItems.first as? NSExtensionItem,
              let attachment = extensionItem.attachments?.first else {
            extensionContext?.cancelRequest(withError: NSError(
                domain: "Seck", code: 1, userInfo: [NSLocalizedDescriptionKey: "no attachment"]))
            return
        }
        attachment.loadFileRepresentation(forTypeIdentifier: UTType.item.identifier) { url, err in
            guard let url = url, let data = try? Data(contentsOf: url) else {
                self.extensionContext?.cancelRequest(withError: NSError(
                    domain: "Seck", code: 2, userInfo: [NSLocalizedDescriptionKey: "read failed"]))
                return
            }
            WGClient.shared.analyze(filename: url.lastPathComponent, contents: data) { result in
                DispatchQueue.main.async {
                    let alert = UIAlertController(
                        title: "seck", message: result, preferredStyle: .alert)
                    alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in
                        self.extensionContext?.completeRequest(
                            returningItems: nil, completionHandler: nil)
                    })
                    self.present(alert, animated: true)
                }
            }
        }
    }

    override func configurationItems() -> [Any]! { return [] }
}
