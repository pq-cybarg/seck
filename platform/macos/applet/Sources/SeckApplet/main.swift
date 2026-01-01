import Cocoa

class SeckAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.activate(ignoringOtherApps: true)
        showWindow()
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls {
            do {
                try spawnSeckWithFD(path: url)
            } catch {
                let alert = NSAlert()
                alert.messageText = "seck failed"
                alert.informativeText = error.localizedDescription
                alert.runModal()
            }
        }
    }

    func showWindow() {
        let win = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 240),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false)
        win.title = "seck"
        let label = NSTextField(labelWithString:
            "Drop a file or folder onto this window (or the dock icon) to analyze it. Paths are opened as pre-opened FDs — never shell-interpreted.")
        label.frame = NSRect(x: 24, y: 80, width: 432, height: 80)
        label.alignment = .center
        label.lineBreakMode = .byWordWrapping
        win.contentView?.addSubview(label)
        win.center()
        win.makeKeyAndOrderFront(nil)
    }
}

let app = NSApplication.shared
let delegate = SeckAppDelegate()
app.delegate = delegate
app.run()
