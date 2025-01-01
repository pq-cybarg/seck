import Foundation
import Darwin

/// Open `path` with O_RDONLY|O_NOFOLLOW|O_CLOEXEC, then posix_spawn the
/// seck CLI binary with that FD inherited as FD 3 in the child. The
/// path is NEVER passed in argv — only the FD number is.
func spawnSeckWithFD(path: URL) throws {
    let fd = open(path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    if fd < 0 {
        throw NSError(
            domain: "SeckApplet",
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: "open(\(path.path)) failed: \(String(cString: strerror(errno)))"])
    }
    defer { close(fd) }

    var fileActions: posix_spawn_file_actions_t? = nil
    posix_spawn_file_actions_init(&fileActions)
    defer { posix_spawn_file_actions_destroy(&fileActions) }
    // dup the open FD into the child's FD 3.
    posix_spawn_file_actions_adddup2(&fileActions, fd, 3)
    // Close the original FD in the child after dup2 (so only FD 3 remains).
    posix_spawn_file_actions_addclose(&fileActions, fd)

    // Locate the seck CLI binary next to the applet inside the .app bundle.
    let bundleURL = Bundle.main.bundleURL
    let seckURL = bundleURL.appendingPathComponent("Contents/Resources/seck")

    // Build argv: ["seck", "analyze", "--fd=3"] — NO path.
    let argv: [String] = [seckURL.path, "analyze", "--fd=3"]
    let cargv: [UnsafeMutablePointer<CChar>?] = argv.map { strdup($0) } + [nil]
    defer { for a in cargv { if let a = a { free(a) } } }

    var pid: pid_t = 0
    let rc = posix_spawn(&pid, seckURL.path, &fileActions, nil, cargv, nil)
    if rc != 0 {
        throw NSError(
            domain: "SeckApplet",
            code: Int(rc),
            userInfo: [NSLocalizedDescriptionKey: "posix_spawn failed: \(String(cString: strerror(rc)))"])
    }
    var status: Int32 = 0
    waitpid(pid, &status, 0)
}
