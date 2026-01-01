// swift-tools-version:5.9
//
// Plan-17 iOS Share Extension.
//
// SwiftPM project layout. The actual Xcode project that produces the
// .appex is generated from this via `swift package generate-xcodeproj`
// (or by hand). To build:
//
//   cd platform/ios/SeckShare
//   xcodebuild -scheme SeckShare -destination 'generic/platform=iOS'
//
// boringtun-swift is added as a dependency at the executor's discretion
// (multiple Swift packages wrap BoringTun; pinning a single one is out
// of scope for the scaffold).
import PackageDescription

let package = Package(
    name: "SeckShare",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "SeckShare", targets: ["SeckShare"]),
    ],
    dependencies: [
        // .package(url: "https://github.com/cloudflare/boringtun.git", from: "0.6.0"),
    ],
    targets: [
        .target(name: "SeckShare", path: "Sources"),
    ]
)
