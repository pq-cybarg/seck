// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SeckApplet",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "SeckApplet", targets: ["SeckApplet"]),
    ],
    targets: [
        .executableTarget(
            name: "SeckApplet",
            path: "Sources/SeckApplet"
        ),
    ]
)
