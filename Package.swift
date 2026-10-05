// swift-tools-version:6.4
import PackageDescription

let package = Package(
    name: "clash-rule",
    // UInt128 (SE-0425) and Span (SE-0447) need macOS 15 / iOS 18.
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        .library(name: "ClashRuleCore", targets: ["ClashRuleCore"]),
        .executable(name: "ClashRuleBenchmark", targets: ["ClashRuleBenchmark"]),
    ],
    targets: [
        .target(
            name: "ClashRuleCore",
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
        .executableTarget(
            name: "ClashRuleBenchmark",
            dependencies: ["ClashRuleCore"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
        .testTarget(
            name: "ClashRuleCoreTests",
            dependencies: ["ClashRuleCore"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
        .testTarget(
            name: "GoldenTests",
            dependencies: ["ClashRuleCore"],
            resources: [
                .copy("Fixtures"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
    ]
)
