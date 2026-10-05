// swift-tools-version:6.4
import PackageDescription

let package = Package(
    name: "clash-rule",
    platforms: [
        .macOS("27.0"),
        .iOS("27.0"),
        .tvOS("27.0"),
        .watchOS("27.0"),
        .visionOS("27.0"),
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
