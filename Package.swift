// swift-tools-version:6.4
import PackageDescription

let package = Package(
    name: "clash-rule",
    platforms: [
        .macOS("27.0"),
        .iOS("27.0"),
        .tvOS("27.0"),
    ],
    products: [
        .library(name: "ClashRuleCore", targets: ["ClashRuleCore"]),
        .library(
            name: "ClashRuleCAPI",
            targets: ["ClashRuleCAPI", "ClashRuleCAPIHeader"]
        ),
        .executable(name: "ClashRuleBenchmark", targets: ["ClashRuleBenchmark"]),
    ],
    traits: [
        .default(enabledTraits: []),
        .trait(name: "Diagnostics", description: "诊断能力（规则序号到源行号的映射），默认关闭"),
    ],
    targets: [
        .target(
            name: "ClashRuleCore",
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
        .target(
            name: "ClashRuleCAPIHeader",
            path: "Sources/ClashRuleCAPIHeader",
            publicHeadersPath: "include"
        ),
        .target(
            name: "ClashRuleCAPI",
            dependencies: ["ClashRuleCore", "ClashRuleCAPIHeader"],
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
        .target(
            name: "ClashRuleAllocCounter",
            path: "Tests/ClashRuleAllocCounter",
            publicHeadersPath: "include"
        ),
        .testTarget(
            name: "ClashRuleCoreTests",
            dependencies: ["ClashRuleCore", "ClashRuleAllocCounter"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
        .target(
            name: "ClashRuleCAPITestSupport",
            dependencies: ["ClashRuleCAPI", "ClashRuleCAPIHeader"],
            path: "Tests/ClashRuleCAPITestSupport",
            publicHeadersPath: "include"
        ),
        .testTarget(
            name: "ClashRuleCAPITests",
            dependencies: [
                "ClashRuleCAPI",
                "ClashRuleCore",
                "ClashRuleCAPITestSupport",
            ],
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
