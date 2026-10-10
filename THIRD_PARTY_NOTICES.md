# 第三方声明

本仓库的代码以 MIT License 发布（见 [LICENSE](LICENSE)）。以下第三方文件不属于 MIT 授权范围，各自遵循其原始许可证。

## Golden 测试语料

| 文件 | 来源 | 许可证 |
|---|---|---|
| `Tests/GoldenTests/Fixtures/community/acl4ssr_lan.list` | [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) | [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/legalcode) |
| `Tests/GoldenTests/Fixtures/community/acl4ssr_proxylite.list` | [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) | [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/legalcode) |
| `Tests/GoldenTests/Fixtures/community/blackmatrix7_apple.list` | [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | [GPL-2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt) |
| `Tests/GoldenTests/Fixtures/community/blackmatrix7_telegram.list` | [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | [GPL-2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt) |

说明：

- `acl4ssr_*` 文件遵循 CC-BY-SA-4.0。再分发时须署名、保留本声明，并以相同或兼容协议发布。
- `blackmatrix7_*` 文件遵循 GPL-2.0。再分发时须附带许可证文本并提供对应源码。
- 本仓库中的上述文件仅作为测试输入使用，并未与本项目代码合并为衍生作品。

## 对拍工具

| 依赖 | 来源 | 许可证 | 使用方式 |
|---|---|---|---|
| mihomo | [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) | MIT | 作为规则语义的 oracle 运行，其源码不随本仓库分发 |

## 基准语料

`Tools/benchmark/data/` 下的规则文件由本仓库的生成器产生，遵循本项目 MIT 许可证。
