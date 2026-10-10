/// 快照结构不变量检查。
///
/// 匹配器依赖这些不变量：例如关键字按序号升序以便早停、逻辑规则按序号升序、
/// `CategoryBounds` 必须等于各类别的真实最小序号（否则剪枝会漏掉命中）。
/// 编译器在 `finish()` 之后断言这些不变量（仅调试构建与测试生效），
/// 违反时返回可读的描述，便于定位编译器缺陷。
extension CompiledRules {
    func invariantViolations() -> [String] {
        var checker = InvariantChecker()
        checkPolicyTable(&checker)
        checkOpenAddressing(&checker, "exact", keys: exactKeys, entries: exactEntries, mask: exactSlotMask)
        checkOpenAddressing(&checker, "processName", keys: processNameKeys, entries: processNameEntries, mask: processNameSlotMask)
        checkOpenAddressing(&checker, "processPath", keys: processPathKeys, entries: processPathEntries, mask: processPathSlotMask)
        checkSuffixTrie(&checker)
        checkIPTrie(&checker, "ipv4", ipv4Nodes)
        checkIPTrie(&checker, "ipv6", ipv6Nodes)
        checkIPTrie(&checker, "srcIPv4", srcIPv4Nodes)
        checkIPTrie(&checker, "srcIPv6", srcIPv6Nodes)
        checkPorts(&checker)
        checkKeywords(&checker)
        checkScalarRules(&checker)
        checkLogic(&checker)
        checkBounds(&checker)
        return checker.violations
    }

    private func isPolicy(_ id: UInt16) -> Bool {
        Int(id) < policyNameRefs.count
    }

    private func isRule(_ index: UInt32) -> Bool {
        Int(index) < ruleCount
    }

    private func checkPolicyTable(_ c: inout InvariantChecker) {
        c.check(policyNameRefs.count <= 65536, "策略数超过 65536")
        var names = Set<[UInt8]>()
        for (id, ref) in policyNameRefs.enumerated() {
            let end = Int(ref.offset) + Int(ref.length)
            c.check(end <= policyArena.count, "策略 \(id) 的名称越界")
            guard end <= policyArena.count else { continue }
            c.check(names.insert(Array(policyArena[Int(ref.offset)..<end])).inserted, "策略 \(id) 的名称重复")
        }
    }

    /// 开放寻址哈希表：容量为 2 的幂，至少有一个空槽，且每个占用槽都能从哈希起点探测到。
    private func checkOpenAddressing(
        _ c: inout InvariantChecker,
        _ name: String,
        keys: ContiguousArray<UInt8>,
        entries: ContiguousArray<ExactEntry>,
        mask: UInt32
    ) {
        guard !entries.isEmpty else {
            c.check(mask == 0, "\(name) 表为空时 mask 应为 0")
            return
        }
        c.check(entries.count.nonzeroBitCount == 1, "\(name) 表容量应为 2 的幂")
        c.check(Int(mask) == entries.count - 1, "\(name) 表的 mask 与容量不一致")
        let occupied = entries.filter { $0.keyLength != 0 }.count
        c.check(occupied < entries.count, "\(name) 表没有空槽，查询可能不会终止")

        for (position, entry) in entries.enumerated() where entry.keyLength != 0 {
            let end = Int(entry.keyOffset) + Int(entry.keyLength)
            c.check(end <= keys.count, "\(name)[\(position)] 的键越界")
            c.check(isPolicy(entry.policyID) && isRule(entry.ruleIndex), "\(name)[\(position)] 的策略或序号无效")
            guard end <= keys.count else { continue }

            let key = Array(keys[Int(entry.keyOffset)..<end])
            var probe = Int(fnv1a(key) & UInt64(mask))
            var steps = 0
            var reachable = false
            while steps < entries.count && entries[probe].keyLength != 0 {
                if probe == position {
                    reachable = true
                    break
                }
                probe = (probe + 1) & Int(mask)
                steps += 1
            }
            c.check(reachable, "\(name)[\(position)] 无法从哈希起点探测到")
        }
    }

    /// 后缀 trie：节点按构建顺序存放，子节点序号必须大于父节点（保证无环），
    /// 每个非根节点恰好有一个父节点，同一父节点下的标签互不相同。
    private func checkSuffixTrie(_ c: inout InvariantChecker) {
        let count = trieNodes.count
        c.check(count >= 1 && Int(trieRoot) == 0, "trie 根节点应位于序号 0")
        var incoming = [Int](repeating: 0, count: count)
        for (index, node) in trieNodes.enumerated() {
            let labelEnd = Int(node.labelOffset) + Int(node.labelLength)
            c.check(labelEnd <= trieLabels.count, "trie[\(index)] 的标签越界")
            c.check(index == 0 || node.labelLength > 0, "trie[\(index)] 的非根节点标签为空")
            if node.isTerminal {
                c.check(isPolicy(node.policyID) && isRule(node.ruleIndex), "trie[\(index)] 终结点的策略或序号无效")
            }

            let first = Int(node.firstChildEntry)
            let childEnd = first + Int(node.childCount)
            c.check(childEnd <= trieChildIndices.count, "trie[\(index)] 的子节点区间越界")
            guard childEnd <= trieChildIndices.count else { continue }

            var labels = Set<[UInt8]>()
            for entry in first..<childEnd {
                let child = Int(trieChildIndices[entry])
                c.check(child < count && child > index, "trie[\(index)] 的子节点 \(child) 无效")
                guard child < count else { continue }
                incoming[child] += 1

                let childNode = trieNodes[child]
                let childLabelEnd = Int(childNode.labelOffset) + Int(childNode.labelLength)
                guard childLabelEnd <= trieLabels.count else { continue }
                let label = Array(trieLabels[Int(childNode.labelOffset)..<childLabelEnd])
                c.check(labels.insert(label).inserted, "trie[\(index)] 下的标签重复")
            }
        }
        c.check(count == 0 || incoming[0] == 0, "trie 根节点不应有父节点")
        for index in 0..<count where index > 0 {
            c.check(incoming[index] == 1, "trie[\(index)] 应恰好有一个父节点，实际 \(incoming[index]) 个")
        }
    }

    /// IP 基数树：子节点序号必须大于父节点，每个非根节点恰好有一个父节点。
    private func checkIPTrie(_ c: inout InvariantChecker, _ name: String, _ nodes: ContiguousArray<IPNode>) {
        c.check(!nodes.isEmpty, "\(name) 树至少应有根节点")
        var incoming = [Int](repeating: 0, count: nodes.count)
        for (index, node) in nodes.enumerated() {
            for child in [node.left, node.right] where child != IPNode.noChild {
                let target = Int(child)
                c.check(target < nodes.count && target > index, "\(name)[\(index)] 的子节点 \(target) 无效")
                if target < nodes.count { incoming[target] += 1 }
            }
            if node.ruleIndex != IPNode.noRule {
                c.check(isPolicy(node.policyID) && isRule(node.ruleIndex), "\(name)[\(index)] 终结点的策略或序号无效")
            }
        }
        for index in 0..<nodes.count where index > 0 {
            c.check(incoming[index] == 1, "\(name)[\(index)] 应恰好有一个父节点，实际 \(incoming[index]) 个")
        }
    }

    /// 端口区间按 (low, high) 严格升序，`maxHigh` 为前缀最大值（查询的 break 条件依赖它）。
    private func checkPorts(_ c: inout InvariantChecker) {
        var previous: PortEntry? = nil
        var runningMax: UInt16 = 0
        for (index, entry) in portEntries.enumerated() {
            c.check(entry.low <= entry.high, "端口区间 \(index) 的下界大于上界")
            if let previous {
                c.check((previous.low, previous.high) < (entry.low, entry.high), "端口区间未按 (low, high) 严格升序")
            }
            runningMax = max(runningMax, entry.high)
            c.check(entry.maxHigh == runningMax, "端口区间 \(index) 的 maxHigh 不是前缀最大值")
            c.check(entry.dstRule != PortEntry.noRule || entry.srcRule != PortEntry.noRule, "端口区间 \(index) 没有任何规则")
            if entry.dstRule != PortEntry.noRule {
                c.check(isPolicy(entry.dstPolicy) && isRule(entry.dstRule), "端口区间 \(index) 的目的端口规则无效")
            }
            if entry.srcRule != PortEntry.noRule {
                c.check(isPolicy(entry.srcPolicy) && isRule(entry.srcRule), "端口区间 \(index) 的源端口规则无效")
            }
            previous = entry
        }
    }

    /// 关键字按序号升序排列：查询时遇到第一个命中即可返回，早停剪枝依赖此顺序。
    private func checkKeywords(_ c: inout InvariantChecker) {
        var previousRule: UInt32 = 0
        for (index, entry) in keywordEntries.enumerated() {
            let end = Int(entry.keyOffset) + Int(entry.keyLength)
            c.check(entry.keyLength > 0 && end <= keywordArena.count, "关键字 \(index) 为空或越界")
            c.check(isPolicy(entry.policyID) && isRule(entry.ruleIndex), "关键字 \(index) 的策略或序号无效")
            if index > 0 {
                c.check(entry.ruleIndex >= previousRule, "关键字未按规则序号升序（早停剪枝依赖此顺序）")
            }
            previousRule = entry.ruleIndex
        }
    }

    /// DSCP / GEOIP / NETWORK / MATCH 这些单值类别。
    private func checkScalarRules(_ c: inout InvariantChecker) {
        c.check(dscpTable.count == 64, "DSCP 表应有 64 项")
        for (value, entry) in dscpTable.enumerated() where entry.ruleIndex != DscpEntry.noRule {
            c.check(isPolicy(entry.policyID) && isRule(entry.ruleIndex), "DSCP \(value) 的策略或序号无效")
        }

        for (index, entry) in geoIPEntries.enumerated() {
            c.check(entry.countryCode != 0, "GEOIP 条目 \(index) 的国家码为 0")
            c.check(isPolicy(entry.policyID) && isRule(entry.ruleIndex), "GEOIP 条目 \(index) 的策略或序号无效")
            if index > 0 {
                c.check(geoIPEntries[index - 1].countryCode < entry.countryCode, "GEOIP 未严格升序（二分查找依赖此顺序）")
            }
        }

        if tcpRuleIndex != UInt32.max {
            c.check(isPolicy(tcpPolicy) && isRule(tcpRuleIndex), "NETWORK,tcp 的策略或序号无效")
        }
        if udpRuleIndex != UInt32.max {
            c.check(isPolicy(udpPolicy) && isRule(udpRuleIndex), "NETWORK,udp 的策略或序号无效")
        }

        if hasMatchRule {
            c.check(isPolicy(matchPolicy) && isRule(matchRuleIndex), "MATCH 的策略或序号无效")
        }
    }

    /// 逻辑表达式：子节点先于父节点出现（因此子序号小于父序号），字符串参数不越界，
    /// 逻辑规则按序号升序排列。
    private func checkLogic(_ c: inout InvariantChecker) {
        var previousRule: UInt32 = 0
        for (index, rule) in logicRules.enumerated() {
            c.check(Int(rule.rootNodeIndex) < logicNodes.count, "逻辑规则 \(index) 的根节点越界")
            c.check(isPolicy(rule.policyID) && isRule(rule.ruleIndex), "逻辑规则 \(index) 的策略或序号无效")
            if index > 0 {
                c.check(rule.ruleIndex >= previousRule, "逻辑规则未按序号升序（早停依赖此顺序）")
            }
            previousRule = rule.ruleIndex
        }

        for (index, node) in logicNodes.enumerated() {
            guard let op = LogicOp(rawValue: node.op) else {
                c.check(false, "逻辑节点 \(index) 的操作码无效")
                continue
            }
            switch op {
            case .and, .or:
                let end = Int(node.firstChildIndex) + Int(node.childCount)
                c.check(end <= logicChildIndices.count, "逻辑节点 \(index) 的子节点区间越界")
                guard end <= logicChildIndices.count else { continue }
                for slot in Int(node.firstChildIndex)..<end {
                    let child = Int(logicChildIndices[slot])
                    c.check(child < index, "逻辑节点 \(index) 的子节点 \(child) 应先于父节点出现")
                }
            case .not:
                c.check(Int(node.firstChildIndex) < index, "逻辑节点 \(index) 的子节点应先于父节点出现")
            case .domain, .domainSuffix, .domainKeyword, .processName, .processPath:
                let end = Int(node.argOffset) + Int(node.argLength)
                c.check(end <= logicArena.count, "逻辑节点 \(index) 的字符串参数越界")
            case .ipCIDR:
                let maxPrefix = (node.flags & 1) != 0 ? 128 : 32
                c.check(Int(node.prefix) <= maxPrefix, "逻辑节点 \(index) 的前缀长度超出地址宽度")
            case .port:
                c.check(node.flags <= 2, "逻辑节点 \(index) 的端口方向无效")
            case .network, .dscp, .geoIP:
                break
            }
        }
    }

    /// `CategoryBounds` 必须等于各类别的真实最小序号：剪枝用它判断某类别是否可能胜出。
    private func checkBounds(_ c: inout InvariantChecker) {
        let b = bounds
        let checks: [(name: String, bound: UInt32, actual: UInt32)] = [
            ("minExactRule", b.minExactRule, minRule(exactEntries.filter { $0.keyLength != 0 }.map(\.ruleIndex))),
            ("minSuffixRule", b.minSuffixRule, minRule(trieNodes.filter(\.isTerminal).map(\.ruleIndex))),
            ("minKeywordRule", b.minKeywordRule, minRule(keywordEntries.map(\.ruleIndex))),
            ("minIPv4Rule", b.minIPv4Rule, minRule(ipRules(ipv4Nodes))),
            ("minIPv6Rule", b.minIPv6Rule, minRule(ipRules(ipv6Nodes))),
            ("minSrcIPv4Rule", b.minSrcIPv4Rule, minRule(ipRules(srcIPv4Nodes))),
            ("minSrcIPv6Rule", b.minSrcIPv6Rule, minRule(ipRules(srcIPv6Nodes))),
            ("minPortRule", b.minPortRule, minRule(portEntries.flatMap { [$0.dstRule, $0.srcRule] }.filter { $0 != PortEntry.noRule })),
            ("minProcessNameRule", b.minProcessNameRule, minRule(processNameEntries.filter { $0.keyLength != 0 }.map(\.ruleIndex))),
            ("minProcessPathRule", b.minProcessPathRule, minRule(processPathEntries.filter { $0.keyLength != 0 }.map(\.ruleIndex))),
            ("minNetworkRule", b.minNetworkRule, minRule([tcpRuleIndex, udpRuleIndex])),
            ("minDscpRule", b.minDscpRule, minRule(dscpTable.map(\.ruleIndex).filter { $0 != DscpEntry.noRule })),
            ("minGeoIPRule", b.minGeoIPRule, minRule(geoIPEntries.map(\.ruleIndex))),
            ("minLogicRule", b.minLogicRule, minRule(logicRules.map(\.ruleIndex))),
        ]
        for check in checks {
            c.check(check.bound == check.actual, "\(check.name) 为 \(check.bound)，真实最小序号为 \(check.actual)")
        }
    }

    private func ipRules(_ nodes: ContiguousArray<IPNode>) -> [UInt32] {
        nodes.map(\.ruleIndex).filter { $0 != IPNode.noRule }
    }

    private func minRule(_ values: [UInt32]) -> UInt32 {
        values.min() ?? UInt32.max
    }
}

struct InvariantChecker {
    private(set) var violations: [String] = []

    mutating func check(_ condition: Bool, _ message: @autoclosure () -> String) {
        if !condition { violations.append(message()) }
    }
}
