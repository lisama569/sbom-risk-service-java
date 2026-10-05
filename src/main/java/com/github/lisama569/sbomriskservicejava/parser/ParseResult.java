package com.github.lisama569.sbomriskservicejava.parser;

import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.RejectedItem;
import com.github.lisama569.sbomriskservicejava.model.UnresolvedComponent;

import java.util.List;

/**
 * 单份清单的解析结果。
 *
 * @param components 可入库的组件（身份可靠）
 * @param rejected   逐条拒绝原因（不静默跳过任何条目，保留清单下标）
 * @param unresolved 与 rejected 一一对应的“无法判定”条目，供摄入服务持久化、
 *                   供报告以 UNKNOWN 结论展示（被拒绝的条目绝不能从报告中消失）
 */
public record ParseResult(List<Component> components,
                          List<RejectedItem> rejected,
                          List<UnresolvedComponent> unresolved) {

    public ParseResult {
        // rejected 与 unresolved 等长且同序，由解析器保证
    }
}
