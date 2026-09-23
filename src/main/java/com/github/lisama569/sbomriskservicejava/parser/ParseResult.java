package com.github.lisama569.sbomriskservicejava.parser;

import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.RejectedItem;

import java.util.List;

/**
 * 单份清单的解析结果：可入库的组件与逐条拒绝原因（不静默跳过任何条目）。
 */
public record ParseResult(List<Component> components, List<RejectedItem> rejected) {
}
