package com.github.lisama569.sbomriskservicejava.parser;

import com.github.lisama569.sbomriskservicejava.model.SbomFormat;

/** SBOM 解析器 SPI。 */
public interface SbomParser {

    /** 是否支持该格式。 */
    boolean supports(SbomFormat format);

    /** 解析清单原文；文档级畸形抛 {@link SbomParseException}，条目级问题收集进 ParseResult。 */
    ParseResult parse(String rawContent);
}
