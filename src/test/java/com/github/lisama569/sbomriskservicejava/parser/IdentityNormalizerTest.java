package com.github.lisama569.sbomriskservicejava.parser;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 身份归一规则单测：Maven 斜杠/冒号分隔符、大小写不敏感、npm 作用域前缀与小写、
 * 不同生态不串号。每个用例打印输入摘要与判定依据。
 */
class IdentityNormalizerTest {

    private static final Logger log = LoggerFactory.getLogger(IdentityNormalizerTest.class);

    private static String canon(String eco, String raw) {
        String out = IdentityNormalizer.name(eco, raw);
        log.info("输入摘要: ecosystem={} rawName='{}' | 判定依据: 稳定身份='{}'", eco, raw, out);
        return out;
    }

    @Test
    @DisplayName("Maven：冒号写法与斜杠写法（组名/构件名）归一到同一 groupId:artifactId 身份")
    void mavenSlashAndColonSpellingsUnify() {
        String viaColon = canon("maven", "org.apache.logging.log4j:log4j-core");
        String viaSlash = canon("maven", "org.apache.logging.log4j/log4j-core");
        assertEquals("org.apache.logging.log4j:log4j-core", viaColon);
        assertEquals(viaColon, viaSlash);
    }

    @Test
    @DisplayName("Maven：组名内的斜杠与点等价（org/apache/log4j -> org.apache.log4j）")
    void mavenGroupInternalSlashEqualsDot() {
        assertEquals("org.apache.log4j:log4j-core",
                canon("maven", "org/apache/log4j/log4j-core"));
        assertEquals("org.apache.log4j:log4j-core",
                canon("maven", "org.apache.log4j:log4j-core"));
    }

    @Test
    @DisplayName("Maven：仅大小写不同的坐标归一到同一稳定身份")
    void mavenCaseInsensitive() {
        String lower = canon("maven", "org.apache.logging.log4j:log4j-core");
        String upper = canon("maven", "ORG.APACHE.LOGGING.LOG4J:LOG4J-CORE");
        String mixed = canon("Maven", "Org.Apache.Logging.Log4j/Log4j-Core");
        assertEquals(lower, upper);
        assertEquals(lower, mixed);
        // 生态标签大小写同样归一
        assertEquals("maven", IdentityNormalizer.ecosystem("  MAVEN "));
    }

    @Test
    @DisplayName("npm：带作用域写法（缺 @ 前缀、大小写不同）归一到 @scope/name")
    void npmScopePrefixAndCase() {
        assertEquals("@angular/core", canon("npm", "@angular/core"));
        assertEquals("@angular/core", canon("npm", "angular/core"));
        assertEquals("@angular/core", canon("npm", "@Angular/Core"));
        assertEquals("@angular/core", canon("NPM", "Angular/Core"));
    }

    @Test
    @DisplayName("npm：无作用域包名小写归一")
    void npmUnscopedLowercase() {
        assertEquals("lodash", canon("npm", "Lodash"));
        assertEquals("lodash", canon("npm", "lodash"));
    }

    @Test
    @DisplayName("生态隔离：同一名字在 maven 与 npm 下归一结果不同，互不串号")
    void ecosystemsDoNotBleed() {
        String maven = canon("maven", "lodash/lodash");
        String npm = canon("npm", "lodash");
        log.info("判定依据: maven 身份='{}' 与 npm 身份='{}' 必须不同", maven, npm);
        assertEquals("lodash:lodash", maven);
        assertEquals("lodash", npm);
        // 不支持的生态不套用 maven/npm 规则，原文保留
        assertEquals("Requests", canon("pypi", "Requests"));
        assertEquals("unknown", IdentityNormalizer.ecosystem(null));
    }
}
