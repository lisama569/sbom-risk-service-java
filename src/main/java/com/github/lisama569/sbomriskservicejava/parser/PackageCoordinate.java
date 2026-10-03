package com.github.lisama569.sbomriskservicejava.parser;

/**
 * 从包坐标（purl）解析出的可靠组件身份。
 *
 * @param ecosystem 生态（purl type，小写），如 maven / npm
 * @param name      归一后的组件名：maven 为 {@code groupId:artifactId}，
 *                  npm 为 {@code @scope/name} 或 {@code name}（小写）
 * @param version   坐标中携带的版本，可能为 null（条目版本字段优先）
 */
public record PackageCoordinate(String ecosystem, String name, String version) {
}
