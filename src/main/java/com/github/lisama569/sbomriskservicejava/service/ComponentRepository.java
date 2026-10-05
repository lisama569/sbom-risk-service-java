package com.github.lisama569.sbomriskservicejava.service;

import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.RejectedItem;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 已摄入组件的内存仓库：
 * <ul>
 *   <li>按 {@code targetId} 分组，组内以组件稳定键（生态::名@版本）去重，
 *       因此同一份清单重复提交不会产生重复记录；</li>
 *   <li>每个目标同时保存<b>无法判定的条目</b>（摄入时被拒绝、非文档内重复的条目），
 *       以 原因+下标+明细 为键去重，重复/并发提交不会累积；这些条目会作为
 *       UNKNOWN 结论出现在风险报告中，并抬高总体结论；</li>
 *   <li>每个目标提供一把锁，供摄入服务把同一目标的并发提交串行化，保证幂等；</li>
 *   <li>读取时按键稳定排序，保证风险报告内容与顺序可复现。</li>
 * </ul>
 */
@Repository
public class ComponentRepository {

    /** targetId -> (componentKey -> component)，TreeMap 保证遍历顺序稳定。 */
    private final Map<String, TreeMap<String, Component>> targets = new ConcurrentHashMap<>();

    /** targetId -> (unjudgeableKey -> rejectedItem)，无法判定条目，键稳定去重。 */
    private final Map<String, TreeMap<String, RejectedItem>> unjudgeable = new ConcurrentHashMap<>();

    /** 每个目标一把锁，避免不同目标相互阻塞。 */
    private final Map<String, Object> targetLocks = new ConcurrentHashMap<>();

    /** 获取目标级锁；同一 targetId 始终返回同一把锁。 */
    public Object lockFor(String targetId) {
        return targetLocks.computeIfAbsent(targetId, k -> new Object());
    }

    /**
     * 新组件则存入并返回 {@link Optional#empty()}；已存在则返回已有组件（幂等命中）。
     */
    public Optional<Component> putIfAbsent(String targetId, Component component) {
        TreeMap<String, Component> store =
                targets.computeIfAbsent(targetId, k -> new TreeMap<>());
        synchronized (store) {
            Component existing = store.putIfAbsent(component.key(), component);
            return Optional.ofNullable(existing);
        }
    }

    /**
     * 记录一条无法判定条目；相同条目（原因+下标+明细）已存在时不重复记录（幂等命中）。
     *
     * @return true 表示本次新记录
     */
    public boolean putUnjudgeableIfAbsent(String targetId, RejectedItem item) {
        TreeMap<String, RejectedItem> store =
                unjudgeable.computeIfAbsent(targetId, k -> new TreeMap<>());
        synchronized (store) {
            return store.putIfAbsent(unjudgeableKey(item), item) == null;
        }
    }

    /** 目标下全部无法判定条目，按键稳定排序。 */
    public List<RejectedItem> findUnjudgeableByTarget(String targetId) {
        TreeMap<String, RejectedItem> store = unjudgeable.get(targetId);
        if (store == null) {
            return List.of();
        }
        synchronized (store) {
            return new ArrayList<>(store.values());
        }
    }

    /** 无法判定条目的稳定去重键：原因 + 条目下标 + 明细。 */
    private static String unjudgeableKey(RejectedItem item) {
        return item.reason().name() + "|" + item.index() + "|" + item.detail();
    }

    /** 目标下全部组件，按组件键稳定排序。 */
    public List<Component> findByTarget(String targetId) {
        TreeMap<String, Component> store = targets.get(targetId);
        if (store == null) {
            return List.of();
        }
        synchronized (store) {
            return new ArrayList<>(store.values());
        }
    }

    /** 目标是否存在（曾经成功摄入过至少一个组件，或记录过无法判定条目）。 */
    public boolean existsTarget(String targetId) {
        return targets.containsKey(targetId) || unjudgeable.containsKey(targetId);
    }
}
