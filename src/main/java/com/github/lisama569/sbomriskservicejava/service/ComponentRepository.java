package com.github.lisama569.sbomriskservicejava.service;

import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.UnresolvedComponent;
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
 *   <li>无法判定的条目（{@link UnresolvedComponent}）同样按目标持久化、按键去重，
 *       报告里以 UNKNOWN 结论逐条出现——被拒绝不等于不存在；</li>
 *   <li>每个目标提供一把锁，供摄入服务把同一目标的并发提交串行化，保证幂等；</li>
 *   <li>读取时按键稳定排序，保证风险报告内容与顺序可复现。</li>
 * </ul>
 */
@Repository
public class ComponentRepository {

    /** targetId -> (componentKey -> component)，TreeMap 保证遍历顺序稳定。 */
    private final Map<String, TreeMap<String, Component>> targets = new ConcurrentHashMap<>();

    /** targetId -> (unresolvedKey -> unresolved)，无法判定条目同样持久化去重。 */
    private final Map<String, TreeMap<String, UnresolvedComponent>> unresolvedByTarget =
            new ConcurrentHashMap<>();

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
     * 无法判定条目去重持久化。返回 true 表示本次新增，false 表示已有等价条目（幂等命中）。
     */
    public boolean putUnresolvedIfAbsent(String targetId, UnresolvedComponent unresolved) {
        TreeMap<String, UnresolvedComponent> store =
                unresolvedByTarget.computeIfAbsent(targetId, k -> new TreeMap<>());
        synchronized (store) {
            return store.putIfAbsent(unresolved.key(), unresolved) == null;
        }
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

    /** 目标下全部无法判定条目，按键稳定排序。 */
    public List<UnresolvedComponent> findUnresolved(String targetId) {
        TreeMap<String, UnresolvedComponent> store = unresolvedByTarget.get(targetId);
        if (store == null) {
            return List.of();
        }
        synchronized (store) {
            return new ArrayList<>(store.values());
        }
    }

    /** 目标是否存在（曾经成功摄入过组件，或持久化过无法判定条目）。 */
    public boolean existsTarget(String targetId) {
        return targets.containsKey(targetId) || unresolvedByTarget.containsKey(targetId);
    }
}
