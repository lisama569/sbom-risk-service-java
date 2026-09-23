package com.github.lisama569.sbomriskservicejava.ingest;

import com.github.lisama569.sbomriskservicejava.model.Component;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory component store keyed by the stable component key.
 *
 * <p>{@link #put} is atomic: a repeated submission (same key) never creates a
 * second record and reports {@link StoreOutcome#DUPLICATE}. Iteration order is
 * insertion order so listings and assessments are stable and reproducible.
 */
@Repository
public class ComponentStore {

    private final ConcurrentMap<String, Component> components = new ConcurrentHashMap<>();

    /**
     * Atomically store a component.
     *
     * @return STORED when newly inserted, DUPLICATE when the key already existed
     */
    public StoreOutcome put(Component component, String documentId) {
        Component previous = components.putIfAbsent(component.key(), component);
        return previous == null ? StoreOutcome.STORED : StoreOutcome.DUPLICATE;
    }

    public Optional<Component> findByKey(String key) {
        return Optional.ofNullable(components.get(key));
    }

    public List<Component> findAll() {
        return components.values().stream()
                .sorted(java.util.Comparator.comparing(Component::key))
                .toList();
    }

    /** Outcome of a store put. */
    public enum StoreOutcome {
        STORED,
        DUPLICATE
    }
}
