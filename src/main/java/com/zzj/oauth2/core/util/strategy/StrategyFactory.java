package com.zzj.oauth2.core.util.strategy;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class StrategyFactory<K, S extends Strategy<K>> implements ApplicationContextAware {

    private final Class<S> clazz;

    private Map<K, S> strategyMap;

    @Override
    public void setApplicationContext(ApplicationContext context) throws BeansException {
        Map<String, S> beans = context.getBeansOfType(clazz);
        if (CollectionUtils.isEmpty(beans)) {
            return;
        }
        strategyMap = Collections.unmodifiableMap(beans.values().stream().collect(Collectors.toMap(Strategy::getKey, Function.identity())));
    }

    public S getStrategy(K key) {
        return strategyMap.get(key);
    }
}