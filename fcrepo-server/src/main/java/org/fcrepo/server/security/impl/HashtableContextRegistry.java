package org.fcrepo.server.security.impl;

import java.util.Hashtable;

import org.fcrepo.server.Context;
import org.fcrepo.server.security.ContextRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class HashtableContextRegistry implements ContextRegistry {

    private static final Logger logger = LoggerFactory.getLogger(HashtableContextRegistry.class);

    private final Hashtable<Object, Context> contexts = new Hashtable<Object, Context>();

    @Override
    public final void registerContext(Object key, Context value) {
        logger.debug("registering {}", key);
        contexts.put(key, value);
    }

    @Override
    public final void unregisterContext(Object key) {
        logger.debug("unregistering {}", key);
        contexts.remove(key);
    }


    @Override
    public Context getContext(Object key) {
        return contexts.get(key);
    }

}
