package org.iamshield.testframework.injection;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.admin.client.IAMShield;
import org.iamshield.testframework.server.IAMShieldServer;

import java.util.Map;

public class ValueTypeAliasTest {

    @Test
    public void withAlias() {
        ValueTypeAlias valueTypeAlias = new ValueTypeAlias();
        valueTypeAlias.addAll(Map.of(IAMShieldServer.class, "server"));
        Assertions.assertEquals("server", valueTypeAlias.getAlias(IAMShieldServer.class));
    }

    @Test
    public void withoutAlias() {
        Assertions.assertEquals("IAMShield", new ValueTypeAlias().getAlias(IAMShield.class));
    }

}
