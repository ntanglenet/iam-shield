package org.iamshield.scripting;

import javax.script.ScriptContext;

import org.iamshield.models.ScriptModel;

/**
 * Wraps a {@link ScriptModel} so it can be evaluated with custom bindings.
 *
 * @author <a href="mailto:jay@anslow.me.uk">Jay Anslow</a>
 */
public interface EvaluatableScriptAdapter {
    ScriptModel getScriptModel();

    Object eval(ScriptBindingsConfigurer bindingsConfigurer) throws ScriptExecutionException;
    Object eval(ScriptContext context) throws ScriptExecutionException;
}
