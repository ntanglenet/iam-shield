package org.iamshield.testframework.remote.providers.runonserver;

import org.iamshield.common.VerificationException;
import org.iamshield.models.IAMShieldSession;

import java.io.IOException;
import java.io.Serializable;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public interface RunOnServer extends Serializable {

    void run(IAMShieldSession session) throws IOException, VerificationException;

}
