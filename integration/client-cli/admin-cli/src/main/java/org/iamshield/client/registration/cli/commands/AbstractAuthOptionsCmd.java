package org.iamshield.client.registration.cli.commands;

import org.iamshield.client.cli.common.BaseAuthOptionsCmd;
import org.iamshield.client.registration.cli.KcRegMain;

import picocli.CommandLine.Option;

/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public abstract class AbstractAuthOptionsCmd extends BaseAuthOptionsCmd {

    @Option(names = {"-t", "--token"}, description = "Initial / Registration access token to use)")
    public void setToken(String token) {
        this.externalToken = token;
    }

    public AbstractAuthOptionsCmd() {
        super(KcRegMain.COMMAND_STATE);
    }

}
