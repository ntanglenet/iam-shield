/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.testsuite.util.cli;

import org.jboss.logging.Logger;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.testsuite.IAMShieldServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * See Testsuite.md (section how to create many users and offline sessions)
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TestsuiteCLI {

    private static final Logger log = Logger.getLogger(TestsuiteCLI.class);

    private static final Class<?>[] BUILTIN_COMMANDS = {
            ExitCommand.class,
            HelpCommand.class,
            AbstractSessionCacheCommand.PutCommand.class,
            AbstractSessionCacheCommand.GetCommand.class,
            AbstractSessionCacheCommand.GetMultipleCommand.class,
            AbstractSessionCacheCommand.GetLocalCommand.class,
            AbstractSessionCacheCommand.SizeLocalCommand.class,
            AbstractSessionCacheCommand.RemoveCommand.class,
            AbstractSessionCacheCommand.SizeCommand.class,
            AbstractSessionCacheCommand.ListCommand.class,
            AbstractSessionCacheCommand.ClearCommand.class,
            AbstractSessionCacheCommand.CreateManySessionsCommand.class,
            AbstractSessionCacheCommand.CreateManySessionsProviderCommand.class,
            PersistSessionsCommand.class,
            LoadPersistentSessionsCommand.class,
            UserCommands.Create.class,
            UserCommands.Remove.class,
            UserCommands.Count.class,
            UserCommands.GetUser.class,
            GroupCommands.Create.class,
            SyncDummyFederationProviderCommand.class,
            RoleCommands.CreateRoles.class,
            CacheCommands.ListCachesCommand.class,
            CacheCommands.GetCacheCommand.class,
            CacheCommands.CacheRealmObjectsCommand.class,
            ClusterProviderTaskCommand.class,
            LdapManyObjectsInitializerCommand.class,
            LdapManyGroupsInitializerCommand.class
    };

    private final IAMShieldSessionFactory sessionFactory;
    private final Map<String, Class<? extends AbstractCommand>> commands = new LinkedHashMap<>();

    public TestsuiteCLI(IAMShieldServer server) {
        this.sessionFactory = server.getSessionFactory();

        // register builtin commands
        for (Class<?> clazz : BUILTIN_COMMANDS) {
            Class<? extends AbstractCommand> commandClazz = (Class<? extends AbstractCommand>) clazz;
            try {
                AbstractCommand command = commandClazz.newInstance();
                commands.put(command.getName(), commandClazz);
            } catch (Exception ex) {
                log.error("Error registering command of class: " + commandClazz.getName(), ex);
            }
        }
    }

    public void registerCommand(String name, Class<? extends AbstractCommand> command) {
        commands.put(name, command);
    }

    // WARNING: Stdin blocking operation
    public void start() throws IOException {
        log.info("Starting testsuite CLI. Exit with 'exit' . Available commands with 'help' ");

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String line;
        System.out.print("$ ");
        try {
            while ((line = reader.readLine()) != null) {
                String[] splits = line.split(" ");
                String commandName = splits[0];
                Class<? extends AbstractCommand> commandClass = commands.get(commandName);
                if (commandClass == null) {
                    log.errorf("Unknown command: %s", commandName);
                } else {
                    try {
                        AbstractCommand command = commandClass.newInstance();
                        List<String> args = new ArrayList<>(Arrays.asList(splits));
                        args.remove(0);
                        command.injectProperties(args, this, sessionFactory);
                        command.runCommand();

                        // Just special handling of ExitCommand
                        if (command instanceof ExitCommand) {
                            return;
                        }

                    } catch (InstantiationException ex) {
                        log.error(ex);
                    } catch (IllegalAccessException ex) {
                        log.error(ex);
                    }
                }

                System.out.print("$ ");
            }
        } finally {
            log.info("Exit testsuite CLI");
            reader.close();
        }
    }

    public static class ExitCommand extends AbstractCommand {

        @Override
        public String getName() {
            return "exit";
        }

        @Override
        public void runCommand() {
            // no need to implement. Exit handled in parent
        }

        @Override
        protected void doRunCommand(IAMShieldSession session) {
            // no need to implement
        }

        @Override
        public String printUsage() {
            return getName();
        }
    }

    public static class HelpCommand extends AbstractCommand {

        private List<String> commandNames = new ArrayList<>();

        @Override
        public void injectProperties(List<String> args, TestsuiteCLI cli, IAMShieldSessionFactory sessionFactory) {
            for (String commandName : cli.commands.keySet()) {
                commandNames.add(commandName);
            }
        }

        @Override
        public String getName() {
            return "help";
        }

        @Override
        public void runCommand() {
            log.info("Available commands: " + commandNames.toString());
        }

        @Override
        protected void doRunCommand(IAMShieldSession session) {
            // no need to implement
        }
    }
}
