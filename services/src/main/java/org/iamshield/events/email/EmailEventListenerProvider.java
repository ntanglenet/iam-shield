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

package org.iamshield.events.email;

import static org.iamshield.models.utils.IAMShieldModelUtils.runJobInTransaction;

import org.jboss.logging.Logger;
import org.iamshield.email.EmailException;
import org.iamshield.email.EmailTemplateProvider;
import org.iamshield.events.Event;
import org.iamshield.events.EventListenerProvider;
import org.iamshield.events.EventListenerTransaction;
import org.iamshield.events.EventType;
import org.iamshield.events.admin.AdminEvent;
import org.iamshield.http.HttpRequest;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldContext;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.IAMShieldSessionTask;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RealmProvider;
import org.iamshield.models.UserModel;

import java.util.Set;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class EmailEventListenerProvider implements EventListenerProvider {

    private static final Logger log = Logger.getLogger(EmailEventListenerProvider.class);

    private IAMShieldSession session;
    private RealmProvider model;
    private Set<EventType> includedEvents;
    private EventListenerTransaction tx = new EventListenerTransaction(null, this::sendEmail);
    private final IAMShieldSessionFactory sessionFactory;

    public EmailEventListenerProvider(IAMShieldSession session, Set<EventType> includedEvents) {
        this.session = session;
        this.model = session.realms();
        this.includedEvents = includedEvents;
        this.session.getTransactionManager().enlistAfterCompletion(tx);
        this.sessionFactory = session.getIAMShieldSessionFactory();
    }

    @Override
    public void onEvent(Event event) {
        if (includedEvents.contains(event.getType())) {
            if (event.getRealmId() != null && event.getUserId() != null) {
                tx.addEvent(event);
            }
        }
    }
    
    private void sendEmail(Event event) {
        HttpRequest request = session.getContext().getHttpRequest();

        runJobInTransaction(sessionFactory, new IAMShieldSessionTask() {
            @Override
            public void run(IAMShieldSession session) {
                IAMShieldContext context = session.getContext();
                RealmModel realm = session.realms().getRealm(event.getRealmId());

                context.setRealm(realm);

                String clientId = event.getClientId();

                if (clientId != null) {
                    ClientModel client = realm.getClientByClientId(clientId);
                    context.setClient(client);
                }

                context.setHttpRequest(request);

                UserModel user = session.users().getUserById(realm, event.getUserId());

                if (user != null && user.getEmail() != null && user.isEmailVerified()) {
                    try {
                        EmailTemplateProvider emailTemplateProvider = session.getProvider(EmailTemplateProvider.class);
                        emailTemplateProvider.setRealm(realm).setUser(user).sendEvent(event);
                    } catch (EmailException e) {
                        log.error("Failed to send type mail", e);
                    }
                }
            }
        });
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {

    }

    @Override
    public void close() {
    }

}
