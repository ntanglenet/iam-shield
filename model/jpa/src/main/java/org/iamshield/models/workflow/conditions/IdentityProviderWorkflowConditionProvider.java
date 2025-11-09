package org.iamshield.models.workflow.conditions;

import java.util.List;
import java.util.stream.Stream;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;
import org.iamshield.models.FederatedIdentityModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.jpa.entities.FederatedIdentityEntity;
import org.iamshield.models.workflow.WorkflowConditionProvider;
import org.iamshield.models.workflow.WorkflowEvent;
import org.iamshield.models.workflow.WorkflowInvalidStateException;
import org.iamshield.models.workflow.ResourceType;

public class IdentityProviderWorkflowConditionProvider implements WorkflowConditionProvider {

    private final List<String> expectedAliases;
    private final IAMShieldSession session;

    public IdentityProviderWorkflowConditionProvider(IAMShieldSession session, List<String> expectedAliases) {
        this.session = session;
        this.expectedAliases = expectedAliases;;
    }

    @Override
    public boolean evaluate(WorkflowEvent event) {
        if (!ResourceType.USERS.equals(event.getResourceType())) {
            return false;
        }

        validate();

        String userId = event.getResourceId();
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, userId);
        Stream<FederatedIdentityModel> federatedIdentities = session.users().getFederatedIdentitiesStream(realm, user);

        return federatedIdentities
                .map(FederatedIdentityModel::getIdentityProvider)
                .anyMatch(expectedAliases::contains);
    }

    @Override
    public Predicate toPredicate(CriteriaBuilder cb, CriteriaQuery<String> query, Root<?> path) {
        Subquery<Integer> subquery = query.subquery(Integer.class);
        Root<FederatedIdentityEntity> from = subquery.from(FederatedIdentityEntity.class);

        subquery.select(cb.literal(1));
        subquery.where(
                cb.and(
                        cb.equal(from.get("user").get("id"), path.get("id")),
                        from.get("identityProvider").in(expectedAliases)
                )
        );

        return cb.exists(subquery);
    }

    @Override
    public void validate() {
        expectedAliases.forEach(alias -> {
            if (session.identityProviders().getByAlias(alias) == null) {
                throw new WorkflowInvalidStateException(String.format("Identity provider %s does not exist.", alias));
            }
        });
    }

    @Override
    public void close() {

    }
}
