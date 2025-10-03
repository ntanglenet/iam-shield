package org.iamshield.storage.ldap.mappers;

import org.iamshield.common.util.PemUtils;
import org.iamshield.component.ComponentModel;
import org.iamshield.storage.ldap.LDAPStorageProvider;
import org.iamshield.storage.ldap.idm.query.Condition;
import org.iamshield.storage.ldap.idm.query.internal.EqualCondition;
import org.iamshield.storage.ldap.idm.query.internal.LDAPQuery;

public class CertificateLDAPStorageMapper extends UserAttributeLDAPStorageMapper {

  public static final String IS_DER_FORMATTED = "is.der.formatted";

  public CertificateLDAPStorageMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
    super(mapperModel, ldapProvider);
  }

  @Override
  public void beforeLDAPQuery(LDAPQuery query) {
    super.beforeLDAPQuery(query);

    String ldapAttrName = getLdapAttributeName();

    if (isDerFormatted()) {
      for (Condition condition : query.getConditions()) {
        if (condition instanceof EqualCondition &&
            condition.getParameterName().equalsIgnoreCase(ldapAttrName)) {
          EqualCondition equalCondition = ((EqualCondition) condition);
          equalCondition.setValue(PemUtils.pemToDer(equalCondition.getValue().toString()));
        }
      }
    }
  }

  private boolean isDerFormatted() {
    return mapperModel.get(IS_DER_FORMATTED, false);
  }
}

