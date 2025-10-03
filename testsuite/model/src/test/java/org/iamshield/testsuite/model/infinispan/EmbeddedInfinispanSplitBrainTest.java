package org.iamshield.testsuite.model.infinispan;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.iamshield.connections.infinispan.InfinispanConnectionProvider.WORK_CACHE_NAME;

import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Assume;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.iamshield.common.Profile;
import org.iamshield.connections.infinispan.InfinispanConnectionProvider;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.cache.CacheRealmProvider;
import org.iamshield.testsuite.model.IAMShieldModelTest;
import org.iamshield.testsuite.model.RequireProvider;

/**
  Tests to ensure that Keycloak correctly handles various split-brain scenarios when an Embedded Infinispan instance
  is used for clustering.
 */
@RequireProvider(CacheRealmProvider.class)
@RequireProvider(InfinispanConnectionProvider.class)
public class EmbeddedInfinispanSplitBrainTest extends IAMShieldModelTest {

   private String realmId;

   @ClassRule
   public static final TestRule SKIPPED_PROFILES = (base, description) -> {
      // We skip split-brain tests for the REMOTE_CACHE and MULTI_SITE features as neither of these architectures
      // utilise embedded distributed/replicated caches
      Assume.assumeFalse(Profile.isFeatureEnabled(Profile.Feature.CLUSTERLESS));
      Assume.assumeFalse(Profile.isFeatureEnabled(Profile.Feature.MULTI_SITE));
      return base;
   };

   @Override
   public void createEnvironment(IAMShieldSession s) {
      RealmModel realm = createRealm(s, "test");
      s.getContext().setRealm(realm);
      realm.setDefaultRole(s.roles().addRealmRole(realm, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + realm.getName()));
      this.realmId = realm.getId();
      s.users().addUser(realm, "user1").setEmail("user1@localhost");
   }

   /**
    * A Test to ensure that when Infinispan recovers from a split-brain event, all Keycloak local caches are cleared
    * and subsequent user requests read from the DB.
    * <p>
    * <a href="https://github.com/keycloak/keycloak/issues/25837" />
    */
   @Test
   public void testLocalCacheClearedOnMergeEvent() throws InterruptedException {
      var numFactories = 2;
      var partitionManager = new PartitionManager(numFactories, Set.of(WORK_CACHE_NAME));
      var factoryIndex = new AtomicInteger(0);
      var addManagerLatch = new CountDownLatch(numFactories);
      var splitLatch = new CountDownLatch(1);
      var mergeLatch = new CountDownLatch(1);
      closeIAMShieldSessionFactory();
      inIndependentFactories(numFactories, 60, () -> {
         var customDisplayName = "custom-value";
         var index = factoryIndex.getAndIncrement();

         // Init PartitionManager
         withRealmConsumer(realmId, (session, realm) -> {
            var cm = session.getProvider(InfinispanConnectionProvider.class)
                  .getCache(InfinispanConnectionProvider.USER_CACHE_NAME)
                  .getCacheManager();
            partitionManager.addManager(index, cm);
            addManagerLatch.countDown();
         });
         awaitLatch(addManagerLatch);

         // Split the cluster and update the realm on the 1st partition
         if (index == 0) {
            partitionManager.splitCluster(new int[]{0}, new int[]{1});
            withRealmConsumer(realmId, (session, realm) -> realm.setDisplayNameHtml(customDisplayName));
            splitLatch.countDown();
         }
         awaitLatch(splitLatch);

         // Assert that the display name has not been updated on the 2nd partition
         if (index == 1) {
            withRealmConsumer(realmId, (session, realm) -> assertNotEquals(customDisplayName, realm.getDisplayNameHtml()));
         }

         // Heal the cluster by merging the two partitions
         if (index == 0) {
            partitionManager.merge(0, 1);
            mergeLatch.countDown();
         }
         awaitLatch(mergeLatch);

         // Ensure that both nodes see the updated realm entity after merge
         withRealmConsumer(realmId, (session, realm) -> assertEquals(customDisplayName, realm.getDisplayNameHtml()));
      });
   }

   private void awaitLatch(CountDownLatch latch) {
      try {
         assertTrue(latch.await(10, TimeUnit.SECONDS));
      } catch (InterruptedException e) {
         Thread.currentThread().interrupt();
         throw new RuntimeException(e);
      }
   }
}
