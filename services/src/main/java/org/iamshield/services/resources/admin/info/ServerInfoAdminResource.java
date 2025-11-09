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

package org.iamshield.services.resources.admin.info;

import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.resteasy.reactive.NoCache;
import org.iamshield.provider.ConfiguredPerClientProvider;
import org.iamshield.broker.provider.IdentityProvider;
import org.iamshield.broker.provider.IdentityProviderFactory;
import org.iamshield.broker.social.SocialIdentityProvider;
import org.iamshield.common.Profile;
import org.iamshield.common.Version;
import org.iamshield.common.crypto.CryptoIntegration;
import org.iamshield.common.crypto.CryptoProvider;
import org.iamshield.common.util.KeystoreUtil;
import org.iamshield.component.ComponentFactory;
import org.iamshield.crypto.ClientSignatureVerifierProvider;
import org.iamshield.events.EventType;
import org.iamshield.events.admin.OperationType;
import org.iamshield.events.admin.ResourceType;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.utils.ModelToRepresentation;
import org.iamshield.policy.PasswordPolicyProvider;
import org.iamshield.policy.PasswordPolicyProviderFactory;
import org.iamshield.protocol.ClientInstallationProvider;
import org.iamshield.protocol.LoginProtocol;
import org.iamshield.protocol.LoginProtocolFactory;
import org.iamshield.protocol.ProtocolMapper;
import org.iamshield.provider.ConfiguredProvider;
import org.iamshield.provider.ProviderConfigProperty;
import org.iamshield.provider.ProviderFactory;
import org.iamshield.provider.ServerInfoAwareProviderFactory;
import org.iamshield.provider.Spi;
import org.iamshield.representations.idm.ComponentTypeRepresentation;
import org.iamshield.representations.idm.PasswordPolicyTypeRepresentation;
import org.iamshield.representations.idm.ProtocolMapperRepresentation;
import org.iamshield.representations.idm.ProtocolMapperTypeRepresentation;
import org.iamshield.representations.info.ClientInstallationRepresentation;
import org.iamshield.representations.info.CpuInfoRepresentation;
import org.iamshield.representations.info.CryptoInfoRepresentation;
import org.iamshield.representations.info.FeatureRepresentation;
import org.iamshield.representations.info.FeatureType;
import org.iamshield.representations.info.MemoryInfoRepresentation;
import org.iamshield.representations.info.ProfileInfoRepresentation;
import org.iamshield.representations.info.ProviderRepresentation;
import org.iamshield.representations.info.ServerInfoRepresentation;
import org.iamshield.representations.info.SpiInfoRepresentation;
import org.iamshield.representations.info.SystemInfoRepresentation;
import org.iamshield.representations.info.ThemeInfoRepresentation;
import org.iamshield.services.resources.IAMShieldOpenAPI;
import org.iamshield.theme.Theme;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Extension(name = IAMShieldOpenAPI.Profiles.ADMIN , value = "")
public class ServerInfoAdminResource {

    private static final Map<String, List<String>> ENUMS = createEnumsMap(EventType.class, OperationType.class, ResourceType.class);

    private final IAMShieldSession session;

    public ServerInfoAdminResource(IAMShieldSession session) {
        this.session = session;
    }

    /**
     * Get themes, social providers, auth providers, and event listeners available on this server
     *
     * @return
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = IAMShieldOpenAPI.Admin.Tags.ROOT)
    @Operation( summary = "Get themes, social providers, auth providers, and event listeners available on this server")
    public ServerInfoRepresentation getInfo() {
        ServerInfoRepresentation info = new ServerInfoRepresentation();
        info.setSystemInfo(SystemInfoRepresentation.create(session.getIAMShieldSessionFactory().getServerStartupTimestamp(), Version.VERSION));
        info.setCpuInfo(CpuInfoRepresentation.create());
        info.setMemoryInfo(MemoryInfoRepresentation.create());
        info.setProfileInfo(createProfileInfo());
        info.setFeatures(createFeatureRepresentations());

        // True - asymmetric algorithms, false - symmetric algorithms
        Map<Boolean, List<String>> algorithms = session.getAllProviders(ClientSignatureVerifierProvider.class).stream()
                        .collect(
                                Collectors.toMap(
                                        ClientSignatureVerifierProvider::isAsymmetricAlgorithm,
                                        clientSignatureVerifier -> Collections.singletonList(clientSignatureVerifier.getAlgorithm()),
                                        (l1, l2) -> {
                                            List<String> result = listCombiner(l1, l2);
                                            return result.stream()
                                                    .sorted()
                                                    .collect(Collectors.toList());
                                        },
                                        HashMap::new
                                )
                        );
        info.setCryptoInfo(createCryptoInfo(algorithms.get(false), algorithms.get(true)));

        setSocialProviders(info);
        setIdentityProviders(info);
        setThemes(info);
        setProviders(info);
        setProtocolMapperTypes(info);
        setBuiltinProtocolMappers(info);
        setClientInstallations(info);
        setPasswordPolicies(info);
        info.setEnums(ENUMS);
        return info;
    }

    private void setProviders(ServerInfoRepresentation info) {
        info.setComponentTypes(new HashMap<>());
        LinkedHashMap<String, SpiInfoRepresentation> spiReps = new LinkedHashMap<>();

        List<Spi> spis = new LinkedList<>(session.getIAMShieldSessionFactory().getSpis());
        Collections.sort(spis, new Comparator<Spi>() {
            @Override
            public int compare(Spi s1, Spi s2) {
                return s1.getName().compareTo(s2.getName());
            }
        });

        for (Spi spi : spis) {
            SpiInfoRepresentation spiRep = new SpiInfoRepresentation();
            spiRep.setInternal(spi.isInternal());

            List<String> providerIds = new LinkedList<>(session.listProviderIds(spi.getProviderClass()));
            Collections.sort(providerIds);

            Map<String, ProviderRepresentation> providers = new HashMap<>();

            for (String name : providerIds) {
                ProviderRepresentation provider = new ProviderRepresentation();
                ProviderFactory<?> pi = session.getIAMShieldSessionFactory().getProviderFactory(spi.getProviderClass(), name);
                provider.setOrder(pi.order());
                if (ServerInfoAwareProviderFactory.class.isAssignableFrom(pi.getClass())) {
                    provider.setOperationalInfo(((ServerInfoAwareProviderFactory) pi).getOperationalInfo());
                }
                if (pi instanceof ConfiguredProvider) {
                    ComponentTypeRepresentation rep = new ComponentTypeRepresentation();
                    rep.setId(pi.getId());
                    ConfiguredProvider configured = (ConfiguredProvider)pi;
                    rep.setHelpText(configured.getHelpText());
                    List<ProviderConfigProperty> configProperties = configured.getConfigProperties();
                    if (configProperties == null) configProperties = Collections.EMPTY_LIST;
                    rep.setProperties(ModelToRepresentation.toRepresentation(configProperties));
                    if (pi instanceof ComponentFactory) {
                        rep.setMetadata(((ComponentFactory)pi).getTypeMetadata());
                    }
                    if (pi instanceof ConfiguredPerClientProvider) {
                        List<ProviderConfigProperty> configClientProperties = ((ConfiguredPerClientProvider) pi).getConfigPropertiesPerClient();
                        rep.setClientProperties(ModelToRepresentation.toRepresentation(configClientProperties));
                    }
                    List<ComponentTypeRepresentation> reps = info.getComponentTypes().get(spi.getProviderClass().getName());
                    if (reps == null) {
                        reps = new LinkedList<>();
                        info.getComponentTypes().put(spi.getProviderClass().getName(), reps);
                    }
                    reps.add(rep);
                }
                providers.put(name, provider);
            }
            spiRep.setProviders(providers);

            spiReps.put(spi.getName(), spiRep);
        }
        info.setProviders(spiReps);
    }

    private void setThemes(ServerInfoRepresentation info) {
        info.setThemes(new HashMap<>());

        for (Theme.Type type : Theme.Type.values()) {
            List<String> themeNames = filterThemes(type, new LinkedList<>(session.theme().nameSet(type)));
            Collections.sort(themeNames);

            List<ThemeInfoRepresentation> themes = new LinkedList<>();
            info.getThemes().put(type.toString().toLowerCase(), themes);

            for (String name : themeNames) {
                try {
                    Theme theme = session.theme().getTheme(name, type);
                    // Different name means the theme itself was not found and fallback to default theme was needed
                    if (theme != null && name.equals(theme.getName())) {
                        ThemeInfoRepresentation ti = new ThemeInfoRepresentation();
                        ti.setName(name);

                        String locales = theme.getProperties().getProperty("locales");
                        if (locales != null) {
                            ti.setLocales(locales.replaceAll(" ", "").split(","));
                        }

                        themes.add(ti);
                    }
                } catch (IOException e) {
                    throw new WebApplicationException("Failed to load themes", e);
                }
            }
        }
    }

    private LinkedList<String> filterThemes(Theme.Type type, LinkedList<String> themeNames) {
        LinkedList<String> filteredNames = new LinkedList<>(themeNames);
        boolean filterAdminV2 = (type == Theme.Type.ADMIN) &&
                !Profile.isFeatureEnabled(Profile.Feature.ADMIN_V2);
        boolean filterLoginV2 = (type == Theme.Type.LOGIN) &&
                !Profile.isFeatureEnabled(Profile.Feature.LOGIN_V2);

        if (filterAdminV2 || filterLoginV2) {
            filteredNames.remove("keycloak.v2");
            filteredNames.remove("rh-sso.v2");
        }

        boolean filterAccountV3 = (type == Theme.Type.ACCOUNT) &&
            !Profile.isFeatureEnabled(Profile.Feature.ACCOUNT_V3);

        if (filterAccountV3) {
            filteredNames.remove("keycloak.v3");
        }

        return filteredNames;
    }

    private void setSocialProviders(ServerInfoRepresentation info) {
        info.setSocialProviders(new LinkedList<>());
        Stream<ProviderFactory> providerFactories = session.getIAMShieldSessionFactory().getProviderFactoriesStream(SocialIdentityProvider.class);
        setIdentityProviders(providerFactories, info.getSocialProviders(), "Social");
    }

    private void setIdentityProviders(ServerInfoRepresentation info) {
        info.setIdentityProviders(new LinkedList<>());
        Stream<ProviderFactory> providerFactories = session.getIAMShieldSessionFactory().getProviderFactoriesStream(IdentityProvider.class);
        setIdentityProviders(providerFactories, info.getIdentityProviders(), "User-defined");

        providerFactories = session.getIAMShieldSessionFactory().getProviderFactoriesStream(SocialIdentityProvider.class);
        setIdentityProviders(providerFactories, info.getIdentityProviders(), "Social");
    }

    public void setIdentityProviders(Stream<ProviderFactory> factories, List<Map<String, String>> providers, String groupName) {
        List<Map<String, String>> providerMaps = factories
                .map(IdentityProviderFactory.class::cast)
                .map(factory -> {
                    Map<String, String> data = new HashMap<>();
                    data.put("groupName", groupName);
                    data.put("name", factory.getName());
                    data.put("id", factory.getId());
                    return data;
                })
                .collect(Collectors.toList());

        providers.addAll(providerMaps);
    }

    private void setClientInstallations(ServerInfoRepresentation info) {
        HashMap<String, List<ClientInstallationRepresentation>> clientInstallations = session.getIAMShieldSessionFactory()
                .getProviderFactoriesStream(ClientInstallationProvider.class)
                .map(ClientInstallationProvider.class::cast)
                .collect(
                        Collectors.toMap(
                                ClientInstallationProvider::getProtocol,
                                this::toClientInstallationRepresentation,
                                (l1, l2) -> listCombiner(l1, l2),
                                HashMap::new
                        )
                );
        info.setClientInstallations(clientInstallations);

    }

    private void setProtocolMapperTypes(ServerInfoRepresentation info) {
        HashMap<String, List<ProtocolMapperTypeRepresentation>> protocolMappers = session.getIAMShieldSessionFactory()
                .getProviderFactoriesStream(ProtocolMapper.class)
                .map(ProtocolMapper.class::cast)
                .collect(
                        Collectors.toMap(
                                ProtocolMapper::getProtocol,
                                this::toProtocolMapperTypeRepresentation,
                                (l1, l2) -> listCombiner(l1, l2),
                                HashMap::new
                        )
                );
        info.setProtocolMapperTypes(protocolMappers);
    }

    private void setBuiltinProtocolMappers(ServerInfoRepresentation info) {
        Map<String, List<ProtocolMapperRepresentation>> protocolMappers = session.getIAMShieldSessionFactory()
                .getProviderFactoriesStream(LoginProtocol.class)
                .collect(Collectors.toMap(
                        p -> p.getId(),
                        p -> {
                            LoginProtocolFactory factory = (LoginProtocolFactory) p;
                            return factory.getBuiltinMappers().values().stream()
                                    .map(ModelToRepresentation::toRepresentation)
                                    .collect(Collectors.toList());
                        })
                );
        info.setBuiltinProtocolMappers(protocolMappers);
    }

    private void setPasswordPolicies(ServerInfoRepresentation info) {
        List<PasswordPolicyTypeRepresentation> passwordPolicyTypes= session.getIAMShieldSessionFactory().getProviderFactoriesStream(PasswordPolicyProvider.class)
                .map(PasswordPolicyProviderFactory.class::cast)
                .map(factory -> {
                    PasswordPolicyTypeRepresentation rep = new PasswordPolicyTypeRepresentation();
                    rep.setId(factory.getId());
                    rep.setDisplayName(factory.getDisplayName());
                    rep.setConfigType(factory.getConfigType());
                    rep.setDefaultValue(factory.getDefaultConfigValue());
                    rep.setMultipleSupported(factory.isMultiplSupported());
                    return rep;
                })
                .collect(Collectors.toList());
        info.setPasswordPolicies(passwordPolicyTypes);
    }

    private List<ClientInstallationRepresentation> toClientInstallationRepresentation(ClientInstallationProvider provider) {
        ClientInstallationRepresentation rep = new ClientInstallationRepresentation();
        rep.setId(provider.getId());
        rep.setHelpText(provider.getHelpText());
        rep.setDisplayType( provider.getDisplayType());
        rep.setProtocol( provider.getProtocol());
        rep.setDownloadOnly( provider.isDownloadOnly());
        rep.setFilename(provider.getFilename());
        rep.setMediaType(provider.getMediaType());
        return Arrays.asList(rep);
    }

    private List<ProtocolMapperTypeRepresentation> toProtocolMapperTypeRepresentation(ProtocolMapper mapper) {
        ProtocolMapperTypeRepresentation rep = new ProtocolMapperTypeRepresentation();
        rep.setId(mapper.getId());
        rep.setName(mapper.getDisplayType());
        rep.setHelpText(mapper.getHelpText());
        rep.setCategory(mapper.getDisplayCategory());
        rep.setPriority(mapper.getPriority());
        List<ProviderConfigProperty> configProperties = mapper.getConfigProperties();
        rep.setProperties(ModelToRepresentation.toRepresentation(configProperties));
        return Arrays.asList(rep);
    }

    private static <T> List<T> listCombiner(List<T> list1, List<T> list2) {
        return Stream.concat(list1.stream(), list2.stream()).collect(Collectors.toList());
    }

    private static Map<String, List<String>> createEnumsMap(Class... enums) {
        Map<String, List<String>> m = new HashMap<>();
        for (Class e : enums) {
            String n = e.getSimpleName();
            n = Character.toLowerCase(n.charAt(0)) + n.substring(1);

            List<String> l = new LinkedList<>();
            for (Object c :  e.getEnumConstants()) {
                l.add(c.toString());
            }
            Collections.sort(l);

            m.put(n, l);
        }
        return m;
    }

    private ProfileInfoRepresentation createProfileInfo() {
        ProfileInfoRepresentation info = new ProfileInfoRepresentation();

        Profile profile = Profile.getInstance();

        info.setName(profile.getName().name().toLowerCase());
        info.setDisabledFeatures(names(profile.getDisabledFeatures()));
        info.setPreviewFeatures(names(profile.getPreviewFeatures()));
        info.setExperimentalFeatures(names(profile.getExperimentalFeatures()));

        return info;
    }

    private static List<String> names(Set<Profile.Feature> featureSet) {
        List<String> l = new LinkedList();
        for (Profile.Feature f : featureSet) {
            l.add(f.name());
        }
        return l;
    }


    private static FeatureRepresentation getFeatureRep(Profile.Feature feature, boolean isEnabled) {
        FeatureRepresentation featureRep = new FeatureRepresentation();
        featureRep.setName(feature.name());
        featureRep.setLabel(feature.getLabel());
        featureRep.setType(FeatureType.valueOf(feature.getType().name()));
        featureRep.setEnabled(isEnabled);
        featureRep.setDependencies(feature.getDependencies() != null ?
                feature.getDependencies().stream().map(Enum::name).collect(Collectors.toSet()) : Collections.emptySet());
        return featureRep;
    }

    private static List<FeatureRepresentation> createFeatureRepresentations() {
        List<FeatureRepresentation> featureRepresentationList = new ArrayList<>();
        Profile profile = Profile.getInstance();
        final Map<Profile.Feature, Boolean> features = profile.getFeatures();
        features.forEach((f, enabled) -> featureRepresentationList.add(getFeatureRep(f, enabled)));
        return featureRepresentationList;
    }

    private static CryptoInfoRepresentation createCryptoInfo(List<String> clientSignatureSymmetricAlgorithms, List<String> clientSignatureAsymmetricAlgorithms) {
        CryptoInfoRepresentation info = new CryptoInfoRepresentation();

        CryptoProvider cryptoProvider = CryptoIntegration.getProvider();
        info.setCryptoProvider(cryptoProvider.getClass().getSimpleName());
        info.setSupportedKeystoreTypes(CryptoIntegration.getProvider().getSupportedKeyStoreTypes()
                .map(KeystoreUtil.KeystoreFormat::toString)
                .collect(Collectors.toList()));
        info.setClientSignatureSymmetricAlgorithms(clientSignatureSymmetricAlgorithms);
        info.setClientSignatureAsymmetricAlgorithms(clientSignatureAsymmetricAlgorithms);

        return info;
    }

}
