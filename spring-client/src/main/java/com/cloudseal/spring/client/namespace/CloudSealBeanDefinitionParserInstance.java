/* Copyright 2011 Cloudseal O†
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cloudseal.spring.client.namespace;

import static org.springframework.util.xml.DomUtils.getChildElementByTagName;
import static org.springframework.util.xml.DomUtils.getChildElementsByTagName;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.MutablePropertyValues;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConstructorArgumentValues;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.*;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.w3c.dom.Element;

import com.cloudseal.spring.client.userdetails.SAMLUserDetailsServiceAdapter;

public class CloudSealBeanDefinitionParserInstance {

    private static final Logger LOGGER = LoggerFactory.getLogger(CloudSealBeanDefinitionParserInstance.class);

    private static final String SPRING_AUTH_MANAGER_ID = "org.springframework.security.authenticationManager";
    private static final String SPRING_FILTER_CHAIN_ID = "org.springframework.security.filterChainProxy";

    private static final String ROOT_ENDPOINT_ATTRIBUTE = "endpoint";
    private static final String ROOT_ENTRY_POINT_ID_ATTRIBUTE = "entry-point-id";
    private static final String ROOT_APP_ID_ATTRIBUTE = "app-id";
    private static final String ROOT_USER_DETAILS_SERVICE_REF_ATTRIBUTE = "user-details-service-ref";
    private static final String ROOT_WEB_SSO_PROFILE_REF_ATTRIBUTE = "web-sso-profile-ref";
    private static final String ROOT_WEB_SSO_PROFILE_CONSUMER_REF_ATTRIBUTE = "web-sso-profile-consumer-ref";
    private static final String ROOT_CONTEXT_PROVIDER_REF_ATTRIBUTE = "context-provider-ref";
    private static final String ROOT_METADATA_DISPLAY_FILTER_REF_ATTRIBUTE = "metadata-display-filter-ref";
    private static final String ROOT_METADATA_GENERATOR_FILTER_REF_ATTRIBUTE = "metadata-generator-filter-ref";
    private static final String ROOT_SINGLE_LOGOUT_PROFILE_REF_ATTRIBUTE = "single-logout-profile-ref";
    private static final String ROOT_LOGOUT_FILTER_URL_ATTRIBUTE = "logout-url";
    private static final String DEFAULT_LOGOUT_FILTER_URL_ATTRIBUTE = "/cslogout";
    private static final String AUTHENTICATION_PROVIDER_NODE = "authentication-provider";
    private static final String AUTHENTICATION_PROVIDER_ID_ATTRIBUTE = "id";

    private static final String METADATA_NODE = "metadata";
    private static final String METADATA_LOCATION_ATTRIBUTE = "location";

    private static final String KEYSTORE_NODE = "keystore";
    private static final String KEYSTORE_LOCATION_ATTRIBUTE = "location";
    private static final String KEYSTORE_PASSWORD_ATTRIBUTE = "password";
    private static final String KEYSTORE_KEY_NODE = "key";
    private static final String KEYSTORE_KEY_NAME_ATTRIBUTE = "name";
    private static final String KEYSTORE_KEY_PASSWORD_ATTRIBUTE = "password";

    private final Element rootNode;
    private final ParserContext parserContext;

    private final BeanDefinition logger;
    private final BeanDefinition contextProvider;
    private final BeanDefinition parserPool;
    private final BeanDefinition processor;

    public CloudSealBeanDefinitionParserInstance(Element rootNode, ParserContext parserContext) {
        this.rootNode = rootNode;
        this.parserContext = parserContext;

        logger = createAndRegisterBean(SAMLDefaultLogger.class);
        contextProvider = getExistingOrCreateBean(getAttribute(ROOT_CONTEXT_PROVIDER_REF_ATTRIBUTE),
                SAMLContextProviderImpl.class, true);
        parserPool = createAndRegisterParserPool();
        processor = createAndRegisterSAMLProcessor();

        parse();
    }

    private void parse() {
        BeanDefinition authenticationProvider = createAuthenticationProvider();
        BeanDefinition authenticationManager = updateOrCreateAuthenticationManager(authenticationProvider);

        createAndRegisterBean(SAMLBootstrap.class);
        createAndRegisterSSOProfile();
        BeanDefinition entryPoint = parseAndRegisterEntryPoint();

        parseAndRegisterKeyManager();
        parseAndRegisterMetadataManager();
        createAndRegisterFilters(authenticationManager, entryPoint);
    }

    private String getAttribute(String name) {
        return rootNode.getAttribute(name);
    }

    private BeanDefinition getExistingOrCreateBean(String existingId, Class<?> clazz) {
        return getExistingOrCreateBean(existingId, clazz, false);
    }

    private BeanDefinition getExistingOrCreateBean(String existingId, Class<?> clazz, boolean register) {
        if (existingId != null && !existingId.isEmpty()) {
            BeanDefinitionRegistry registry = parserContext.getRegistry();
            if (registry.containsBeanDefinition(existingId)) {
                return registry.getBeanDefinition(existingId);
            }
        }
        if (register) {
            return createAndRegisterBean(clazz);
        }
        return createBean(clazz).getBeanDefinition();
    }

    private BeanDefinition createAndRegisterParserPool() {
        BeanDefinitionBuilder builder = createBean(BasicParserPool.class);
        builder.setScope("singleton");
        return registerBean(builder);
    }

    private void parseAndRegisterKeyManager() {
        Element keyManagerNode = getRequiredElement(rootNode, KEYSTORE_NODE);
        Map<String, String> keys = new ManagedMap<String, String>();
        List<Element> keyNodes = getChildElementsByTagName(keyManagerNode, KEYSTORE_KEY_NODE);
        if (keyNodes.isEmpty())
            throw missingElementException(KEYSTORE_KEY_NODE);
        String defaultKey = null;
        for (Element keyNode : keyNodes) {
            String key = getRequiredAttribute(keyNode, KEYSTORE_KEY_NAME_ATTRIBUTE);
            String password = getRequiredAttribute(keyNode, KEYSTORE_KEY_PASSWORD_ATTRIBUTE);
            keys.put(key, password);
            if (defaultKey == null)
                defaultKey = key;
        }

        String location = getRequiredAttribute(keyManagerNode, KEYSTORE_LOCATION_ATTRIBUTE);
        String filePassword = getRequiredAttribute(keyManagerNode, KEYSTORE_PASSWORD_ATTRIBUTE);

        BeanDefinitionBuilder builder = createBean(JKSKeyManager.class);
        builder.addConstructorArgValue(getResourceFromLocation(location));
        builder.addConstructorArgValue(filePassword);
        builder.addConstructorArgValue(keys);
        builder.addConstructorArgValue(defaultKey);
        registerBean(builder);
    }

    private void parseAndRegisterMetadataManager() {
        String defaultIDP = getRequiredAttribute(rootNode, ROOT_ENDPOINT_ATTRIBUTE);

        Element node = getRequiredElement(rootNode, METADATA_NODE);
        Collection<BeanDefinition> metadataDelegates = new ManagedList<BeanDefinition>();
        metadataDelegates.add(createMetadataDelegate(node));

        BeanDefinitionBuilder builder = createBean(CachingMetadataManager.class);
        builder.addConstructorArgValue(metadataDelegates);
        builder.addPropertyValue("defaultIDP", defaultIDP);
        registerBean(builder);
    }

    private BeanDefinition createMetadataDelegate(Element metadataNode) {
        BeanDefinitionBuilder builder = createBean(ExtendedMetadataDelegate.class);
        builder.addConstructorArgValue(createMetadataProvider(metadataNode));
        builder.addConstructorArgValue(createBean(ExtendedMetadata.class).getBeanDefinition());
        return builder.getBeanDefinition();
    }

    private BeanDefinition createMetadataProvider(Element metadataNode) {
        String location = getRequiredAttribute(metadataNode, METADATA_LOCATION_ATTRIBUTE);
        BeanDefinitionBuilder builder = createBean(FilesystemMetadataProvider.class);
        builder.addConstructorArgValue(getFileFromLocation(location));
        builder.addPropertyValue("parserPool", parserPool);
        return builder.getBeanDefinition();
    }

    private BeanDefinition createAndRegisterSAMLProcessor() {
        Collection<BeanDefinition> bindings = new ManagedList<BeanDefinition>();
        bindings.add(createRedirectBinding());
        bindings.add(createPostBinding());

        BeanDefinitionBuilder builder = createBean(SAMLProcessorImpl.class);
        builder.addConstructorArgValue(bindings);
        BeanDefinition bean = builder.getBeanDefinition();
        return registerBean(bean);
    }

    private BeanDefinition createRedirectBinding() {
        BeanDefinitionBuilder builder = createBean(HTTPRedirectDeflateBinding.class);
        builder.addConstructorArgValue(parserPool);
        return builder.getBeanDefinition();
    }

    private BeanDefinition createPostBinding() {
        BeanDefinitionBuilder builder = createBean(HTTPPostBinding.class);
        builder.addConstructorArgValue(parserPool);
        builder.addConstructorArgValue(createVelocityEngine());
        return builder.getBeanDefinition();
    }

    private BeanDefinition createVelocityEngine() {
        BeanDefinitionBuilder builder = createBean(VelocityFactory.class);
        builder.setFactoryMethod("getEngine");
        return builder.getBeanDefinition();
    }

    private BeanDefinition createAuthenticationProvider() {
        BeanDefinitionBuilder builder = createBean(SAMLAuthenticationProvider.class);
        builder.addPropertyValue("userDetails", parseUserDetailsService());
        builder.addPropertyValue("consumer", createProfileConsumer());
        builder.addPropertyValue("hokConsumer", createHokProfileConsumer());
        builder.addPropertyValue("samlLogger", logger);
        return builder.getBeanDefinition();
    }

    private BeanDefinition parseUserDetailsService() {
        String userDetailsServiceID = getAttribute(ROOT_USER_DETAILS_SERVICE_REF_ATTRIBUTE);
        BeanDefinitionBuilder builder = createBean(SAMLUserDetailsServiceAdapter.class);
        if (!userDetailsServiceID.trim().isEmpty()) {
            builder.addPropertyReference("userDetailsService", userDetailsServiceID);
        }
        return builder.getBeanDefinition();
    }

    @SuppressWarnings("unchecked")
    private BeanDefinition updateOrCreateAuthenticationManager(BeanDefinition authenticationProvider) {
        Element element = getChildElementByTagName(rootNode, AUTHENTICATION_PROVIDER_NODE);
        if (element != null) {
            String id = getRequiredAttribute(element, AUTHENTICATION_PROVIDER_ID_ATTRIBUTE);
            if (!id.trim().isEmpty()) {
                registerBean(authenticationProvider, id);
            }
        }
        
        BeanDefinitionRegistry registry = parserContext.getRegistry();
        if (registry.containsBeanDefinition(SPRING_AUTH_MANAGER_ID)) {
            BeanDefinition bean = registry.getBeanDefinition(SPRING_AUTH_MANAGER_ID);
            MutablePropertyValues properties = bean.getPropertyValues();
            PropertyValue property = properties.getPropertyValue("providers");
            if (property == null) {
                List<BeanDefinition> list = new ManagedList<BeanDefinition>();
                list.add(authenticationProvider);
                properties.addPropertyValue("providers", list);
            } else {
                ((ManagedList<BeanDefinition>) property.getValue()).add(authenticationProvider);
            }
            return bean;
        } 
        
        return createAuthenticationManager(authenticationProvider);
    }

    private BeanDefinition createAuthenticationManager(BeanDefinition authenticationProvider) {
        List<BeanDefinition> list = new ManagedList<BeanDefinition>();
        list.add(authenticationProvider);
        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(ProviderManager.class);
        builder.addPropertyValue("providers", list);
        return registerBean(builder, SPRING_AUTH_MANAGER_ID);
    }

    private BeanDefinition createProfileConsumer() {
        return getExistingOrCreateBean(getAttribute(ROOT_WEB_SSO_PROFILE_CONSUMER_REF_ATTRIBUTE),
                WebSSOProfileConsumerImpl.class);
    }

    private BeanDefinition createHokProfileConsumer() {
        return createBean(WebSSOProfileConsumerHoKImpl.class).getBeanDefinition();
    }

    private void createAndRegisterFilters(BeanDefinition authenticationManager, BeanDefinition entryPoint) {
        BeanDefinition logoutHandler = createLogoutHandler();
        BeanDefinition logoutSuccessHandler = createLogoutSuccessHandler();
        BeanDefinition logoutProfile = createLogoutProfile();

        BeanDefinition medatataDisplayFilter = createMetadataDisplayFilter();
        BeanDefinition metadataGeneratorFilter = createMetadataGeneratorFilter();
        BeanDefinition processingFilter = createAndRegisterSAMLFilter(authenticationManager);
        BeanDefinition logoutProcessingFilter = createAndRegisterSAMLLogoutProcessingFilter(logoutProfile,
                logoutHandler, logoutSuccessHandler);
        BeanDefinition logoutFilter = createAndRegisterSAMLLogoutFilter(logoutProfile, logoutHandler,
                logoutSuccessHandler);

        updateSecurityCustomFilters(medatataDisplayFilter, metadataGeneratorFilter, processingFilter, logoutFilter,
                logoutProcessingFilter, entryPoint);
    }

    private BeanDefinition createMetadataDisplayFilter() {
        return getExistingOrCreateBean(getAttribute(ROOT_METADATA_DISPLAY_FILTER_REF_ATTRIBUTE),
                MetadataDisplayFilter.class);
    }

    private BeanDefinition createMetadataGeneratorFilter() {
        BeanDefinitionBuilder generator = createBean(CloudSealMetadataGenerator.class);
        generator.addPropertyValue("includeDiscovery", false);
        generator.addPropertyValue("assertionConsumerIndex", 1);
        BeanDefinition generatorBean = generator.getBeanDefinition();
        registerBean(generatorBean);

        ConstructorArgumentValues constructorArgs = new ConstructorArgumentValues();
        constructorArgs.addGenericArgumentValue(generatorBean);

        BeanDefinition bean = getExistingOrCreateBean(getAttribute(ROOT_METADATA_GENERATOR_FILTER_REF_ATTRIBUTE),
                MetadataGeneratorFilter.class);
        bean.getConstructorArgumentValues().addArgumentValues(constructorArgs);
        return bean;
    }

    private BeanDefinition parseAndRegisterEntryPoint() {
        BeanDefinitionBuilder builder = createBean(SAMLEntryPoint.class);
        builder.addPropertyValue("defaultProfileOptions", createDefaultProfileOptions());
        return registerBean(builder, getRequiredAttribute(rootNode, ROOT_ENTRY_POINT_ID_ATTRIBUTE));
    }

    private BeanDefinition createAndRegisterSSOProfile() {
        BeanDefinition bean = getExistingOrCreateBean(getAttribute(ROOT_WEB_SSO_PROFILE_REF_ATTRIBUTE),
                WebSSOProfileImpl.class);
        registerBean(bean, "webSSOprofile");
        return bean;
    }

    private BeanDefinition createAndRegisterSAMLFilter(BeanDefinition authenticationManager) {
        BeanDefinition successRedirectHandler = createBean(SavedRequestAwareAuthenticationSuccessHandler.class)
                .getBeanDefinition();
        BeanDefinitionBuilder builder = createBean(SAMLProcessingFilter.class);
        builder.addPropertyValue("authenticationManager", authenticationManager);
        builder.addPropertyValue("authenticationSuccessHandler", successRedirectHandler);
        builder.addPropertyValue("SAMLProcessor", processor);
        builder.addPropertyValue("contextProvider", contextProvider);
        return registerBean(builder);
    }

    private BeanDefinition createAndRegisterSAMLLogoutProcessingFilter(BeanDefinition logoutProfile,
            BeanDefinition logoutHandler, BeanDefinition logoutSuccessHandler) {
        BeanDefinitionBuilder builder = createBean(SAMLLogoutProcessingFilter.class);
        builder.addConstructorArgValue(logoutSuccessHandler);
        builder.addConstructorArgValue(logoutHandler);
        builder.addPropertyValue("contextProvider", contextProvider);
        builder.addPropertyValue("SAMLProcessor", processor);
        builder.addPropertyValue("samlLogger", logger);
        builder.addPropertyValue("logoutProfile", logoutProfile);
        return registerBean(builder);
    }

    private BeanDefinition createAndRegisterSAMLLogoutFilter(BeanDefinition logoutProfile,
            BeanDefinition logoutHandler, BeanDefinition logoutSuccessHandler) {
        BeanDefinitionBuilder builder = createBean(CloudSealSAMLLogoutFilter.class);
        builder.addConstructorArgValue(logoutSuccessHandler);
        builder.addConstructorArgValue(logoutHandler);
        builder.addPropertyValue("contextProvider", contextProvider);
        builder.addPropertyValue("samlLogger", logger);
        builder.addPropertyValue("profile", logoutProfile);
        builder.addPropertyValue("filterProcessesUrl", getLogoutUrl());
        return registerBean(builder);
    }

    private String getLogoutUrl() {
        String logoutUrl = getAttribute(ROOT_LOGOUT_FILTER_URL_ATTRIBUTE);
        if (logoutUrl.equals("")) {
            logoutUrl = DEFAULT_LOGOUT_FILTER_URL_ATTRIBUTE;
        }
        return logoutUrl;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private void updateSecurityCustomFilters(BeanDefinition metadataDisplayFilter,
            BeanDefinition metadataGeneratorFilter, BeanDefinition processingFilter, BeanDefinition logoutFilter,
            BeanDefinition logoutProcessingFilter, BeanDefinition entryPoint) {
        if (!parserContext.getRegistry().getClass().getCanonicalName().startsWith("org.springframework.")) {
            return;
        }
        ManagedMap<String, ManagedList<BeanDefinition>> samlFilterMap = new ManagedMap<String, ManagedList<BeanDefinition>>();

        addFilterChainMapValue(samlFilterMap, "/saml/login/**", entryPoint);
        addFilterChainMapValue(samlFilterMap, getLogoutUrl(), logoutFilter);
        addFilterChainMapValue(samlFilterMap, "/saml/metadata/**", metadataDisplayFilter);
        addFilterChainMapValue(samlFilterMap, "/saml/SSO/**", processingFilter);
        addFilterChainMapValue(samlFilterMap, "/saml/SingleLogout/**", logoutProcessingFilter);
        addFilterChainMapValue(samlFilterMap, "/saml/discovery/**", createBean(SAMLDiscovery.class).getBeanDefinition());
        addFilterChainMapValue(samlFilterMap, "/cloudSeal/logout.png", createBean(CloudSealLogoutImageFilter.class)
                .getBeanDefinition());

        BeanDefinitionBuilder samlFilterChain = createBean(FilterChainProxy.class);
        samlFilterChain.addPropertyValue("filterChainMap", samlFilterMap);

        BeanDefinition springFilterChain = getBeanFromContext(SPRING_FILTER_CHAIN_ID);
        Map springFilterChainMap = getBeanPropertyAsManagedMap(springFilterChain, "filterChainMap");

        List list = getMapValueAsManagedList(springFilterChainMap, "/**");
        int index = getBeanIndexToAddAfter(list, "^org\\.springframework\\.security\\.web\\.context\\.");
        list.add(index, samlFilterChain.getBeanDefinition());
        list.add(0, metadataGeneratorFilter);
    }

    private int getBeanIndexToAddAfter(List list, String regexp) {
        int index = getBeanIndex(list, regexp);
        if (index == -1) {
            return 0;
        }
        return index + 1;
    }

    @SuppressWarnings("unchecked")
    private void addFilterChainMapValue(Map map, String path, BeanDefinition bean) {
        ManagedList<BeanDefinition> list = (ManagedList<BeanDefinition>) map.get(path);
        if (list == null) {
            list = new ManagedList<BeanDefinition>();
        }
        list.add(bean);
        map.put(path, list);
    }

    private int getBeanIndex(List list, String regexp) {
        final Pattern pattern = Pattern.compile(regexp);
        final Matcher matcher = pattern.matcher("");
        int index = -1;
        for (int i = 0; i < list.size(); i++) {
            final Object item = list.get(i);
            if (BeanDefinition.class.isInstance(item)) {
                final BeanDefinition filter = (BeanDefinition) item;
                matcher.reset(filter.getBeanClassName());
                if (matcher.find()) {
                    index = i;
                }
            }
        }
        return index;
    }

    private BeanDefinition getBeanFromContext(String beanID) {
        return parserContext.getRegistry().getBeanDefinition(beanID);
    }

    private ManagedMap getBeanPropertyAsManagedMap(BeanDefinition bean, String propertyName) {
        PropertyValue property = bean.getPropertyValues().getPropertyValue(propertyName);
        String beanClassname = bean.getBeanClassName();
        if (property == null) {
            throw new IllegalStateException("No property " + propertyName + " in bean " + beanClassname);
        }
        Object value = property.getValue();
        if (!ManagedMap.class.isInstance(value)) {
            throw new IllegalStateException("Property " + propertyName + " in bean " + beanClassname
                    + " is not ManagedMap: " + value.getClass().getCanonicalName());
        }
        return (ManagedMap) value;
    }

    private ManagedList getMapValueAsManagedList(Map map, String key) {
        Object item = map.get(key);
        if (item == null) {
            throw new IllegalStateException("No value for key " + key + " in map: " + map.getClass().getCanonicalName());
        }
        if (!ManagedList.class.isInstance(item)) {
            throw new IllegalStateException("Value for key " + key + " in map is not ManagedList: "
                    + item.getClass().getCanonicalName());
        }
        return (ManagedList) item;
    }

    private BeanDefinition createDefaultProfileOptions() {
        BeanDefinitionBuilder builder = createBean(WebSSOProfileOptions.class);
        builder.addPropertyValue("includeScoping", "false");
        String attr = getAttribute(ROOT_APP_ID_ATTRIBUTE);
        if (attr != null && attr.length() > 0) {
            builder.addPropertyValue("providerName", attr);
        }
        return builder.getBeanDefinition();
    }

    private BeanDefinition createLogoutProfile() {
        return getExistingOrCreateBean(getAttribute(ROOT_SINGLE_LOGOUT_PROFILE_REF_ATTRIBUTE),
                SingleLogoutProfileImpl.class);
    }

    private BeanDefinition createLogoutHandler() {
        BeanDefinitionBuilder builder = createBean(SecurityContextLogoutHandler.class);
        builder.addPropertyValue("invalidateHttpSession", "true");
        return builder.getBeanDefinition();
    }

    private BeanDefinition createLogoutSuccessHandler() {
        BeanDefinitionBuilder builder = createBean(SimpleUrlLogoutSuccessHandler.class);
        builder.addPropertyValue("defaultTargetUrl", "/");
        return builder.getBeanDefinition();
    }

    private Element getRequiredElement(Element parentElement, String elementTag) {
        Element element = getChildElementByTagName(parentElement, elementTag);
        if (element == null) {
            throw missingElementException(elementTag);
        }
        return element;
    }

    private IllegalStateException missingElementException(String elementTag) {
        return new IllegalStateException("Missing element in CloudSeal configuration: " + elementTag);
    }

    private String getRequiredAttribute(Element element, String attributeTag) {
        String attribute = element.getAttribute(attributeTag);
        if (attribute.trim().isEmpty()) {
            throw new IllegalStateException("Missing or empty attribute of " + element.getNodeName() + " element "
                    + "in CloudSeal configuration: " + attributeTag);
        }
        return attribute;
    }

    private BeanDefinition createAndRegisterBean(Class<?> beanClass) {
        return registerBean(createBean(beanClass));
    }

    private BeanDefinitionBuilder createBean(Class<?> beanClass) {
        LOGGER.debug("Creating a {} class bean...", beanClass.getSimpleName());
        return BeanDefinitionBuilder.rootBeanDefinition(beanClass);
    }

    private BeanDefinition registerBean(BeanDefinitionBuilder beanBuilder) {
        return registerBean(beanBuilder.getBeanDefinition());
    }

    private BeanDefinition registerBean(BeanDefinition bean) {
        String beanID = parserContext.getReaderContext().generateBeanName(bean);
        return registerBean(bean, beanID);
    }

    private BeanDefinition registerBean(BeanDefinitionBuilder beanBuilder, String beanID) {
        return registerBean(beanBuilder.getBeanDefinition(), beanID);
    }

    private BeanDefinition registerBean(BeanDefinition bean, String beanID) {
        LOGGER.debug("Registering a {} class bean as {}...", bean.getBeanClassName(), beanID);
        parserContext.registerBeanComponent(new BeanComponentDefinition(bean, beanID));
        return bean;
    }

    private Resource getResourceFromLocation(String location) {
        Resource resource = parserContext.getReaderContext().getResourceLoader().getResource(location);
        if (!resource.exists()) {
            throw new IllegalStateException("Cannot find resource: " + location);
        }
        return resource;
    }

    private File getFileFromLocation(String location) {
        File file;
        try {
            file = getResourceFromLocation(location).getFile();
        } catch (IOException e) {
            throw new IllegalStateException("Cannot obtain file from resource: " + location, e);
        }
        return file;
    }
}
