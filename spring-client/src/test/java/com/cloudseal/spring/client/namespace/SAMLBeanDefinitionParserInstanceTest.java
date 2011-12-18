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

import static com.cloudseal.spring.client.namespace.Utility.domFromFile;
import static com.cloudseal.spring.client.namespace.Utility.removeNode;
import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;

import java.io.IOException;
import java.util.Map;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.*;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.XmlReaderContext;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.web.FilterChainProxy;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ParserContext.class, XmlReaderContext.class})
public class SAMLBeanDefinitionParserInstanceTest {
    private static final String SPRING_AUTH_MANAGER_ID = "org.springframework.security.authenticationManager";

    private ParserContext parserContext;
    private BeanDefinitionRegistry registry;
    private Element rootElement;

    private static class GeneratedBeanNameAnswer implements Answer<String> {
        public static Answer<String> generatedBeanName() {
            return new GeneratedBeanNameAnswer();
        }

        @Override
        public String answer(InvocationOnMock invocation) throws Throwable {
            return ((BeanDefinition) (invocation.getArguments()[0])).getBeanClassName();
        }
    }

    @Before
    @SuppressWarnings({"unchecked"})
    public void prepareParserContext() throws IOException, SAXException, ParserConfigurationException {
        final XmlReaderContext readerContext = mock(XmlReaderContext.class);
        when(readerContext.generateBeanName(any(BeanDefinition.class))).
                thenAnswer(GeneratedBeanNameAnswer.generatedBeanName());
        when(readerContext.getResourceLoader()).thenReturn(new DefaultResourceLoader());

        registry = new SimpleBeanDefinitionRegistry();
        final BeanDefinitionBuilder filterChain = BeanDefinitionBuilder.rootBeanDefinition(FilterChainProxy.class);
        final Map map = new ManagedMap();
        map.put("/**", new ManagedList());
        filterChain.addPropertyValue("filterChainMap", map);
        registry.registerBeanDefinition("org.springframework.security.filterChainProxy",
                filterChain.getBeanDefinition());

        parserContext = mock(ParserContext.class);
        when(parserContext.getReaderContext()).thenReturn(readerContext);
        when(parserContext.getRegistry()).thenReturn(registry);

        rootElement = domFromFile("full-config.xml", "sso");
    }

    @Test
    public void canProcessFullConfig() {
        new CloudSealBeanDefinitionParserInstance(rootElement, parserContext);
    }

    @Test
    public void canProcessSimpleConfig() throws XPathExpressionException {
        removeOptionalNodes(rootElement);
        new CloudSealBeanDefinitionParserInstance(rootElement, parserContext);
    }

    @Test
    public void AuthenticationManagerHasNoProviders() {
        final BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(ProviderManager.class);
        registry.registerBeanDefinition(SPRING_AUTH_MANAGER_ID, builder.getBeanDefinition());
        new CloudSealBeanDefinitionParserInstance(rootElement, parserContext);
    }

    @Test
    public void AuthenticationManagerHasOtherProviders() {
        final BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(ProviderManager.class);
        builder.addPropertyValue("providers", new ManagedList<BeanDefinition>());
        registry.registerBeanDefinition(SPRING_AUTH_MANAGER_ID, builder.getBeanDefinition());
        new CloudSealBeanDefinitionParserInstance(rootElement, parserContext);
    }

    @Test(expected = IllegalStateException.class)
    public void failOnMissingConfigAttribute()
            throws IOException, SAXException, ParserConfigurationException, XPathExpressionException {
        removeNode(rootElement, "@endpoint");
        new CloudSealBeanDefinitionParserInstance(rootElement, parserContext);
    }

    @Test(expected = IllegalStateException.class)
    public void failOnMissingConfigElement()
            throws IOException, SAXException, ParserConfigurationException, XPathExpressionException {
        removeNode(rootElement, "cloudseal:metadata");
        new CloudSealBeanDefinitionParserInstance(rootElement, parserContext);
    }

    private static void removeOptionalNodes(final Element rootElement) throws XPathExpressionException {
        removeNode(rootElement, "@user-details-service-ref");
        removeNode(rootElement, "cloudseal:authentication-provider");
    }
}
