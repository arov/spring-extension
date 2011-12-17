package com.cloudseal.spring.client.namespace;

import static com.cloudseal.spring.client.namespace.Utility.domFromString;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.when;

import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.beans.factory.xml.BeanDefinitionParserDelegate;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

@RunWith(PowerMockRunner.class)
@PrepareForTest(ParserContext.class)
public class CloudSealNamespaceHandlerTest {
    
    @Mock private CloudSealBeanDefinitionParser parser;
    @Mock private ParserContext parserContext;
    @Mock private BeanDefinitionParserDelegate parserDelegate;
    
    @Test
    public void samlParserIsActuallyRegisteredForSSOTag() throws IOException, SAXException, ParserConfigurationException {
        CloudSealNamespaceHandler handler = new CloudSealNamespaceHandler(parser);
        handler.init();

        when(parserContext.getDelegate()).thenReturn(parserDelegate);
        when(parserDelegate.getLocalName(any(Node.class))).thenCallRealMethod();

        Element rootElement = domFromString("<sso/>");
        handler.parse(rootElement, parserContext);
        verify(parser, atLeastOnce()).parse(rootElement, parserContext);
    }
}