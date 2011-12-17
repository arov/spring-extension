/* Copyright 2009 Cloudseal O†
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

import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.util.Iterator;

class Utility {
    private static class CloudSealNamespaceContext implements NamespaceContext {
        @Override
        public String getNamespaceURI(final String prefix) {
            if (prefix.equals("cloudseal")) return "http://www.cloudseal.com/schema/spring";
            if (prefix.equals(XMLConstants.XML_NS_PREFIX)) return XMLConstants.XML_NS_URI;
            return XMLConstants.NULL_NS_URI;
        }

        @Override
        public String getPrefix(String s) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Iterator getPrefixes(String s) {
            throw new UnsupportedOperationException();
        }
    }

    public static Element domFromString(final String xml)
            throws ParserConfigurationException, IOException, SAXException {
        return domFromReader(new StringReader(xml));
    }

    public static Element domFromFile(final String fileName, final String rootElement)
            throws ParserConfigurationException, IOException, SAXException {
        final InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName);
        if (stream == null) throw new FileNotFoundException("Cannot find file: " + fileName);
        return DomUtils.getChildElementByTagName(domFromReader(new InputStreamReader(stream, "UTF-8")), rootElement);
    }

    public static void removeNode(final Element rootElement, final String xPathLocation)
            throws XPathExpressionException {
        final XPath xPath = XPathFactory.newInstance().newXPath();
        xPath.setNamespaceContext(new CloudSealNamespaceContext());
        final Node node = (Node) xPath.evaluate(xPathLocation, rootElement, XPathConstants.NODE);
        final short nodeType = node.getNodeType();

        switch (nodeType) {
            case Node.ELEMENT_NODE:
                final Node parent = node.getParentNode();
                parent.removeChild(node);
                break;

            case Node.ATTRIBUTE_NODE:
                final Attr attribute = (Attr) node;
                final Element element = attribute.getOwnerElement();
                element.removeAttributeNode(attribute);
                break;

            default:
                throw new IllegalArgumentException("Not supported node type: " + nodeType);
        }
    }

    private static Element domFromReader(final Reader reader)
            throws ParserConfigurationException, IOException, SAXException {
        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        return factory.newDocumentBuilder().parse(new InputSource(reader)).getDocumentElement();
    }
}
