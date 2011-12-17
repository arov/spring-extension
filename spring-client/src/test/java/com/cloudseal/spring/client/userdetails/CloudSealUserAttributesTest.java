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
package com.cloudseal.spring.client.userdetails;

import static com.cloudseal.spring.client.namespace.IsCollection.hasSameOrder;
import static com.cloudseal.spring.client.userdetails.CloudSealUserAttributes.*;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.jetbrains.annotations.Nullable;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.NameID;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.saml.SAMLCredential;

public class CloudSealUserAttributesTest {

    private SAMLCredential credential;

    @Before
    public void prepare() {
        credential = mock(SAMLCredential.class);
    }

    @Test
    public void userName() {
        final String userName = "username@company.com";

        setNameIDValue(userName);
        assertThat(new CloudSealUserAttributes(credential).getUserName(), is(userName));
    }

    @Test
    public void userNameMustBeNotNull() {
        setNameIDValue(null);
        assertThat(new CloudSealUserAttributes(credential).getUserName(), is(""));

        setNameID(null);
        assertThat(new CloudSealUserAttributes(credential).getUserName(), is(""));
    }

    @Test
    public void firstNameFromSingleAttributeValue() {
        final String firstName = "First";

        setStringAttributes(FIRST_NAME, firstName);
        assertThat(new CloudSealUserAttributes(credential).getFirstName(), is(firstName));
    }

    @Test
    public void firstNameFromManyAttributeValues() {
        final String firstName1 = "First";
        final String firstName2 = "Name";

        setStringAttributes(FIRST_NAME, firstName1, firstName2);
        assertThat(new CloudSealUserAttributes(credential).getFirstName(), is(firstName1 + "," + firstName2));
    }

    @Test
    public void firstNameFromManyAttributes() {
        final String firstName1 = "First";
        final String firstName2 = "Name";

        setAttributes(createStringAttribute(FIRST_NAME, firstName1), createStringAttribute(FIRST_NAME, firstName2));
        assertThat(new CloudSealUserAttributes(credential).getFirstName(), is(firstName1 + "," + firstName2));
    }

    @Test
    public void lastNameFromSingleAttributeValue() {
        final String lastName = "Last";

        setStringAttributes(LAST_NAME, lastName);
        assertThat(new CloudSealUserAttributes(credential).getLastName(), is(lastName));
    }

    @Test
    public void lastNameFromManyAttributeValues() {
        final String lastName1 = "Last";
        final String lastName2 = "Name";

        setStringAttributes(LAST_NAME, lastName1, lastName2);
        assertThat(new CloudSealUserAttributes(credential).getLastName(), is(lastName1 + "," + lastName2));
    }

    @Test
    public void lastNameFromManyAttributes() {
        final String lastName1 = "Last";
        final String lastName2 = "Name";

        setAttributes(createStringAttribute(LAST_NAME, lastName1), createStringAttribute(LAST_NAME, lastName2));
        assertThat(new CloudSealUserAttributes(credential).getLastName(), is(lastName1 + "," + lastName2));
    }

    @Test
    public void emailFromSingleAttributeValue() {
        final String email = "user@company.com";

        setStringAttributes(EMAIL, email);
        assertThat(new CloudSealUserAttributes(credential).getEmail(), is(email));
    }

    @Test
    public void emailFromManyAttributeValues() {
        final String email1 = "user@company.com";
        final String email2 = "user@university.edu";

        setStringAttributes(EMAIL, email1, email2);
        assertThat(new CloudSealUserAttributes(credential).getEmail(), is(email1 + "," + email2));
    }

    @Test
    public void emailFromManyAttributes() {
        final String email1 = "user@company.com";
        final String email2 = "user@university.edu";

        setAttributes(createStringAttribute(EMAIL, email1), createStringAttribute(EMAIL, email2));
        assertThat(new CloudSealUserAttributes(credential).getEmail(), is(email1 + "," + email2));
    }

    @Test
    public void rolesFromSingleAttributeValue() {
        final GrantedAuthority role = new GrantedAuthorityImpl("USER");

        setStringAttributes(ROLES, role.getAuthority());
        assertThat(new CloudSealUserAttributes(credential).getRoles(), hasSameOrder(asList(role)));
    }

    @Test
    public void rolesFromManyAttributeValues() {
        final GrantedAuthority role1 = new GrantedAuthorityImpl("USER");
        final GrantedAuthority role2 = new GrantedAuthorityImpl("ADMIN");

        setStringAttributes(ROLES, role1.getAuthority(), role2.getAuthority());
        assertThat(new CloudSealUserAttributes(credential).getRoles(), hasSameOrder(asList(role1, role2)));
    }

    @Test
    public void rolesFromManyAttributes() {
        final GrantedAuthority role1 = new GrantedAuthorityImpl("USER");
        final GrantedAuthority role2 = new GrantedAuthorityImpl("ADMIN");

        setAttributes(createStringAttribute(ROLES, role1.getAuthority()),
                createStringAttribute(ROLES, role2.getAuthority()));
        assertThat(new CloudSealUserAttributes(credential).getRoles(), hasSameOrder(asList(role1, role2)));
    }

    @Test
    public void objectsFromSingleAttributeValue() {
        final String attributeName = "attribute";
        final XMLObject object = mock(XMLObject.class);

        setXMLObjectAttributes(attributeName, object);
        assertThat(new CloudSealUserAttributes(credential).getAttribute(attributeName), hasSameOrder(asList(object)));
    }

    @Test
    public void objectsFromManyAttributeValues() {
        final String attributeName = "attribute";
        final XMLObject object1 = mock(XMLObject.class);
        final XMLObject object2 = mock(XMLObject.class);

        setXMLObjectAttributes(attributeName, object1, object2);
        assertThat(new CloudSealUserAttributes(credential).getAttribute(attributeName),
                hasSameOrder(asList(object1, object2)));
    }

    @Test
    public void objectsFromManyAttributes() {
        final String attributeName = "attribute";
        final XMLObject object1 = mock(XMLObject.class);
        final XMLObject object2 = mock(XMLObject.class);

        setAttributes(createXMLObjectAttribute(attributeName, object1),
                createXMLObjectAttribute(attributeName, object2));
        assertThat(new CloudSealUserAttributes(credential).getAttribute(attributeName),
                hasSameOrder(asList(object1, object2)));
    }

    private void setNameID(@Nullable final NameID nameID) {
        when(credential.getNameID()).thenReturn(nameID);
    }

    private void setNameIDValue(@Nullable final String userName) {
        final NameID nameID = mock(NameID.class);
        when(nameID.getValue()).thenReturn(userName);
        setNameID(nameID);
    }

    private void setAttributes(final Attribute... attributes) {
        when(credential.getAttributes()).thenReturn(asList(attributes));
    }

    private Attribute createXMLObjectAttribute(final String attributeName, final XMLObject... objects) {
        return createXMLObjectAttribute(attributeName, asList(objects));
    }

    private Attribute createXMLObjectAttribute(final String attributeName, final List<XMLObject> values) {
        final Attribute attribute = mock(Attribute.class);
        when(attribute.getName()).thenReturn(attributeName);
        when(attribute.getAttributeValues()).thenReturn(values);

        return attribute;
    }

    private void setXMLObjectAttributes(final String attributeName, final XMLObject... xmlObjects) {
        setXMLObjectAttributes(attributeName, asList(xmlObjects));
    }

    private void setXMLObjectAttributes(final String attributeName, final List<XMLObject> values) {
        setAttributes(createXMLObjectAttribute(attributeName, values));
    }

    private Attribute createStringAttribute(String attributeName, final String... strings) {
        final List<XMLObject> values = new ArrayList<XMLObject>(strings.length);
        for (final String string : strings) {
            final XSString value = mock(XSString.class);
            when(value.getValue()).thenReturn(string);

            values.add(value);
        }

        return createXMLObjectAttribute(attributeName, values);
    }

    private void setStringAttributes(final String attributeName, final String... strings) {
        setAttributes(createStringAttribute(attributeName, strings));
    }
}
