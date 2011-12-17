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

import java.util.*;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.NameID;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.saml.SAMLCredential;

public class CloudSealUserAttributes {

    public static final String FIRST_NAME = "firstName";
    public static final String LAST_NAME = "lastName";
    public static final String EMAIL = "email";
    public static final String USERNAME = "username";
    public static final String ADDRESS = "address";
    public static final String BIRTHDAY = "birthday";
    public static final String COMPANY = "company";
    public static final String COUNTRY = "country";
    public static final String DEPARTMENT = "department";
    public static final String GENDER = "gender";
    public static final String JOB_TITLE = "jobTitle";
    public static final String LANGUAGE = "language";
    public static final String MIDDLE_INITIAL = "middleInitial";
    public static final String PHONE = "phone";
    public static final String POST_CODE = "postCode";
    public static final String TIMEZONE = "timezone";
    public static final String ROLES = "roles";

    private final Map<String, Collection<XMLObject>> attributes;
    private final String userName;

    private final String firstName;
    private final String lastName;
    private final String email;
    private final String address;
    private final String birthday;
    private final String company;
    private final String country;
    private final String department;
    private final String gender;
    private final String jobTitle;
    private final String language;
    private final String middleInitial;
    private final String phone;
    private final String postCode;
    private final String timezone;
    private final Collection<GrantedAuthority> roles;

    public CloudSealUserAttributes(SAMLCredential credential) {
        userName = getUserName(credential);

        Map<String, Collection<XMLObject>> attributes = getAttributes(credential);
        firstName = removeStringAttribute(attributes, FIRST_NAME);
        lastName = removeStringAttribute(attributes, LAST_NAME);
        email = removeStringAttribute(attributes, EMAIL);
        address = removeStringAttribute(attributes, ADDRESS);
        birthday = removeStringAttribute(attributes, BIRTHDAY);
        company = removeStringAttribute(attributes, COMPANY);
        country = removeStringAttribute(attributes, COUNTRY);
        department = removeStringAttribute(attributes, DEPARTMENT);
        gender = removeStringAttribute(attributes, GENDER);
        jobTitle = removeStringAttribute(attributes, JOB_TITLE);
        language = removeStringAttribute(attributes, LANGUAGE);
        middleInitial = removeStringAttribute(attributes, MIDDLE_INITIAL);
        phone = removeStringAttribute(attributes, PHONE);
        postCode = removeStringAttribute(attributes, POST_CODE);
        timezone = removeStringAttribute(attributes, TIMEZONE);
        roles = removeRoleListAttribute(attributes);
        
        this.attributes = Collections.unmodifiableMap(attributes);
    }

    public String getUserName() {
        return userName;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getEmail() {
        return email;
    }

    public String getAddress() {
        return address;
    }
    
    public String getBirthday() {
        return birthday;
    }
    
    public String getCompany() {
        return company;
    }
    
    public String getCountry() {
        return country;
    }
    
    public String getDepartment() {
        return department;
    }
    
    public String getGender() {
        return gender;
    }
    
    public String getJobTitle() {
        return jobTitle;
    }
    
    public String getLanguage() {
        return language;
    }
    
    public String getMiddleInitial() {
        return middleInitial;
    }
    
    public String getPhone() {
        return phone;
    }
    
    public String getPostCode() {
        return postCode;
    }
    
    public String getTimezone() {
        return timezone;
    }
    
    public Collection<GrantedAuthority> getRoles() {
        return roles;
    }

    public Collection<XMLObject> getAttribute(String attributeName) {
        return attributes.get(attributeName);
    }

    private String getUserName(SAMLCredential credential) {
        NameID nameID = credential.getNameID();
        if (nameID == null) {
            return "";
        }
        String userName = nameID.getValue();
        if (userName == null) {
            return "";
        }
        return userName;
    }

    private Map<String, Collection<XMLObject>> getAttributes(SAMLCredential credential) {
        Collection<Attribute> credentialAttributes = credential.getAttributes();
        Map<String, Collection<XMLObject>> attributes = new HashMap<String, Collection<XMLObject>>(
                credentialAttributes.size());
        for (Attribute attribute : credentialAttributes) {
            String name = attribute.getName();
            Collection<XMLObject> newValue = new ArrayList<XMLObject>(attribute.getAttributeValues());
            Collection<XMLObject> oldValue = attributes.get(name);
            if (oldValue != null) {
                oldValue.addAll(newValue);
            } else {
                attributes.put(name, newValue);
            }
        }
        return attributes;
    }

    private String removeStringAttribute(Map<String, Collection<XMLObject>> attributes, String name) {
        Collection<XMLObject> list = attributes.remove(name);
        if (list == null || list.isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (XMLObject xmlObject : list) {
            if (XSString.class.isInstance(xmlObject)) {
                if (builder.length() != 0) {
                    builder.append(",");
                }
                builder.append(((XSString) xmlObject).getValue());
            }
        }
        return builder.toString();
    }

    private Collection<GrantedAuthority> removeRoleListAttribute(Map<String, Collection<XMLObject>> attributes) {
        Collection<XMLObject> list = attributes.remove(ROLES);
        if (list == null || list.isEmpty()) {
            return Collections.emptyList();
        }
        Collection<GrantedAuthority> roles = new ArrayList<GrantedAuthority>(list.size());
        for (XMLObject xmlObject : list) {
            if (XSString.class.isInstance(xmlObject)) {
                String roleName = ((XSString) xmlObject).getValue();
                roles.add(new GrantedAuthorityImpl(roleName));
            }
        }
        return Collections.unmodifiableCollection(roles);
    }
}
