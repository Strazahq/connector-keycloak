/*
 *  Copyright Nomura Research Institute, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package jp.openstandia.connector.keycloak.integration;

import jp.openstandia.connector.keycloak.KeycloakClientHandler;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ClientIT extends AbstractIntegrationTest {

    private static final ObjectClass CLIENT_OBJECT_CLASS = KeycloakClientHandler.CLIENT_OBJECT_CLASS;

    // --- Create ---

    @Test
    void addClient() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("test-client"));
        attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        attrs.add(AttributeBuilder.buildEnabled(true));

        Uid uid = connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        assertNotNull(uid);
        assertNotNull(uid.getUidValue());
        assertEquals("test-client", uid.getNameHintValue());

        ConnectorObject result = connector.getObject(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")),
                defaultGetOperation("protocol", "publicClient"));

        assertEquals("test-client", result.getName().getNameValue());
        assertEquals("openid-connect", singleAttr(result, "protocol"));
    }

    @Test
    void addClientWithClientAuthenticatorType() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("test-client"));
        attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        attrs.add(AttributeBuilder.build("clientAuthenticatorType", "client-jwt"));
        attrs.add(AttributeBuilder.buildEnabled(true));

        Uid uid = connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")),
                defaultGetOperation("clientAuthenticatorType"));

        assertEquals("client-jwt", singleAttr(result, "clientAuthenticatorType"));
    }

    @Test
    void addClientWithDefaultClientScopes() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("test-client"));
        attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        attrs.add(AttributeBuilder.build("defaultClientScopes", list("phone", "address")));
        attrs.add(AttributeBuilder.buildEnabled(true));

        Uid uid = connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")),
                defaultGetOperation("defaultClientScopes"));

        List<Object> scopes = multiAttr(result, "defaultClientScopes");
        assertTrue(scopes.contains("phone"));
        assertTrue(scopes.contains("address"));
    }

    // --- Update ---

    @Test
    void updateClientAuthenticatorType() {
        Uid uid = createTestClient("test-client");

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("clientAuthenticatorType", "client-jwt"));

        connector.updateDelta(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")), modifications, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")),
                defaultGetOperation("clientAuthenticatorType"));

        assertEquals("client-jwt", singleAttr(result, "clientAuthenticatorType"));
    }

    @Test
    void updateClientDefaultClientScopesAdd() {
        Uid uid = createTestClient("test-client", list("profile"));

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("defaultClientScopes", list("email"), null));

        connector.updateDelta(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")), modifications, new OperationOptionsBuilder().build());

        List<Object> scopes = defaultClientScopesOf(uid);
        assertTrue(scopes.contains("profile"), "Existing scope should be preserved");
        assertTrue(scopes.contains("email"), "New scope should be added");
    }

    @Test
    void updateClientDefaultClientScopesRemove() {
        Uid uid = createTestClient("test-client", list("phone", "address"));

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("defaultClientScopes", null, list("phone")));

        connector.updateDelta(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")), modifications, new OperationOptionsBuilder().build());

        List<Object> scopes = defaultClientScopesOf(uid);
        assertFalse(scopes.contains("phone"), "Removed scope should be gone");
        assertTrue(scopes.contains("address"), "Remaining scope should be preserved");
    }

    @Test
    void updateClientDefaultClientScopesReplace() {
        Uid uid = createTestClient("test-client", list("phone", "address"));

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("defaultClientScopes", list("profile", "email")));

        connector.updateDelta(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")), modifications, new OperationOptionsBuilder().build());

        List<Object> scopes = defaultClientScopesOf(uid);
        assertEquals(set("profile", "email"), asSet(scopes));
    }

    @Test
    void updateClientDefaultClientScopesUnknownName() {
        Uid uid = createTestClient("test-client", list("profile"));

        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(AttributeDeltaBuilder.build("defaultClientScopes", list("email"), list("no-such-scope")));

        InvalidAttributeValueException e = assertThrows(InvalidAttributeValueException.class, () -> {
            connector.updateDelta(CLIENT_OBJECT_CLASS,
                    new Uid(uid.getUidValue(), new Name("test-client")), modifications, new OperationOptionsBuilder().build());
        });
        assertTrue(e.getMessage().contains("no-such-scope"), "The message should name the unknown scope: " + e.getMessage());

        List<Object> scopes = defaultClientScopesOf(uid);
        assertEquals(set("profile"), asSet(scopes), "The refused update should not change any scope");
    }

    // --- Read ---

    @Test
    void getClientByUid() {
        Uid uid = createTestClient("test-client");

        ConnectorObject result = connector.getObject(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")),
                defaultGetOperation("protocol"));

        assertEquals(CLIENT_OBJECT_CLASS, result.getObjectClass());
        assertEquals(uid.getUidValue(), result.getUid().getUidValue());
        assertEquals("test-client", result.getName().getNameValue());
        assertEquals("openid-connect", singleAttr(result, "protocol"));
    }

    /**
     * This test verifies the bug fix where getClient by name was comparing
     * rep.getName() instead of rep.getClientId(). The clientId ("test-client")
     * and the display name ("Test Client Display") are different, so the old
     * buggy code would fail to find the client.
     */
    @Test
    void getClientByName() {
        // Create client with clientId different from display name
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("test-client"));
        attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        attrs.add(AttributeBuilder.build("name", "Test Client Display"));
        attrs.add(AttributeBuilder.buildEnabled(true));

        Uid uid = connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        // Search by clientId (Name) — this would fail with the old getName() bug
        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        connector.search(CLIENT_OBJECT_CLASS, FilterBuilder.equalTo(new Name("test-client")), handler, defaultSearchOperation());

        assertEquals(1, results.size());
        assertEquals(uid.getUidValue(), results.get(0).getUid().getUidValue());
        assertEquals("test-client", results.get(0).getName().getNameValue());
    }

    // --- Search ---

    @Test
    void getClients() {
        createTestClient("client1");
        createTestClient("client2");

        List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = connectorObject -> {
            results.add(connectorObject);
            return true;
        };
        SearchResult searchResult = connector.search(CLIENT_OBJECT_CLASS, null, handler, defaultSearchOperation());

        // Keycloak has default clients (account, admin-cli, etc.) + our 2
        assertTrue(results.size() >= 2);

        Set<String> clientIds = new HashSet<>();
        for (ConnectorObject co : results) {
            clientIds.add(co.getName().getNameValue());
        }
        assertTrue(clientIds.contains("client1"));
        assertTrue(clientIds.contains("client2"));

        // Verify SearchResultsHandler.handleResult() was called
        assertNotNull(searchResult);
        assertTrue(searchResult.isAllResultsReturned());
    }

    // --- Secret as GuardedString ---

    @Test
    void getClientSecretAsGuardedString() {
        // The admin REST API only includes the client secret in ClientRepresentation
        // since Keycloak 24.0.0 (ModelToRepresentation.toRepresentation never set it before).
        assumeTrue(KEYCLOAK_MAJOR_VERSION >= 24, "Client secret is returned by the admin API only since Keycloak 24");

        // Create a confidential client (non-public) so it has a secret
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("confidential-client"));
        attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        attrs.add(AttributeBuilder.build("publicClient", false));
        attrs.add(AttributeBuilder.buildEnabled(true));

        Uid uid = connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("confidential-client")),
                defaultGetOperation("secret"));

        Attribute secretAttr = result.getAttributeByName("secret");
        assertNotNull(secretAttr);
        Object secretValue = secretAttr.getValue().get(0);
        assertInstanceOf(GuardedString.class, secretValue);

        // Verify the secret is non-empty
        String plain = toPlain((GuardedString) secretValue);
        assertNotNull(plain);
        assertFalse(plain.isEmpty());
    }

    // --- Delete ---

    @Test
    void deleteClient() {
        Uid uid = createTestClient("test-client");

        connector.delete(CLIENT_OBJECT_CLASS, new Uid(uid.getUidValue(), new Name("test-client")), new OperationOptionsBuilder().build());

        ConnectorObject result = connector.getObject(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name("test-client")), defaultGetOperation());
        assertNull(result);
    }

    // --- Helpers ---

    private Uid createTestClient(String clientId) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(clientId));
        attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        return connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
    }

    private Uid createTestClient(String clientId, List<String> defaultClientScopes) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(clientId));
        attrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        attrs.add(AttributeBuilder.build("defaultClientScopes", defaultClientScopes));
        attrs.add(AttributeBuilder.buildEnabled(true));
        return connector.create(CLIENT_OBJECT_CLASS, attrs, new OperationOptionsBuilder().build());
    }

    private List<Object> defaultClientScopesOf(Uid uid) {
        ConnectorObject result = connector.getObject(CLIENT_OBJECT_CLASS,
                new Uid(uid.getUidValue(), new Name(uid.getNameHintValue())),
                defaultGetOperation("defaultClientScopes"));
        return multiAttr(result, "defaultClientScopes");
    }
}
