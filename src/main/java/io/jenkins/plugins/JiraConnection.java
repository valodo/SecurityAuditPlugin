package io.jenkins.plugins;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.core.util.Base64;
import hudson.util.Secret;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.auth.AuthenticationException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Dictionary;
import java.util.Hashtable;

public class JiraConnection {

    private static Dictionary vulnerabilityReferences;
    private static String auth;
    private static String url;

    public static void main(String jira_url, String jira_username, Secret jira_password) {
        populateVulnerabilityReferencesDictionary();

        auth = new String(Base64.encode(jira_username+ ":" + jira_password.getPlainText()));

        String serverURL = jira_url;
        url = serverURL + "/rest/api/2/issue";
    }

    /**
     * invokePostMethod method sends a POST HTTP request in order to create a bug issue in Jira
     * @param projectKey of the Jira issue
     * @param affectedVersionList the list of affected versions of the Jira issue
     * @param actionSteps the steps in order to reproduce the vulnerability
     * @param confirmedVulnerability the Vulnerability Object which contains all information
     * @return the HTTP response after creating the Jira issue
     * @throws AuthenticationException when the authentication failed
     * @throws ClientHandlerException
     */
    public static ClientResponse invokePostMethod(String projectKey, String affectedVersionList, String actionSteps, Vulnerability confirmedVulnerability) throws AuthenticationException, ClientHandlerException {
        String data = createJSONStringToSendData(projectKey, affectedVersionList, actionSteps, confirmedVulnerability);

        Client client = Client.create();
        WebResource webResource = client.resource(url);
        ClientResponse response = webResource.header("Authorization", "Basic " + auth).type("application/json")
                .accept("application/json").post(ClientResponse.class, data);
        int statusCode = response.getStatus();
        if (statusCode == 401) {
            throw new AuthenticationException("Invalid Username or Password");
        }
        return response;
    }

    /**
     * createJSONStringToSendData method generates the JSON string which is sent to Jira server in order to create a 
     * particular issue for a vulnerability
     * @param projectKey of the Jira issue
     * @param affectedVersionList the list of affected versions of the Jira issue
     * @param actionSteps the steps in order to reproduce the vulnerability
     * @param confirmedVulnerability the Vulnerability Object which contains all information
     * @return the JSON string
     */
    private static String createJSONStringToSendData(String projectKey, String affectedVersionList, String actionSteps, Vulnerability confirmedVulnerability){
        String[] affectedVersions = affectedVersionList.split(";");

        String stepsWithoutSpecialCharacters = StringEscapeUtils.escapeHtml(actionSteps);
        stepsWithoutSpecialCharacters =  stepsWithoutSpecialCharacters.replace("&gt;", ">");
        stepsWithoutSpecialCharacters =  stepsWithoutSpecialCharacters.replace("&lt;", "<");

        String data = "{\"fields\":{\"project\":{\"key\":\"" + projectKey + "\"},\"summary\":\"" + confirmedVulnerability.getVulnerabilityType() + " in " +
                confirmedVulnerability.getVulnerableParameter() + " parameter\",\"issuetype\":{\"name\":\"Bug\"}, \"description\":\"Found " +
                confirmedVulnerability.getVulnerabilityType() + " vulnerability in " + confirmedVulnerability.getVulnerablePath() +
                " applying the following attack vector "+ confirmedVulnerability.getAttackVector() +
                " on " + confirmedVulnerability.getVulnerableParameter() + " parameter.\n\nReferences:\n"
                + vulnerabilityReferences.get(confirmedVulnerability.getVulnerabilityType())+ "\"," +
                "\"customfield_10201\":\"" + stepsWithoutSpecialCharacters + "\", \"customfield_10200\":\"-\"," +
                "\"versions\": [";
        for (int i = 0; i < affectedVersions.length; i++) {
            data += "{\"name\":\"" + affectedVersions[i] + "\"}";
            if(i == affectedVersions.length - 1){
                data += "]}}";
            } else {
                data += ",";
            }
        }
        data = data.replace("\n", "\\n");

        return data;
    }

    /**
     * populateVulnerabilityReferencesDictionary method populates the dictionary of references for each vulnerability class.
     */
    private static void populateVulnerabilityReferencesDictionary(){
        vulnerabilityReferences = new Hashtable();

        vulnerabilityReferences.put("SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection\nhttp://en.wikipedia.org/wiki/SQL_injection\nhttps://cwe.mitre.org/data/definitions/89.html");
        vulnerabilityReferences.put("Blind SQL Injection", "https://owasp.org/www-community/attacks/Blind_SQL_Injection\nhttps://cwe.mitre.org/data/definitions/89.html");
        vulnerabilityReferences.put("Cross Site Scripting", "https://owasp.org/www-community/attacks/xss/\nhttp://en.wikipedia.org/wiki/Cross-site_scripting\nhttp://cwe.mitre.org/data/definitions/79.html");
        vulnerabilityReferences.put("File Handling", "https://owasp.org/www-community/attacks/Path_Traversal\nhttp://cwe.mitre.org/data/definitions/22.html");
        vulnerabilityReferences.put("CRLF Injection", "https://owasp.org/www-community/vulnerabilities/CRLF_Injection\nhttp://cwe.mitre.org/data/definitions/93.html");
        vulnerabilityReferences.put("Commands execution", "https://owasp.org/www-community/attacks/Command_Injection\nhttp://cwe.mitre.org/data/definitions/78.html");
        vulnerabilityReferences.put("Htaccess Bypass", "http://cwe.mitre.org/data/definitions/538.html");
        vulnerabilityReferences.put("Backup file", "http://cwe.mitre.org/data/definitions/530.html");
        vulnerabilityReferences.put("Potentially dangerous file", "http://osvdb.org/");
        vulnerabilityReferences.put("Server Side Request Forgery", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery\nhttps://cwe.mitre.org/data/definitions/918.html");
        vulnerabilityReferences.put("Open Redirect", "https://cwe.mitre.org/data/definitions/601.html");
        vulnerabilityReferences.put("XXE", "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing\nhttps://cwe.mitre.org/data/definitions/611.html");
    }

    /**
     * invokeDeleteMethod method sends a HTTP request in order to delete a particular issue in JIRA
     * @param jiraID, which is the id of the Jira issue that will be deleted
     * @throws AuthenticationException
     * @throws ClientHandlerException
     */
    public static void invokeDeleteMethod(String jiraID) throws AuthenticationException, ClientHandlerException {
        url += "/" + jiraID;

        Client client = Client.create();
        WebResource webResource = client.resource(url);
        ClientResponse response = webResource.header("Authorization", "Basic " + auth).type("application/json")
                .accept("application/json").delete(ClientResponse.class);
        int statusCode = response.getStatus();
        if (statusCode == 401) {
            throw new AuthenticationException("Invalid Username or Password");
        }
    }
}
