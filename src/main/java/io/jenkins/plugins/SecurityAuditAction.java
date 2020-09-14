package io.jenkins.plugins;

import com.sun.jersey.api.client.ClientResponse;
import hudson.FilePath;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.Run;
import hudson.model.UnprotectedRootAction;
import hudson.util.Secret;
import jenkins.model.RunAction2;
import org.apache.http.auth.AuthenticationException;
import org.apache.tools.ant.taskdefs.condition.Http;
import org.json.JSONArray;
import org.json.JSONObject;
import org.kohsuke.stapler.bind.JavaScriptMethod;

import javax.xml.transform.sax.SAXSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

/*
*   TestAction class usually adds additional information, behaviors, and UIs.
*   This class adds a new item menu in the build information menu.
*/
public class SecurityAuditAction implements RunAction2, UnprotectedRootAction {

    private transient Run run;
    private AbstractBuild<?,?> build;
    private String artifactPath;
    private String fileContent;
    private ArrayList<Vulnerability> vulnerabilities;
    private String sqlUrl;
    private String sqlUsername;
    private Secret sqlPassword;
    private String jiraUrl;
    private String jiraUsername;
    private Secret jiraPassword;
    private String HTTPBadRequest;

    private FileHandler file;

    public SecurityAuditAction(Run run, String artifactPath, String sqlUrl, String sqlUsername, Secret sqlPassword, String jiraUrl, String jiraUsername, Secret jiraPassword){
        this.run = run;
        this.artifactPath = artifactPath;

        this.sqlUrl = sqlUrl;
        this.sqlUsername = sqlUsername;
        this.sqlPassword = sqlPassword;
        this.jiraUrl = jiraUrl;
        this.jiraUsername = jiraUsername;
        this.jiraPassword = jiraPassword;

        this.file = new FileHandler(run, artifactPath, sqlUrl, sqlUsername, sqlPassword);
    }

    /**
     * getVulnerabilities method retrieves the vulnerabilities information in order to display it in the list
     * @return an ArrayList of Vulnerability Objects containing the information of vulnerabilities
     */
    public ArrayList<Vulnerability> getVulnerabilities() {
        this.vulnerabilities = this.file.getVulnerabilities();
        return vulnerabilities;
    }

    public String getErrorMessage(){
        System.out.println(this.HTTPBadRequest);
        return this.HTTPBadRequest;
    }

    @Override
    public String getIconFileName() {
        return "document.png";
    }

    @Override
    public String getDisplayName() {
        return "Summary Security Report";
    }

    @Override
    public String getUrlName() {
        return "report";
    }

    @Override
    public void onAttached(Run<?, ?> run) {
        this.run = run;
    }

    @Override
    public void onLoad(Run<?, ?> run) {
        this.run = run;
    }

    public Run getRun() {
        return run;
    }

    /**
     * submitData method manages the information when the user clicks the submit button. More in details, it retrieves
     * the values of all input in the tables, such as the options, the how to reproduce steps, the projects keys and the affected versions.
     * It calls all method in order to manage the vulnerabilities based on the option type.
     * @param options the array that contains the type of option for each detected vulnerability (i.e. no actions, confirm bug and add blacklist)
     * @param actionSteps the array that contains the steps in order to reproduce the bug. 
     *                    If the option value is not equal to confirm bug, then the element is an empty string.
     * @param projectKey the array that contains the project key of Jira. If the option value is not equal to confirm bug, 
     *                   the the element in the array is an empty string.
     * @param affectedVersion the array that contains the list of affected versions (i.e. "0.4.0-1;1.3.0-1"). 
     *                        If the option value is not equal to confirm bug, then the element in the array is an empty string.
     */
    @JavaScriptMethod
    public void submitData(String[] options, String[] actionSteps, String[] projectKey, String[] affectedVersion) {
        ArrayList<String> optionsArray = new ArrayList<String>(Arrays.asList(options)) ;
        ArrayList<String> actionStepsArray = new ArrayList<String>(Arrays.asList(actionSteps));
        ArrayList<String> projectKeyArray =  new ArrayList<String>(Arrays.asList(projectKey));
        ArrayList<String> affectedVersionArray =  new ArrayList<String>(Arrays.asList(affectedVersion));

        this.file.updateBlacklist(optionsArray);
        this.file.updateStatusInSecurityReport(optionsArray);

        ArrayList<String> jiraResponse = new ArrayList<String>();
        JiraConnection.main(this.jiraUrl, this.jiraUsername, this.jiraPassword);
        this.HTTPBadRequest = "";
        for(int i = 0; i < optionsArray.size(); i++){
            if(optionsArray.get(i).equals("confirmed") && vulnerabilities.get(i).getProjectKey() == null) {
                try{
                    ClientResponse response = JiraConnection.invokePostMethod(projectKeyArray.get(i), affectedVersionArray.get(i), actionStepsArray.get(i), vulnerabilities.get(i));
                    if(response.getStatus() == 400){
                        jiraResponse.add("");
                        optionsArray.set(i, "no_action");
                        String error = response.getEntity(String.class);
                        this.HTTPBadRequest += parseErrorMessage(i, error);
                    } else {
                        jiraResponse.add(response.getEntity(String.class));
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else {
                jiraResponse.add("");
            }
        }

        this.file.addHowToReproduceDescriptionInSecurityReport(actionStepsArray, optionsArray);
        this.file.addJiraInformationToSecurityReport(projectKeyArray, affectedVersionArray, optionsArray, jiraResponse);
        this.file.updateConfirmedList(optionsArray);
    }

    /**
     * cleanUp method removes the blacklist vulnerabilities from JSON security report
     * @param options the array that contains the type of option for each detected vulnerability (i.e. no actions, confirm bug and add blacklist)
     */
    @JavaScriptMethod
    public void cleanUp(String[] options){
        ArrayList<String> optionsArray = new ArrayList<String>(Arrays.asList(options));
        this.file.removeBlacklistElementFromSecurityReport(optionsArray);
    }

    /**
     * resetStatus method resets the status of a particular vulnerability in order to delete it from blacklist or whitelist table in the DB.
     * Moreover, if the vulnerability is in the whitelist, then this method delete from Jira the related issue.
     * @param index of the vulnerability
     */
    @JavaScriptMethod
    public void resetStatus(String index){
        int vulnerabilityIndex = Integer.parseInt(index.trim());
        DatabaseConnection database = new DatabaseConnection(this.sqlUrl, this.sqlUsername, this.sqlPassword);

        String vulnerabilityType = this.vulnerabilities.get(vulnerabilityIndex).getVulnerabilityType();
        String vulnerableURL =  this.vulnerabilities.get(vulnerabilityIndex).getUrl();
        String parameter = this.vulnerabilities.get(vulnerabilityIndex).getVulnerableParameter();
        String path = this.vulnerabilities.get(vulnerabilityIndex).getVulnerablePath();;
        String method = this.vulnerabilities.get(vulnerabilityIndex).getHTTPMethod();
        String attackVector = this.vulnerabilities.get(vulnerabilityIndex).getAttackVector();

        if(vulnerabilities.get(vulnerabilityIndex).getStatus().equals("Confirmed")){
            boolean existWhitelistElement = database.checkConfirmedElement(vulnerabilityType, path, parameter, method);
            if(existWhitelistElement) {
                int id = database.getIDFromWhitelist(vulnerabilityType, path, parameter, method);
                database.removeElementFromWhitelist(id);

                JiraConnection.main(jiraUrl, jiraUsername, jiraPassword);
                try {
                    JiraConnection.invokeDeleteMethod(this.vulnerabilities.get(vulnerabilityIndex).getIssueJiraID());
                } catch (AuthenticationException e) {
                    e.printStackTrace();
                }
                this.vulnerabilities.get(vulnerabilityIndex).setStatus("Not confirmed");
            }
        } else {
            boolean existBlacklistElement = database.checkBlacklistElement(vulnerabilityType, path, parameter, attackVector);
            if(existBlacklistElement) {
                int id = database.getIDFromBlacklist(vulnerabilityType, path, parameter, attackVector);
                database.removeElementFromBlacklist(id);
                this.vulnerabilities.get(vulnerabilityIndex).setStatus("Not confirmed");
            }
        }
        database.closeDBConnection();
    }

    private String parseErrorMessage(int index, String error){
        String HTTPerror = "VULNERABILITY #" + (index + 1) + " ";
        JSONObject jsonError = new JSONObject(error);
        if(jsonError.has("errorMessages")){
            JSONArray errorMessages = jsonError.getJSONArray("errorMessages");
            for(int i = 0; i < errorMessages.length(); i++) {
                HTTPerror += errorMessages.getString(i);
                HTTPerror += "\n";
            }
        }
        if(jsonError.has("errors")) {
            JSONObject errors = jsonError.getJSONObject("errors");
            for(Iterator key = errors.keys(); key.hasNext();){
                String item = key.next().toString();
                HTTPerror += item;
                HTTPerror += ": ";
                HTTPerror += errors.getString(item);
                HTTPerror += ". ";
            }
        }
        return HTTPerror;
    }
}
