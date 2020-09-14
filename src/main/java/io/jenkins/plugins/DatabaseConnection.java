package io.jenkins.plugins;
import java.sql.*;

import hudson.util.Secret;
import oracle.jdbc.driver.*;


public class DatabaseConnection {

    private Connection connection;

    /**
     * DatabaseConnection is the constructor, which connects to the SQL database
     * @param url of the SQL server
     * @param username of the SQL user
     * @param password of the SQL user
     */
    public DatabaseConnection(String url, String username, Secret password){
        try {
            Class.forName("com.mysql.jdbc.Driver");
            DriverManager.registerDriver(new oracle.jdbc.driver.OracleDriver());
            this.connection = DriverManager.getConnection (url, username, password.getPlainText());
            System.out.println("");
        } catch (SQLException | ClassNotFoundException throwables) {
            throwables.printStackTrace();
        }
    }

     /**
     * closeDBConnection method closes the connection with the SQL database
     */
    public void closeDBConnection(){
        try{
            this.connection.close();
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
    }

    /**
     * insertNewBlacklistElement method adds a vulnerability in the blacklist tables in the database
     * @param vulnerabilityType, the type of vulnerability of false positive vulnerability
     * @param path, the url where the vulnerability was detected
     * @param parameter, the parameter where the vulnerability was exploited
     * @param epoch, the epoch of security report file
     */
    public void insertNewBlacklistElement(String vulnerabilityType, String path, String parameter, String attackVector, long epoch){
        try {
            PreparedStatement insertBlacklist = this.connection.prepareStatement("INSERT INTO blacklist (vulnerability_type, path, parameter, attack_vector, report_epoch) VALUES (?,?,?,?,?)");
            insertBlacklist.setString(1, vulnerabilityType);
            insertBlacklist.setString(2, path);
            insertBlacklist.setString(3, parameter);
            insertBlacklist.setString(4, attackVector);
            insertBlacklist.setLong(5, epoch);
            boolean result = insertBlacklist.execute();
            insertBlacklist.close();
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
    }

     /**
     * checkBlacklistElement method checks if a particular false positive vulnerability is already in the database
     * @param vulnerabilityType the type of vulnerability of false positive vulnerability
     * @param path where the vulnerability was detected
     * @param parameter where the vulnerability was exploited
     * @return true, if the false positive vulnerability is already in the DB. Otherwise, false
     */
    public boolean checkBlacklistElement(String vulnerabilityType, String path, String parameter, String attackVector){
        boolean exist = false;
        try {
            PreparedStatement selectBlacklist = this.connection.prepareStatement("SELECT * FROM blacklist");
            ResultSet results = selectBlacklist.executeQuery();

            while (results.next())
            {
                String blacklistVulnerabilityType = results.getString("vulnerability_type");
                String blacklistPath = results.getString("path");
                String blacklistParameter = results.getString("parameter");
                String blacklistAttackVector = results.getString("attack_vector");

                if(blacklistVulnerabilityType.equals(vulnerabilityType) && blacklistPath.equals(path) && blacklistParameter.equals(parameter) && blacklistAttackVector.equals(attackVector)){
                    exist = true;
                }
            }
            results.close();
            selectBlacklist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return exist;
    }

    /**
     * insertNewConfirmedElement method adds a vulnerability in the whitelist table in the database
     * @param vulnerabilityType the type of vulnerability of false positive vulnerability
     * @param path of HTTP request
     * @param parameter where the vulnerability was exploited
     * @param method of HTTP request
     * @param url where the vulnerability was detected
     * @param howToReproduce the steps to reproduce the detected vulnerability
     * @param projectKey the key of Jira project in order to create an issue
     * @param affectedVersions the affected versions of Jira
     * @param requestID the ID which is generated when a Jira issue is created
     * @param jiraID the Jira ID which is the key of the Jira issue (e.g. IMD-101)
     * @param issueURL the url of the created Jira issue
     * @param epoch the epoch of the security report
     */
    public void insertNewConfirmedElement(String vulnerabilityType, String path, String parameter, String method, String url, String howToReproduce, String projectKey, String affectedVersions, String requestID, String jiraID, String issueURL, long epoch){
        try {
            PreparedStatement insertWhitelist = this.connection.prepareStatement("INSERT INTO whitelist (vulnerability_type, path, parameter, method, url, how_to_reproduce, project_key, affected_versions, id_request, id_jira, issue_url, report_epoch) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)");
            insertWhitelist.setString(1, vulnerabilityType);
            insertWhitelist.setString(2, path);
            insertWhitelist.setString(3, parameter);
            insertWhitelist.setString(4, method);
            insertWhitelist.setString(5, url);
            insertWhitelist.setString(6, howToReproduce);
            insertWhitelist.setString(7, projectKey);
            insertWhitelist.setString(8, affectedVersions);
            insertWhitelist.setString(9, requestID);
            insertWhitelist.setString(10, jiraID);
            insertWhitelist.setString(11, issueURL);
            insertWhitelist.setLong(12, epoch);
            boolean result = insertWhitelist.execute();
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
    }

    /**
     * checkConfirmedElement method checks if a confirmed vulnerability is already in the whitelist table
     * @param vulnerabilityType the type of vulnerability of false positive vulnerability
     * @param path of HTTP request
     * @param parameter where the vulnerability was exploited
     * @param method of HTTP request
     * @return
     */
    public boolean checkConfirmedElement(String vulnerabilityType, String path, String parameter, String method){
        boolean exist = false;
        try {
            PreparedStatement selectWhitelist = this.connection.prepareStatement("SELECT * FROM whitelist");
            ResultSet results = selectWhitelist.executeQuery();

            while (results.next())
            {
                String whitelistVulnerabilityType = results.getString("vulnerability_type");
                String whitelistPath = results.getString("path");
                String whitelistParameter = results.getString("parameter");
                String whitelistMethod = results.getString("method");

                if(whitelistVulnerabilityType.equals(vulnerabilityType) && whitelistPath.equals(path) && whitelistParameter.equals(parameter) && whitelistMethod.equals(method)){
                    exist = true;
                }
            }
            results.close();
            selectWhitelist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return exist;
    }

    /**
     * getIDFromWhitelist method gets the ID of a particular whitelist vulnerability
     * @param vulnerabilityType the type of vulnerability of false positive vulnerability
     * @param path of HTTP request
     * @param parameter where the vulnerability was exploited
     * @param method of HTTP request
     * @return id of the confirmed vulnerability. Otherwise, -1.
     */
    public int getIDFromWhitelist(String vulnerabilityType, String path, String parameter, String method){
        int id = -1;
        try {
            PreparedStatement selectWhitelist = this.connection.prepareStatement("SELECT id FROM whitelist WHERE vulnerability_type=? " +
                    "AND path=? AND parameter=? AND method=?");
            selectWhitelist.setString(1, vulnerabilityType);
            selectWhitelist.setString(2, path);
            selectWhitelist.setString(3, parameter);
            selectWhitelist.setString(4, method);

            ResultSet results = selectWhitelist.executeQuery();

            while (results.next())
            {
                id = results.getInt("id");
            }
            results.close();
            selectWhitelist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return id;
    }

    /**
     * getIDFromBlacklist method gets the ID of a particular blacklist vulnerability
     * @param vulnerabilityType the type of vulnerability of false positive vulnerability
     * @param path where the vulnerability was detected
     * @param parameter where the vulnerability was exploited
     * @return id of the confirmed vulnerability. Otherwise, -1.
     */
    public int getIDFromBlacklist(String vulnerabilityType, String path, String parameter, String attackVector){
        int id = -1;
        try {
            PreparedStatement selectBlacklist = this.connection.prepareStatement("SELECT id FROM blacklist WHERE vulnerability_type=? " +
                    "AND path=? AND parameter=? AND attack_vector=?");
            selectBlacklist.setString(1, vulnerabilityType);
            selectBlacklist.setString(2, path);
            selectBlacklist.setString(3, parameter);
            selectBlacklist.setString(4, attackVector);

            ResultSet results = selectBlacklist.executeQuery();

            while (results.next())
            {
                id = results.getInt("id");
            }
            results.close();
            selectBlacklist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return id;
    }

    /**
     * getEpochFromBlacklist method gets the epoch of the security report where the vulnerabilities was selected as blacklist element
     * @param id of the database entry
     * @return epoch of the security report. Otherwise, 0.
     */
    public long getEpochFromBlacklist(int id){
        long epoch = 0;
        try {
            PreparedStatement selectBlacklist = this.connection.prepareStatement("SELECT report_epoch FROM blacklist WHERE id=?");
            selectBlacklist.setInt(1, id);

            ResultSet results = selectBlacklist.executeQuery();

            while (results.next())
            {
                epoch = results.getLong("report_epoch");
            }
            results.close();
            selectBlacklist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return epoch;
    }

    /**
     * getEpochFromWhitelist method gets the epoch of the security report where the vulnerabilities was selected as confirmed element
     * @param id of the database entry
     * @return epoch of the security report. Otherwise, 0.
     */
    public long getEpochFromWhitelist(int id){
        long epoch = 0;
        try {
            PreparedStatement selectWhitelist = this.connection.prepareStatement("SELECT report_epoch FROM whitelist where id=?");
            selectWhitelist.setInt(1, id);

            ResultSet results = selectWhitelist.executeQuery();

            while (results.next())
            {
                epoch = results.getLong("report_epoch");

            }
            results.close();
            selectWhitelist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return epoch;
    }

    /**
     * getHowToReproduce method gets the steps in order to reproduce the vulnerability
     * @param id of the database entry
     * @return the steps to reproduce the vulnerability
     */
    public String getHowToReproduce(int id){
        String howToReproduce = "";
        try {
            PreparedStatement selectWhitelist = this.connection.prepareStatement("SELECT how_to_reproduce FROM whitelist WHERE id=?");
            selectWhitelist.setInt(1, id);

            ResultSet results = selectWhitelist.executeQuery();

            while (results.next())
            {
                howToReproduce = results.getString("how_to_reproduce");
            }
            results.close();
            selectWhitelist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return howToReproduce;
    }

    /**
     * getProjectKey method gets the project key of Jira of a particular vulnerbaility
     * @param id of the database entry
     * @return the project key of Jira
     */
    public String getProjectKey(int id){
        String projectKey = "";
        try {
            PreparedStatement selectWhitelist = this.connection.prepareStatement("SELECT project_key FROM whitelist WHERE id=?");
            selectWhitelist.setInt(1, id);

            ResultSet results = selectWhitelist.executeQuery();

            while (results.next())
            {
                projectKey = results.getString("project_key");
            }
            results.close();
            selectWhitelist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return projectKey;
    }

    /**
     * getAffectedVersions method gets the affected versions of Jira issue of a particular vulnerbaility
     * @param id of the database entry
     * @return the affected versions of Jira issue
     */
    public String getAffectedVersions(int id){
        String affectedVersions = "";
        try {
            PreparedStatement selectWhitelist = this.connection.prepareStatement("SELECT affected_versions FROM whitelist WHERE id=?");
            selectWhitelist.setInt(1, id);

            ResultSet results = selectWhitelist.executeQuery();

            while (results.next())
            {
                affectedVersions = results.getString("affected_versions");
            }
            results.close();
            selectWhitelist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return affectedVersions;
    }

     /**
     * getRequestID method gets the id of the request which is generated when a Jira issue is created
     * @param id of the database entry
     * @return the id of the request which is generated when a Jira issue is created
     */
    public String getRequestID(int id){
        String requestID = "";
        try {
            PreparedStatement selectWhitelist = this.connection.prepareStatement("SELECT * FROM whitelist WHERE id=?");
            selectWhitelist.setInt(1, id);

            ResultSet results = selectWhitelist.executeQuery();

            while (results.next())
            {
                requestID = results.getString("id_request");
            }
            results.close();
            selectWhitelist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return requestID;
    }

    /**
     * getJiraID method gets the id of jira issue
     * @param id of the database entry
     * @return the id of jira issue
     */
    public String getJiraID(int id){
        String jiraID = "";
        try {
            PreparedStatement selectWhitelist = this.connection.prepareStatement("SELECT * FROM whitelist WHERE id=?");
            selectWhitelist.setInt(1, id);

            ResultSet results = selectWhitelist.executeQuery();

            while (results.next())
            {
                jiraID = results.getString("id_jira");
            }
            results.close();
            selectWhitelist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return jiraID;
    }

    /**
     * getIssueURL method gets the url of jira issue
     * @param id of the database entry
     * @return the url of the jira issue
     */
    public String getIssueURL(int id){
        String issueURL = "";
        try {
            PreparedStatement selectWhitelist = this.connection.prepareStatement("SELECT * FROM whitelist WHERE id=?");
            selectWhitelist.setInt(1, id);

            ResultSet results = selectWhitelist.executeQuery();

            while (results.next())
            {
                issueURL = results.getString("issue_url");
            }
            results.close();
            selectWhitelist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return issueURL;
    }

    /**
     * removeElementFromBlacklist method deletes a blacklist element from the blacklist table in the DB
     * @param id of the vulnerability entry in the DB which will be deleted
     */
    public void removeElementFromBlacklist(int id){
        try {
            PreparedStatement deleteBlacklist = this.connection.prepareStatement("DELETE FROM blacklist WHERE id=?");
            deleteBlacklist.setInt(1, id);

            deleteBlacklist.executeUpdate();

            deleteBlacklist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
    }

     /**
     * removeElementFromWhitelist method deletes a whitelist element from the blacklist table in the DB
     * @param id of the vulnerability entry in the DB which will be deleted
     */
    public void removeElementFromWhitelist(int id){
        try {
            PreparedStatement deleteWhitelist = this.connection.prepareStatement("DELETE FROM whitelist WHERE id=?");
            deleteWhitelist.setInt(1, id);

            deleteWhitelist.executeUpdate();

            deleteWhitelist.close();

        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
    }
}
