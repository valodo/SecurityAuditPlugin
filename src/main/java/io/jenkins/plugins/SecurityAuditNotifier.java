package io.jenkins.plugins;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Run;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.util.Secret;
import org.jenkinsci.Symbol;
import org.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import java.net.URI;

public class SecurityAuditNotifier extends Notifier {

    private String sql_url;
    private String sql_username;
    private Secret sql_password;
    private String jira_url;
    private String jira_username;
    private Secret jira_password;

    @DataBoundConstructor
    public SecurityAuditNotifier(String sql_url, String sql_username, Secret sql_password, String jira_url, String jira_username, Secret jira_password){
        this.sql_url = sql_url;
        this.sql_username = sql_username;
        this.sql_password = sql_password;
        this.jira_url = jira_url;
        this.jira_username = jira_username;
        this.jira_password = jira_password;
    }

    public String getSql_url(){
        return this.sql_url;
    }

    public String getSql_username(){
        return this.sql_username;
    }

    public Secret getSql_password(){
        return this.sql_password;
    }

    public String getJira_url(){
        return this.jira_url;
    }

    public String getJira_username(){
        return this.jira_username;
    }

    public Secret getJira_password(){
        return this.jira_password;
    }

    @Override
    public boolean perform(final AbstractBuild build, final Launcher launcher, final BuildListener listener) {
        Run run = build;
        String artifactPath = run.getArtifactManager().root().toURI().getPath();
        listener.getLogger().println("Security Audit Plugin - Artifacts directory: " + artifactPath);
        listener.getLogger().println("Security Audit Plugin - Current workspace: " + build.getProject().getSomeWorkspace().toString());
        build.addAction(new SecurityAuditAction(run, artifactPath, this.sql_url, this.sql_username, this.sql_password, this.jira_url, this.jira_username, this.jira_password));
        return true;
    }

    @Extension
    public static class SecurityAuditDescriptor extends BuildStepDescriptor<Publisher> {

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Summary Security Report";
        }
    }
}
