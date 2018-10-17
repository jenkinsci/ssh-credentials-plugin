package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.FilePath;
import hudson.cli.CLICommandInvoker;
import hudson.cli.UpdateJobCommand;
import hudson.model.Job;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import static hudson.cli.CLICommandInvoker.Matcher.failedWith;
import static hudson.cli.CLICommandInvoker.Matcher.succeeded;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

//TODO merge it into BasicSSHUserPrivateKeyTest after security patch
public class BasicSSHUserPrivateKeyTest_SEC440 {
    
    @Rule
    public JenkinsRule r = new JenkinsRule();
    
    {r.timeout = 0;}
    
    @Test
    @Issue("SECURITY-440")
    @LocalData("updateJob")
    public void userWithoutRunScripts_cannotMigrateDangerousPrivateKeySource() throws Exception {
        Folder folder = r.jenkins.createProject(Folder.class, "folder1");
        
        FilePath updateFolder = r.jenkins.getRootPath().child("update_folder.xml");
        
        { // as user with just configure, you cannot migrate
            CLICommandInvoker.Result result = new CLICommandInvoker(r, new UpdateJobCommand())
                    .authorizedTo(Jenkins.READ, Job.READ, Job.CONFIGURE)
                    .withStdin(updateFolder.read())
                    .invokeWithArgs("folder1");
            
            assertThat(result.stderr(), containsString("user is missing the Overall/RunScripts permission"));
            assertThat(result, failedWith(-1));
            
            // config file not touched
            String configFileContent = folder.getConfigFile().asString();
            assertThat(configFileContent, not(containsString("FileOnMasterPrivateKeySource")));
            assertThat(configFileContent, not(containsString("BasicSSHUserPrivateKey")));
        }
        { // but as admin with RUN_SCRIPTS, you can
            CLICommandInvoker.Result result = new CLICommandInvoker(r, new UpdateJobCommand())
                    .authorizedTo(Jenkins.ADMINISTER)
                    .withStdin(updateFolder.read())
                    .invokeWithArgs("folder1");
            
            assertThat(result, succeeded());
            String configFileContent = folder.getConfigFile().asString();
            assertThat(configFileContent, containsString("BasicSSHUserPrivateKey"));
            assertThat(configFileContent, not(containsString("FileOnMasterPrivateKeySource")));
        }
    }
}
