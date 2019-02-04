/*
 * The MIT License
 *
 * Copyright 2014 Jesse Glick.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import java.util.List;
import hudson.FilePath;
import hudson.cli.CLICommandInvoker;
import hudson.cli.UpdateJobCommand;
import hudson.model.Hudson;
import hudson.model.Job;
import hudson.security.ACL;
import jenkins.model.Jenkins;

import org.junit.Test;

import static hudson.cli.CLICommandInvoker.Matcher.failedWith;
import static hudson.cli.CLICommandInvoker.Matcher.succeeded;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

public class BasicSSHUserPrivateKeyTest {

    final static String TESTKEY_ID = "bc07f814-78bd-4b29-93d4-d25b93285f93";
    final static String TESTKEY_BEGIN = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAu1r+HHzmpybc4iwoP5+44FjvcaMkNEWeGQZlmPwLx70XW8+8";
    final static String TESTKEY_END = "sroT/IHW2jKMD0v8kKLUnKCZYzlw0By7+RvJ8lgzHB0D71f6EC1UWg==\n-----END RSA PRIVATE KEY-----";

    @Rule public JenkinsRule r = new JenkinsRule();

    @LocalData
    @Test
    public void readOldCredentials() throws Exception {
        SSHUserPrivateKey supk = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(SSHUserPrivateKey.class, Hudson.getInstance(), ACL.SYSTEM,
                        (List<DomainRequirement>)null),
                CredentialsMatchers.withId(TESTKEY_ID));
        assertNotNull(supk);
        List<String> keyList = supk.getPrivateKeys();
        assertNotNull(keyList);
        assertEquals(keyList.size(), 1);
        String privateKey = keyList.get(0);
        assertNotNull(privateKey);
        assertTrue(privateKey.startsWith(TESTKEY_BEGIN));
        assertTrue(privateKey.endsWith(TESTKEY_END));
    }

    // TODO demonstrate that all private key sources are round-tripped in XStream

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
