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

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import java.util.List;
import hudson.FilePath;
import hudson.model.Hudson;
import hudson.remoting.Callable;
import hudson.security.ACL;
import jenkins.security.MasterToSlaveCallable;

import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;


public class BasicSSHUserPrivateKeyTest {

    final static String TESTKEY_ID = "bc07f814-78bd-4b29-93d4-d25b93285f93";
    final static String TESTKEY_BEGIN = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAu1r+HHzmpybc4iwoP5+44FjvcaMkNEWeGQZlmPwLx70XW8+8";
    final static String TESTKEY_END = "sroT/IHW2jKMD0v8kKLUnKCZYzlw0By7+RvJ8lgzHB0D71f6EC1UWg==\n-----END RSA PRIVATE KEY-----";

    @Rule public JenkinsRule r = new JenkinsRule();

    @Test public void masterKeysOnSlave() throws Exception {
        FilePath keyfile = r.jenkins.getRootPath().child("key");
        keyfile.write("stuff", null);
        SSHUserPrivateKey key = new BasicSSHUserPrivateKey(CredentialsScope.SYSTEM, "mycreds", "git", new BasicSSHUserPrivateKey.FileOnMasterPrivateKeySource(keyfile.getRemote()), null, null);
        assertEquals("[stuff]", key.getPrivateKeys().toString());
        // TODO would be more interesting to use a Docker fixture to demonstrate that the file load is happening only from the master side
        assertEquals("[stuff]", r.createOnlineSlave().getChannel().call(new LoadPrivateKeys(key)));
    }
    private static class LoadPrivateKeys extends MasterToSlaveCallable<String,Exception> {
        private final SSHUserPrivateKey key;
        LoadPrivateKeys(SSHUserPrivateKey key) {
            this.key = key;
        }
        @Override public String call() throws Exception {
            return key.getPrivateKeys().toString();
        }
    }

    @LocalData
    @Test
    public void readOldCredentials() throws Exception {
        SSHUserPrivateKey supk = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(SSHUserPrivateKey.class, Hudson.getInstance(), ACL.SYSTEM, null),
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

}
