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
import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.FilePath;
import hudson.remoting.Callable;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.jvnet.hudson.test.JenkinsRule;

public class BasicSSHUserPrivateKeyTest {

    @Rule public JenkinsRule r = new JenkinsRule();

    @Test public void masterKeysOnSlave() throws Exception {
        FilePath keyfile = r.jenkins.getRootPath().child("key");
        keyfile.write("stuff", null);
        SSHUserPrivateKey key = new BasicSSHUserPrivateKey(CredentialsScope.SYSTEM, "mycreds", "git", new BasicSSHUserPrivateKey.FileOnMasterPrivateKeySource(keyfile.getRemote()), null, null);
        assertEquals("[stuff]", key.getPrivateKeys().toString());
        // TODO would be more interesting to use a Docker fixture to demonstrate that the file load is happening only from the master side
        assertEquals("[stuff]", r.createOnlineSlave().getChannel().call(new LoadPrivateKeys(key)));
    }
    private static class LoadPrivateKeys implements Callable<String,Exception> {
        private final SSHUserPrivateKey key;
        LoadPrivateKeys(SSHUserPrivateKey key) {
            this.key = key;
        }
        @Override public String call() throws Exception {
            return key.getPrivateKeys().toString();
        }
    }

    // TODO demonstrate that all private key sources are round-tripped in XStream

}
