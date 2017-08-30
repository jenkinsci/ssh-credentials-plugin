/*
 * The MIT License
 *
 * Copyright (c) 2011-2012, CloudBees, Inc., Stephen Connolly.
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

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticator;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.UserInfo;
import hudson.model.Items;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.UserAuth;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

public class JSchSSHPasswordAuthenticatorTest {

    private JSchConnector connector;
    private StandardUsernamePasswordCredentials user;

    @Rule public JenkinsRule r = new JenkinsRule();
    
    @After
    public void tearDown() throws Exception {
        if (connector != null) {
            connector.close();
            connector = null;
        }
    }

    // disabled as Apache MINA sshd does not provide easy mech for giving a Keyboard Interactive authenticator
    // so this test relies on having a local sshd which is keyboard interactive only
    public void dontTestKeyboardInteractive() throws Exception {

        BasicSSHUserPassword user = new BasicSSHUserPassword(CredentialsScope.SYSTEM,
                null, "....",  // <---- put your username here
                "....",  // <---- put your password here
                null);
        JSch jsch = new JSch();
        jsch.setHostKeyRepository(new BlindTrustHostKeyRepository());
        connector = new JSchConnector(user.getUsername(), "localhost", 22);
        JSchSSHPasswordAuthenticator instance = new JSchSSHPasswordAuthenticator (connector, user);
        assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.BEFORE_CONNECT));
        assertThat(instance.canAuthenticate(), is(true));
        assertThat(instance.authenticate(), is(true));
        assertThat(instance.isAuthenticated(), is(true));
        assertThat(connector.getSession().isConnected(), is(false));
        connector.getSession().setConfig("StrictHostKeyChecking", "no");
        connector.getSession().connect((int) TimeUnit.SECONDS.toMillis(60));
        assertThat(connector.getSession().isConnected(), is(true));
    }

    @Before
    public void setUp() throws Exception {
        user =(StandardUsernamePasswordCredentials) Items.XSTREAM.fromXML(Items.XSTREAM.toXML(new BasicSSHUserPassword(CredentialsScope.SYSTEM, null, "foobar", "foomanchu", null)));
    }

    @Test
    public void testPassword() throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
            public boolean authenticate(String username, String password, ServerSession session) {
                return "foomanchu".equals(password);
            }
        });
        sshd.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthPasswordFactory()));
        try {
            sshd.start();
            connector = new JSchConnector(user.getUsername(),"localhost", sshd.getPort());
            JSchSSHPasswordAuthenticator instance = new JSchSSHPasswordAuthenticator(connector, user);
            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.BEFORE_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(true));
            assertThat(instance.isAuthenticated(), is(true));
            assertThat(connector.getSession().isConnected(), is(false));
            connector.getSession().setConfig("StrictHostKeyChecking", "no");
            connector.getSession().connect((int) TimeUnit.SECONDS.toMillis(30));
            assertThat(connector.getSession().isConnected(), is(true));
        } finally {
            try {
                sshd.stop(true);
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
        }
    }

    @Test
    public void testFactory() throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
            public boolean authenticate(String username, String password, ServerSession session) {
                return "foomanchu".equals(password);
            }
        });
        sshd.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthPasswordFactory()));
        try {
            sshd.start();
            connector = new JSchConnector(user.getUsername(),"localhost", sshd.getPort());
            SSHAuthenticator instance = SSHAuthenticator.newInstance(connector, user);
            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.BEFORE_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(true));
            assertThat(instance.isAuthenticated(), is(true));
            assertThat(connector.getSession().isConnected(), is(false));
            connector.getSession().setConfig("StrictHostKeyChecking", "no");
            connector.getSession().connect((int) TimeUnit.SECONDS.toMillis(30));
            assertThat(connector.getSession().isConnected(), is(true));
        } finally {
            try {
                sshd.stop(true);
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
        }
    }

    private static class BlindTrustHostKeyRepository implements HostKeyRepository {

        public int check(String host, byte[] key) {
            return OK;
        }

        public void add(HostKey hostkey, UserInfo ui) {
        }

        public void remove(String host, String type) {
        }

        public void remove(String host, String type, byte[] key) {
        }

        public String getKnownHostsRepositoryID() {
            return null;
        }

        public HostKey[] getHostKey() {
            return new HostKey[0];
        }

        public HostKey[] getHostKey(String host, String type) {
            return new HostKey[0];
        }
    }
}
