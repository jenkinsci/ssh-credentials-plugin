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
import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticatorFactory;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.trilead.ssh2.Connection;
import com.trilead.ssh2.ServerHostKeyVerifier;
import hudson.model.Computer;
import hudson.model.Items;
import hudson.slaves.DumbSlave;
import jenkins.security.MasterToSlaveCallable;

import org.apache.sshd.server.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.UserAuth;
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TrileadSSHPasswordAuthenticatorTest {

    private Connection connection;
    private StandardUsernamePasswordCredentials user;
    private SshServer sshd;

    @Rule public JenkinsRule r = new JenkinsRule();
    
    @After
    public void tearDown() throws Exception {
        if (connection != null) {
            connection.close();
            connection = null;
        }
        if (sshd!=null) {
            try {
                sshd.stop(true);
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
        }
    }

    // disabled as Apache MINA sshd does not provide easy mech for giving a Keyboard Interactive authenticator
    // so this test relies on having a local sshd which is keyboard interactive only
    public void dontTestKeyboardInteractive() throws Exception {
        connection = new Connection("localhost");
        connection.connect(new NoVerifier());
        TrileadSSHPasswordAuthenticator instance =
                new TrileadSSHPasswordAuthenticator(connection, new BasicSSHUserPassword(CredentialsScope.SYSTEM,
                        null, "....",  // <---- put your username here
                        "....",  // <---- put your password here
                        null));
        assertThat(instance.canAuthenticate(), is(true));
        assertThat(instance.authenticate(), is(true));
        assertThat(instance.isAuthenticated(), is(true));
    }

    @Before
    public void setUp() throws Exception {
        user =(StandardUsernamePasswordCredentials) Items.XSTREAM.fromXML(Items.XSTREAM.toXML(new BasicSSHUserPassword(CredentialsScope.SYSTEM, null, "foobar", "foomanchu", null)));
    }

    @Test
    public void testPassword() throws Exception {
        sshd = createPasswordAuthenticatedSshServer();
        sshd.start();
        connection = new Connection("localhost", sshd.getPort());
        connection.connect(new NoVerifier());
        TrileadSSHPasswordAuthenticator instance =
                new TrileadSSHPasswordAuthenticator(connection, user);
        assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
        assertThat(instance.canAuthenticate(), is(true));
        assertThat(instance.authenticate(), is(true));
        assertThat(instance.isAuthenticated(), is(true));
    }

    private SshServer createPasswordAuthenticatedSshServer() {
        return createPasswordAuthenticatedSshServer(null);
    }

    private SshServer createPasswordAuthenticatedSshServer(final String username) {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
            public boolean authenticate(String _username, String password, ServerSession session) {
                return (username == null || username.equals(_username)) && "foomanchu".equals(password);
            }
        });
        sshd.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthPasswordFactory()));
        return sshd;
    }

    @Test
    public void testFactory() throws Exception {
        sshd = createPasswordAuthenticatedSshServer();
        sshd.start();
        connection = new Connection("localhost", sshd.getPort());
        connection.connect(new NoVerifier());
        SSHAuthenticator instance = SSHAuthenticator.newInstance(connection, user);
        assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
        assertThat(instance.canAuthenticate(), is(true));
        assertThat(instance.authenticate(), is(true));
        assertThat(instance.isAuthenticated(), is(true));
    }

    @Test
    public void testFactoryAltUsername() throws Exception {
        sshd = createPasswordAuthenticatedSshServer("bill");
        sshd.start();
        connection = new Connection("localhost", sshd.getPort());
        connection.connect(new NoVerifier());
        SSHAuthenticator instance = SSHAuthenticator.newInstance(connection, user, null);
        assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
        assertThat(instance.canAuthenticate(), is(true));
        assertThat(instance.authenticate(), is(false));
        assertThat(instance.isAuthenticated(), is(false));
        connection = new Connection("localhost", sshd.getPort());
        connection.connect(new NoVerifier());
        instance = SSHAuthenticator.newInstance(connection, user, "bill");
        assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
        assertThat(instance.canAuthenticate(), is(true));
        assertThat(instance.authenticate(), is(true));
        assertThat(instance.isAuthenticated(), is(true));
    }

    /**
     * Brings the {@link SSHAuthenticatorFactory} to a slave.
     */
    @Test
    public void testSlave() throws Exception {
        SshServer sshd = createPasswordAuthenticatedSshServer();
        sshd.start();

        DumbSlave s = r.createSlave();
        Computer c = s.toComputer();
        c.connect(false).get();

        final int port = sshd.getPort();

        c.getChannel().call(new RemoteConnectionTest(port,user));
    }

    private static class NoVerifier implements ServerHostKeyVerifier {
        public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm,
                                           byte[] serverHostKey) throws Exception {
            return true;
        }
    }

    private static final class RemoteConnectionTest extends MasterToSlaveCallable<Void, Exception> {
        private final int port;
        private StandardUsernamePasswordCredentials user;

        public RemoteConnectionTest(int port, StandardUsernamePasswordCredentials user) {
            this.port = port;
            this.user = user;
        }

        public Void call() throws Exception {
            Connection connection = new Connection("localhost", port);
            connection.connect(new NoVerifier());
            SSHAuthenticator instance = SSHAuthenticator.newInstance(connection,user);

            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(true));
            assertThat(instance.isAuthenticated(), is(true));
            connection.close();
            return null;
        }

        private static final long serialVersionUID = 1L;
    }
}
