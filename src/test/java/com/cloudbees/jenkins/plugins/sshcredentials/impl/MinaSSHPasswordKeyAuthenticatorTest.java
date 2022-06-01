package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticator;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.IOException;
import java.util.Collections;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class MinaSSHPasswordKeyAuthenticatorTest {

    private static final Logger LOGGER = Logger.getLogger(MinaSSHPasswordKeyAuthenticatorTest.class.getName());

    private SshServer sshd;

    @Rule
    public JenkinsRule r = new JenkinsRule();

    private final StandardUsernamePasswordCredentials user =
        new UsernamePasswordCredentialsImpl(CredentialsScope.SYSTEM, null, "foobar", "foobar", "foomanchu");

    @After
    public void tearDown() {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Problems shutting down ssh server", e);
            }
        }
    }

    @Before
    public void setUp() throws IOException {
        sshd = SshServer.setUpDefaultServer();
        sshd.setHost("localhost");
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPasswordAuthenticator((s, s1, serverSession) -> user.getUsername().equals(s) && user.getPassword().getPlainText().equals(s1));
        sshd.setUserAuthFactories(Collections.singletonList(new UserAuthPasswordFactory()));
        try {
            sshd.start();
            LOGGER.log(Level.INFO, "Started ssh Server");
        } catch (Throwable e) {
            LOGGER.log(Level.WARNING, "Problems starting ssh server", e);
            try {
                sshd.stop();
            } catch (Throwable t) {
                LOGGER.log(Level.WARNING, "Problems shutting down ssh server", t);
            }
            throw e;
        }
    }

    @Test
    public void testAuthenticate() throws Exception {
        try (SshClient sshClient = SshClient.setUpDefaultClient()) {
            sshClient.start();
            try (ClientSession connection = sshClient
                .connect(user.getUsername(), sshd.getHost(), sshd.getPort())
                .verify(15, TimeUnit.SECONDS)
                .getClientSession()) {

                MinaSSHPasswordKeyAuthenticator instance = new MinaSSHPasswordKeyAuthenticator(connection, user);
                assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
                assertThat(instance.canAuthenticate(), is(true));
                assertThat(instance.authenticate(), is(true));
                assertThat(instance.isAuthenticated(), is(true));
            }
        }
    }

    @Test
    public void testFactory() throws Exception {
        try (SshClient sshClient = SshClient.setUpDefaultClient()) {
            sshClient.start();
            try (ClientSession connection = sshClient
                .connect(user.getUsername(), sshd.getHost(), sshd.getPort())
                .verify(30, TimeUnit.SECONDS)
                .getClientSession()) {

                SSHAuthenticator<Object, StandardUsernameCredentials> instance = SSHAuthenticator.newInstance(connection, user);
                assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
                assertThat(instance.canAuthenticate(), is(true));
                assertThat(instance.authenticate(), is(true));
                assertThat(instance.isAuthenticated(), is(true));
            }
        }
    }
}
