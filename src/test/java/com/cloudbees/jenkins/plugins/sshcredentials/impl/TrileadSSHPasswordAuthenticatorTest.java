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
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import hudson.slaves.DumbSlave;
import jenkins.security.MasterToSlaveCallable;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.MatcherAssert.assertThat;

public class TrileadSSHPasswordAuthenticatorTest {

    private Connection connection;
    private StandardUsernamePasswordCredentials user;
    private Object sshd;

    @Rule public JenkinsRule r = new JenkinsRule();
    
    @After
    public void tearDown() {
        if (connection != null) {
            connection.close();
            connection = null;
        }
        if (sshd!=null) {
            try {
                invoke(sshd, "stop", new Class<?>[] {Boolean.TYPE}, new Object[] {true});
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
    public void setUp() {
        user =(StandardUsernamePasswordCredentials) Items.XSTREAM.fromXML(Items.XSTREAM.toXML(new BasicSSHUserPassword(CredentialsScope.SYSTEM, null, "foobar", "foomanchu", null)));
    }

    @Test
    public void testPassword() throws Exception {
        sshd = createPasswordAuthenticatedSshServer();
        invoke(sshd, "start", null, null);
        int port = (Integer)invoke(sshd, "getPort", null, null);
        connection = new Connection("localhost", port);
        connection.connect(new NoVerifier());
        TrileadSSHPasswordAuthenticator instance =
                new TrileadSSHPasswordAuthenticator(connection, user);
        assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
        assertThat(instance.canAuthenticate(), is(true));
        assertThat(instance.authenticate(), is(true));
        assertThat(instance.isAuthenticated(), is(true));
    }

    private Object createPasswordAuthenticatedSshServer() throws InvocationTargetException, NoSuchMethodException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        return createPasswordAuthenticatedSshServer(null);
    }

    private Object createPasswordAuthenticatedSshServer(final String username) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, ClassNotFoundException, InstantiationException {
        Object sshd = newDefaultSshServer();
        Class<?> keyPairProviderClass = newKeyPairProviderClass();
        Object provider = newProvider();
        Class<?> authenticatorClass = newAuthenticatorClass();
        Object authenticator = newAuthenticator(authenticatorClass, username);
        Object factory = newFactory();

        invoke(sshd, "setPort", new Class<?>[] {Integer.TYPE}, new Object[] {0});
        invoke(sshd, "setKeyPairProvider", new Class<?>[] {keyPairProviderClass}, new Object[] {provider});
        invoke(sshd, "setPasswordAuthenticator", new Class<?>[] {authenticatorClass}, new Object[] {authenticator});
        invoke(sshd, "setUserAuthFactories", new Class<?>[] {List.class}, new Object[] {Collections.singletonList(factory)});

        return sshd;
    }

    @Test
    public void testFactory() throws Exception {
        sshd = createPasswordAuthenticatedSshServer();
        invoke(sshd, "start", null, null);
        int port = (Integer)invoke(sshd, "getPort", null, null);
        connection = new Connection("localhost", port);
        connection.connect(new NoVerifier());
        SSHAuthenticator<Connection, StandardUsernamePasswordCredentials> instance = SSHAuthenticator.newInstance(connection, user);
        assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
        assertThat(instance.canAuthenticate(), is(true));
        assertThat(instance.authenticate(), is(true));
        assertThat(instance.isAuthenticated(), is(true));
    }

    @Test
    public void testFactoryAltUsername() throws Exception {
        sshd = createPasswordAuthenticatedSshServer("bill");
        invoke(sshd, "start", null, null);
        int port = (Integer)invoke(sshd, "getPort", null, null);
        connection = new Connection("localhost", port);
        connection.connect(new NoVerifier());
        SSHAuthenticator<Connection, StandardUsernamePasswordCredentials> instance = SSHAuthenticator.newInstance(connection, user, null);
        assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
        assertThat(instance.canAuthenticate(), is(true));
        assertThat(instance.authenticate(), is(false));
        assertThat(instance.isAuthenticated(), is(false));
        connection = new Connection("localhost", port);
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
        Object sshd = createPasswordAuthenticatedSshServer();
        invoke(sshd, "start", null, null);

        DumbSlave s = r.createSlave();
        Computer c = s.toComputer();
        assertNotNull(c);
        c.connect(false).get();

        final int port = (Integer)invoke(sshd, "getPort", null, null);

        TaskListener l = r.createTaskListener();
        VirtualChannel channel = c.getChannel();
        assertNotNull(channel);
        channel.call(new RemoteConnectionTest(port, user));
    }

    private static class NoVerifier implements ServerHostKeyVerifier {
        public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm,
                                           byte[] serverHostKey) {
            return true;
        }
    }

    private static final class RemoteConnectionTest extends MasterToSlaveCallable<Void, Exception> {
        private final int port;
        private final StandardUsernamePasswordCredentials user;

        public RemoteConnectionTest(int port, StandardUsernamePasswordCredentials user) {
            this.port = port;
            this.user = user;
        }

        public Void call() throws Exception {
            Connection connection = new Connection("localhost", port);
            connection.connect(new NoVerifier());
            SSHAuthenticator<Connection, StandardUsernamePasswordCredentials> instance = SSHAuthenticator.newInstance(connection,user);

            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            instance.authenticateOrFail();
            assertThat(instance.isAuthenticated(), is(true));
            connection.close();
            return null;
        }

        private static final long serialVersionUID = 1L;
    }

    private Object invoke(Object target, String methodName, Class<?>[] parameterTypes, Object[] args) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        return target.getClass().getMethod(methodName, parameterTypes).invoke(target, args);
    }

    private Object newDefaultSshServer() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Object server = null;
        Class<?> serverClass;
        try {
            serverClass = Class.forName("org.apache.sshd.SshServer");
        } catch (ClassNotFoundException e) {
            serverClass = Class.forName("org.apache.sshd.server.SshServer");
        }

        server = serverClass.getDeclaredMethod("setUpDefaultServer").invoke(null);
        assertNotNull(server);

        return server;
    }

    private Class<?> newKeyPairProviderClass() throws ClassNotFoundException {
        Class<?> keyPairProviderClass;
        try {
            keyPairProviderClass = Class.forName("org.apache.sshd.common.KeyPairProvider");
        } catch (ClassNotFoundException e) {
            keyPairProviderClass = Class.forName("org.apache.sshd.common.keyprovider.KeyPairProvider");
        }

        return keyPairProviderClass;
    }

    private Object newProvider() throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        Class<?> providerClass = Class.forName("org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider");
        Object provider = providerClass.getConstructor().newInstance();
        assertNotNull(provider);

        return provider;
    }

    private Class<?> newAuthenticatorClass() throws ClassNotFoundException {
        Class<?> authenticatorClass;
        try {
            authenticatorClass = Class.forName("org.apache.sshd.server.auth.password.PasswordAuthenticator");
        } catch(ClassNotFoundException e) {
            authenticatorClass = Class.forName("org.apache.sshd.server.PasswordAuthenticator");
        }

        return authenticatorClass;
    }

    private Object newAuthenticator(Class<?> authenticatorClass, final String userName) throws IllegalArgumentException {
        Object authenticator = Proxy.newProxyInstance(
                authenticatorClass.getClassLoader(), new Class<?>[]{authenticatorClass}, (proxy, method, args) ->
                        method.getName().equals("authenticate") ?
                                (userName == null || userName.equals(args[0])) && "foomanchu".equals(args[1]) :
                                null);
        assertNotNull(authenticator);
        return authenticator;
    }

    private Object newFactory() throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        Object factory = null;
        Class<?> factoryClass;
        try {
            factoryClass = Class.forName("org.apache.sshd.server.auth.UserAuthPassword$Factory");
        } catch (ClassNotFoundException e) {
            factoryClass = Class.forName("org.apache.sshd.server.auth.password.UserAuthPasswordFactory");
        }

        factory = factoryClass.getConstructor().newInstance();

        assertNotNull(factory);
        return factory;
    }
}
