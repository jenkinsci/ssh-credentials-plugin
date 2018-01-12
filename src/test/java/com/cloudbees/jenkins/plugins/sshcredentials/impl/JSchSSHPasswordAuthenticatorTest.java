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
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.List;
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
        Object sshd = newDefaultSshServer();
        Class keyPairProviderClass = newKeyPairProviderClass();
        Object provider = newProvider();
        Class authenticatorClass = newAuthenticatorClass();
        Object authenticator = newAuthenticator(authenticatorClass);
        Object factory = newFactory();

        invoke(sshd, "setPort", new Class[] {Integer.TYPE}, new Object[] {0});
        invoke(sshd, "setKeyPairProvider", new Class[] {keyPairProviderClass}, new Object[] {provider});
        invoke(sshd, "setPasswordAuthenticator", new Class[] {authenticatorClass}, new Object[] {authenticator});
        invoke(sshd, "setUserAuthFactories", new Class[] {List.class}, new Object[] {Arrays.asList(factory)});
        try {
            invoke(sshd, "start", null, null);
            int port = (Integer)invoke(sshd, "getPort", null, null);
            connector = new JSchConnector(user.getUsername(),"localhost", port);
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
                invoke(sshd, "stop", new Class[] {Boolean.TYPE}, new Object[] {true});
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
        }
    }

    @Test
    public void testFactory() throws Exception {
        Object sshd = newDefaultSshServer();
        Class keyPairProviderClass = newKeyPairProviderClass();
        Object provider = newProvider();
        Class authenticatorClass = newAuthenticatorClass();
        Object authenticator = newAuthenticator(authenticatorClass);
        Object factory = newFactory();

        invoke(sshd, "setPort", new Class[] {Integer.TYPE}, new Object[] {0});
        invoke(sshd, "setKeyPairProvider", new Class[] {keyPairProviderClass}, new Object[] {provider});
        invoke(sshd, "setPasswordAuthenticator", new Class[] {authenticatorClass}, new Object[] {authenticator});
        invoke(sshd, "setUserAuthFactories", new Class[] {List.class}, new Object[] {Arrays.asList(factory)});
        try {
            invoke(sshd, "start", null, null);
            int port = (Integer)invoke(sshd, "getPort", null, null);
            connector = new JSchConnector(user.getUsername(),"localhost", port);
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
                invoke(sshd, "stop", new Class[] {Boolean.TYPE}, new Object[] {true});
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



    private Object invoke(Object target, String methodName, Class[] parameterTypes, Object[] args) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        return target.getClass().getMethod(methodName, parameterTypes).invoke(target, args);
    }

    private Object newDefaultSshServer() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Object sshd = null;
        Class sshdClass;
        try {
            sshdClass = Class.forName("org.apache.sshd.SshServer");
        } catch (ClassNotFoundException e) {
            sshdClass = Class.forName("org.apache.sshd.server.SshServer");
        }

        sshd = sshdClass.getDeclaredMethod("setUpDefaultServer", null).invoke(null);
        assertNotNull(sshd);

        return sshd;
    }

    private Class newKeyPairProviderClass() throws ClassNotFoundException {
        Class keyPairProviderClass;
        try {
            keyPairProviderClass = Class.forName("org.apache.sshd.common.KeyPairProvider");
        } catch (ClassNotFoundException e) {
            keyPairProviderClass = Class.forName("org.apache.sshd.common.keyprovider.KeyPairProvider");
        }

        return keyPairProviderClass;
    }

    private Object newProvider() throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        Class providerClass = Class.forName("org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider");
        Object provider = providerClass.getConstructor().newInstance();
        assertNotNull(provider);

        return provider;
    }
    private Class newAuthenticatorClass() throws ClassNotFoundException {
        Class authenticatorClass;
        try {
            authenticatorClass = Class.forName("org.apache.sshd.server.auth.password.PasswordAuthenticator");
        } catch(ClassNotFoundException e) {
            authenticatorClass = Class.forName("org.apache.sshd.server.PasswordAuthenticator");
        }

        return authenticatorClass;
    }

    private Object newAuthenticator(Class authenticatorClass) throws ClassNotFoundException, IllegalArgumentException {
        Object authenticator = java.lang.reflect.Proxy.newProxyInstance(
                authenticatorClass.getClassLoader(),
                new java.lang.Class[]{authenticatorClass},
                new java.lang.reflect.InvocationHandler() {

                    @Override
                    public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) throws java.lang.Throwable {
                        if (method.getName().equals("authenticate")) {
                            return "foomanchu".equals(args[1]);
                        }

                        return null;
                    }
                });
        assertNotNull(authenticator);
        return authenticator;
    }

    private Object newFactory() throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        Object factory = null;
        Class factoryClass;
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
