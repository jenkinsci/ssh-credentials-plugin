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
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.trilead.ssh2.Connection;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.lang.reflect.InvocationTargetException;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.reflect.Proxy.*;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@WithJenkins
class TrileadSSHPublicKeyAuthenticatorTest {

    private Connection connection;
    private SSHUserPrivateKey user;

    private JenkinsRule r;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        r = rule;

        user = new SSHUserPrivateKey() {

            @NonNull
            public String getUsername() {
                return "foobar";
            }

            @NonNull
            public String getDescription() {
                return "";
            }

            @NonNull
            public String getId() {
                return "";
            }

            public CredentialsScope getScope() {
                return CredentialsScope.SYSTEM;
            }

            @NonNull
            public CredentialsDescriptor getDescriptor() {
                return new CredentialsDescriptor() {
                    @NonNull
                    @Override
                    public String getDisplayName() {
                        return "";
                    }
                };
            }

            @CheckForNull
            public Secret getPassphrase() {
                return null;
            }

            @NonNull
            public List<String> getPrivateKeys() {
                // just want a valid key... I generated this and have thrown it away (other than here)
                // do not use other than in this test
                return List.of("""
                        -----BEGIN RSA PRIVATE KEY-----
                        MIICWQIBAAKBgQDADDwooNPJNQB4N4bJPiBgq/rkWKMABApX0w4trSkkX5q+l+CL
                        CuddGGAsAu6XPari8v49ipbBmHqRLP9+X3ARGWKU2gDvGTBr99/ReUl2YgVjCwy+
                        KMrGCN7SNTgRo6StwVaPhh6pUpNTQciDe/kOwUnQFWSM6/lwkOD1Uod45wIBIwKB
                        gHi3O8HELVnmzRhdaqphkLHLL/0/B18Ye4epPBy1/JqFPLJQ1kjFBnUIAe/HVCSN
                        KZX30wIcmUZ9GdeYoJiTwsfTy9t2KwHjqrapTfiekVZAW+3iDBqRZMxQ5MoK7b6g
                        w5HrrtrtPfYuAsBnYjIS6qsKAVT3vdolJ5eai/RlPO4LAkEA76YuUozC/dW7Ox+R
                        1Njd6cWJsRVXGemkSYY/rSh0SbfHAebqL/bDg8xXim9UiuD9Hc6md3glHQj6iKvl
                        BxWq4QJBAM0moKiM16WFSFJP1wVDj0Bnx6DkJYSpf5u+C0ghBVoqIYKq6/P/gRE2
                        +ColsLu6AYftaEJVpAgxeTU/IsGoJMcCQHRmqMkCipiMYkFJ2R49cxnGWNJa0ojt
                        03QrQ3/9tNNZQ2dS5sbW8UAEKoURgNW9vMVVvpHMpE/uaw8u65W6ESsCQDTAyjn4
                        VLWIrDJsTTveLCaBFhNt3cMHA45ysnGiF1GzD+5mdzAdITBP9qvAjIgLQjjlRrH4
                        w8eXsXQXjJgyjR0CQHfvhiMPG5pWwmXpsEOFo6GKSvOC/5sNEcnddenuO/2T7WWi
                        o1LQh9naeuX8gti0vNR8+KtMEaIcJJeWnk56AVY=
                        -----END RSA PRIVATE KEY-----
                        """);
            }
        };
    }

    @AfterEach
    void tearDown() {
        if (connection != null) {
            connection.close();
            connection = null;
        }
    }

    @Test
    void testAuthenticate() throws Exception {
        Object sshd = newDefaultSshServer();
        Class<?> keyPairProviderClass = newKeyPairProviderClass();
        Object provider = newProvider();
        Class<?> authenticatorClass = newAuthenticatorClass();
        Object authenticator = newAuthenticator(authenticatorClass, "foobar");
        Object factory = newFactory();
        assertNotNull(factory);

        invoke(sshd, "setPort", new Class<?>[] {Integer.TYPE}, new Object[] {0});
        invoke(sshd, "setKeyPairProvider", new Class<?>[] {keyPairProviderClass}, new Object[] {provider});
        invoke(sshd, "setPublickeyAuthenticator", new Class<?>[] {authenticatorClass}, new Object[] {authenticator});
        invoke(sshd, "setUserAuthFactories", new Class<?>[] {List.class}, new Object[] {Collections.singletonList(factory)});

        try {
            invoke(sshd, "start", null, null);
            int port = (Integer)invoke(sshd, "getPort", null, null);
            connection = new Connection("localhost", port);
            connection.connect((hostname, port1, serverHostKeyAlgorithm, serverHostKey) -> true);
            TrileadSSHPublicKeyAuthenticator instance =
                    new TrileadSSHPublicKeyAuthenticator(connection, user);
            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(true));
            assertThat(instance.isAuthenticated(), is(true));
        } finally {
            try {
                invoke(sshd, "stop", new Class<?>[] {Boolean.TYPE}, new Object[] {true});
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
        }
    }

    @Test
    void testFactory() throws Exception {
        Object sshd = newDefaultSshServer();
        Class<?> keyPairProviderClass = newKeyPairProviderClass();
        Object provider = newProvider();
        Class<?> authenticatorClass = newAuthenticatorClass();
        Object authenticator = newAuthenticator(authenticatorClass, "foobar");
        Object factory = newFactory();
        assertNotNull(factory);

        invoke(sshd, "setPort", new Class<?>[] {Integer.TYPE}, new Object[] {0});
        invoke(sshd, "setKeyPairProvider", new Class<?>[] {keyPairProviderClass}, new Object[] {provider});
        invoke(sshd, "setPublickeyAuthenticator", new Class<?>[] {authenticatorClass}, new Object[] {authenticator});
        invoke(sshd, "setUserAuthFactories", new Class<?>[] {List.class}, new Object[] {Collections.singletonList(factory)});
        try {
            invoke(sshd, "start", null, null);
            int port = (Integer)invoke(sshd, "getPort", null, null);
            connection = new Connection("localhost", port);
            connection.connect((hostname, port1, serverHostKeyAlgorithm, serverHostKey) -> true);
            SSHAuthenticator<Object, StandardUsernameCredentials> instance = SSHAuthenticator.newInstance(connection, user);
            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(true));
            assertThat(instance.isAuthenticated(), is(true));
        } finally {
            try {
                invoke(sshd, "stop", new Class<?>[] {Boolean.TYPE}, new Object[] {true});
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
        }
    }

    @Test
    void testAltUsername() throws Exception {
        Object sshd = newDefaultSshServer();
        Class<?> keyPairProviderClass = newKeyPairProviderClass();
        Object provider = newProvider();
        Class<?> authenticatorClass = newAuthenticatorClass();
        Object authenticator = newAuthenticator(authenticatorClass, "bill");
        Object factory = newFactory();

        invoke(sshd, "setPort", new Class<?>[] {Integer.TYPE}, new Object[] {0});
        invoke(sshd, "setKeyPairProvider", new Class<?>[] {keyPairProviderClass}, new Object[] {provider});
        invoke(sshd, "setPublickeyAuthenticator", new Class<?>[] {authenticatorClass}, new Object[] {authenticator});
        invoke(sshd, "setUserAuthFactories", new Class<?>[] {List.class}, new Object[] {Collections.singletonList(factory)});
        try {
            invoke(sshd, "start", null, null);
            int port = (Integer)invoke(sshd, "getPort", null, null);
            connection = new Connection("localhost", port);
            connection.connect((hostname, port12, serverHostKeyAlgorithm, serverHostKey) -> true);
            SSHAuthenticator<Connection, SSHUserPrivateKey> instance = SSHAuthenticator.newInstance(connection, user, null);
            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(false));
            assertThat(instance.isAuthenticated(), is(false));
            connection = new Connection("localhost", port);
            connection.connect((hostname, port1, serverHostKeyAlgorithm, serverHostKey) -> true);
            instance = SSHAuthenticator.newInstance(connection, user, "bill");
            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(true));
            assertThat(instance.isAuthenticated(), is(true));
        } finally {
            try {
                invoke(sshd, "stop", new Class<?>[] {Boolean.TYPE}, new Object[] {true});
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
        }
    }

    private Object invoke(Object target, String methodName, Class<?>[] parameterTypes, Object[] args) throws Exception {
        return target.getClass().getMethod(methodName, parameterTypes).invoke(target, args);
    }

    private Object newDefaultSshServer() throws Exception {
        Object sshd;
        Class<?> sshdClass;
        try {
            sshdClass = Class.forName("org.apache.sshd.SshServer");
        } catch (ClassNotFoundException e) {
            sshdClass = Class.forName("org.apache.sshd.server.SshServer");
        }

        sshd = sshdClass.getDeclaredMethod("setUpDefaultServer").invoke(null);
        assertNotNull(sshd);

        return sshd;
    }

    private Class<?> newKeyPairProviderClass() throws Exception {
        Class<?> keyPairProviderClass;
        try {
            keyPairProviderClass = Class.forName("org.apache.sshd.common.KeyPairProvider");
        } catch (ClassNotFoundException e) {
            keyPairProviderClass = Class.forName("org.apache.sshd.common.keyprovider.KeyPairProvider");
        }

        return keyPairProviderClass;
    }

    private Object newProvider() throws Exception {
        Class<?> providerClass = Class.forName("org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider");
        Object provider = providerClass.getConstructor().newInstance();
        assertNotNull(provider);

        return provider;
    }

    private Class<?> newAuthenticatorClass() throws Exception {
        Class<?> authenticatorClass;
        try {
            authenticatorClass = Class.forName("org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator");
        } catch(ClassNotFoundException e) {
            authenticatorClass = Class.forName("org.apache.sshd.server.PublickeyAuthenticator");
        }

        return authenticatorClass;
    }

    private Object newAuthenticator(Class<?> authenticatorClass, final String userName) {
        Object authenticator = newProxyInstance(
                authenticatorClass.getClassLoader(), new Class<?>[]{authenticatorClass},
                (proxy, method, args) -> method.getName().equals("authenticate") ? userName.equals(args[0]) : null);
        assertNotNull(authenticator);
        return authenticator;
    }

    private Object newFactory() throws Exception {
        Object factory;
        Class<?> factoryClass;
        try {
            factoryClass = Class.forName("org.apache.sshd.server.auth.UserAuthPublicKey$Factory");
        } catch (ClassNotFoundException e) {
            factoryClass = Class.forName("org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory");
        }

        factory = factoryClass.getConstructor().newInstance();

        assertNotNull(factory);
        return factory;
    }
}
