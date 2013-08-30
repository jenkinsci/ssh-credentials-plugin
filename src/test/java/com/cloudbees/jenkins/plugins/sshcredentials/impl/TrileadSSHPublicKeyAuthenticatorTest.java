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
import com.trilead.ssh2.Connection;
import com.trilead.ssh2.ServerHostKeyVerifier;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.jvnet.hudson.test.HudsonTestCase;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TrileadSSHPublicKeyAuthenticatorTest extends HudsonTestCase {

    private Connection connection;
    private SSHUserPrivateKey user;

    @Override
    protected void tearDown() throws Exception {
        if (connection != null) {
            connection.close();
            connection = null;
        }
        super.tearDown();
    }

    protected void setUp() throws Exception {
        super.setUp();
        user = new SSHUserPrivateKey() {

            @NonNull
            public String getUsername() {
                return "foobar";
            }

            @NonNull
            public String getDescription() {
                return "";
            }

            public String getId() {
                return "";
            }

            public CredentialsScope getScope() {
                return CredentialsScope.SYSTEM;
            }

            @NonNull
            public CredentialsDescriptor getDescriptor() {
                return new CredentialsDescriptor() {
                    @Override
                    public String getDisplayName() {
                        return "";
                    }
                };
            }

            @NonNull
            public String getPrivateKey() {
                // just want a valid key... I generated this and have thrown it away (other than here)
                // do not use other than in this test
                return "-----BEGIN RSA PRIVATE KEY-----\n"
                        + "MIICWQIBAAKBgQDADDwooNPJNQB4N4bJPiBgq/rkWKMABApX0w4trSkkX5q+l+CL\n"
                        + "CuddGGAsAu6XPari8v49ipbBmHqRLP9+X3ARGWKU2gDvGTBr99/ReUl2YgVjCwy+\n"
                        + "KMrGCN7SNTgRo6StwVaPhh6pUpNTQciDe/kOwUnQFWSM6/lwkOD1Uod45wIBIwKB\n"
                        + "gHi3O8HELVnmzRhdaqphkLHLL/0/B18Ye4epPBy1/JqFPLJQ1kjFBnUIAe/HVCSN\n"
                        + "KZX30wIcmUZ9GdeYoJiTwsfTy9t2KwHjqrapTfiekVZAW+3iDBqRZMxQ5MoK7b6g\n"
                        + "w5HrrtrtPfYuAsBnYjIS6qsKAVT3vdolJ5eai/RlPO4LAkEA76YuUozC/dW7Ox+R\n"
                        + "1Njd6cWJsRVXGemkSYY/rSh0SbfHAebqL/bDg8xXim9UiuD9Hc6md3glHQj6iKvl\n"
                        + "BxWq4QJBAM0moKiM16WFSFJP1wVDj0Bnx6DkJYSpf5u+C0ghBVoqIYKq6/P/gRE2\n"
                        + "+ColsLu6AYftaEJVpAgxeTU/IsGoJMcCQHRmqMkCipiMYkFJ2R49cxnGWNJa0ojt\n"
                        + "03QrQ3/9tNNZQ2dS5sbW8UAEKoURgNW9vMVVvpHMpE/uaw8u65W6ESsCQDTAyjn4\n"
                        + "VLWIrDJsTTveLCaBFhNt3cMHA45ysnGiF1GzD+5mdzAdITBP9qvAjIgLQjjlRrH4\n"
                        + "w8eXsXQXjJgyjR0CQHfvhiMPG5pWwmXpsEOFo6GKSvOC/5sNEcnddenuO/2T7WWi\n"
                        + "o1LQh9naeuX8gti0vNR8+KtMEaIcJJeWnk56AVY=\n"
                        + "-----END RSA PRIVATE KEY-----\n";
            }

            @CheckForNull
            public Secret getPassphrase() {
                return null;
            }

            @NonNull
            public List<String> getPrivateKeys() {
                return Collections.singletonList(getPrivateKey());
            }
        };
    }

    public void testAuthenticate() throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                return username.equals("foobar");
            }
        });
        sshd.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthPublicKey.Factory()));
        try {
            sshd.start();
            connection = new Connection("localhost", sshd.getPort());
            connection.connect(new ServerHostKeyVerifier() {
                public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm,
                                                   byte[] serverHostKey)
                        throws Exception {
                    return true;
                }
            });
            TrileadSSHPublicKeyAuthenticator instance =
                    new TrileadSSHPublicKeyAuthenticator(connection, user);
            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(true));
            assertThat(instance.isAuthenticated(), is(true));
        } finally {
            try {
                sshd.stop(true);
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
        }
    }

    public void testFactory() throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                return username.equals("foobar");
            }
        });
        sshd.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthPublicKey.Factory()));
        try {
            sshd.start();
            connection = new Connection("localhost", sshd.getPort());
            connection.connect(new ServerHostKeyVerifier() {
                public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm,
                                                   byte[] serverHostKey)
                        throws Exception {
                    return true;
                }
            });
            SSHAuthenticator instance = SSHAuthenticator.newInstance(connection, user);
            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(true));
            assertThat(instance.isAuthenticated(), is(true));
        } finally {
            try {
                sshd.stop(true);
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
        }
    }

    public void testAltUsername() throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                return username.equals("bill");
            }
        });
        sshd.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthPublicKey.Factory()));
        try {
            sshd.start();
            connection = new Connection("localhost", sshd.getPort());
            connection.connect(new ServerHostKeyVerifier() {
                public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm,
                                                   byte[] serverHostKey)
                        throws Exception {
                    return true;
                }
            });
            SSHAuthenticator instance = SSHAuthenticator.newInstance(connection, user, null);
            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(false));
            assertThat(instance.isAuthenticated(), is(false));
            connection = new Connection("localhost", sshd.getPort());
            connection.connect(new ServerHostKeyVerifier() {
                public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm,
                                                   byte[] serverHostKey)
                        throws Exception {
                    return true;
                }
            });
            instance = SSHAuthenticator.newInstance(connection, user, "bill");
            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(true));
            assertThat(instance.isAuthenticated(), is(true));
        } finally {
            try {
                sshd.stop(true);
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
        }
    }
}
