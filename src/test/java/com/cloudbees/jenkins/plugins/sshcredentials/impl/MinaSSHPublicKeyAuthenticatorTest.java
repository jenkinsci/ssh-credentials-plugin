package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticator;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class MinaSSHPublicKeyAuthenticatorTest {
    
    private static final Logger LOGGER = Logger.getLogger(MinaSSHPublicKeyAuthenticatorTest.class.getName());

    private SshServer sshd;

    @Rule
    public JenkinsRule r = new JenkinsRule();

    private final SSHUserPrivateKey user = new SSHUserPrivateKey() {

        @NonNull
        public String getUsername() {
            return "foomanchu";
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
                @Override
                @NonNull
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


    private final SSHUserPrivateKey userWithPassphrase = new SSHUserPrivateKey() {

        @NonNull
        public String getUsername() {
            return "foomanchu";
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
                @Override
                @NonNull
                public String getDisplayName() {
                    return "";
                }
            };
        }

        @NonNull
        public String getPrivateKey() {
            // just want a valid key... I generated this and have thrown it away (other than here)
            // do not use other than in this test
            return "-----BEGIN RSA PRIVATE KEY-----\n" +
                "Proc-Type: 4,ENCRYPTED\n" +
                "DEK-Info: AES-128-CBC,3D392A6AD3BB4B6F6931E8B6AFAC44C3\n" +
                "\n" +
                "eKjTixX+AoVPmfWz0MCQwmu9ZCcunXu3Ks+l7E7j4W6O1tI+5Xxo19jyFyVHKcSP\n" +
                "dgxTvko3V9E3fyG120C6fqkdFijp//s/RwzafGh1rDf7l4W2DBX5euyaE+mQG9PV\n" +
                "LStH4AEPSVnGiBmp1Faz/Xcj5NMCwZxOo0cImJQL3tnm8X8pQaPJknWmJea+Tsu/\n" +
                "+Y82ysygXSvX7phoYSEIg63VGxbhGLFNNptRdNOi4RfE/dP0/WJZo+xyNCMOclSH\n" +
                "fkXZ6ZGZTDnQ7v3gVw91v0t7eDpPjkdFI8OqwZhnTOxZh9d4xtuqdrbPlEgO2Dxa\n" +
                "Mn7sgSfFipRyGgyancylIFVJzOpr4Hp/9Xndm6oSyoeUrp2tbJ2CBIC1hYFIMrYS\n" +
                "Kzj9PAvz4l6elHVQ3dJS5LnNRNrYZf2yNCKJB3u1YSUGYDO4wNmSEL+MxjhMqyAg\n" +
                "avPbxGNJMgXHCcMqXjcWtTW3XAEvyl6sTNRu210exv1xeWePICaCi0/EPbvE6Ttv\n" +
                "w8ARLIJr6J3EkaIqt/mhckfjRAS4iNC0xmqAgnxJwrCulKA6JkXtWtXmLvCAau9q\n" +
                "ukEWbqV6fXnTrALYXTu0mBw8jylBDK1RWQ++GfyPOsUPqvwGK6o3YQLoQIoFxEBP\n" +
                "k+tgWVtgC6PxbAQSBOrfgPhYNQJVkdLZv6/dLxhuyww1XhBL3r2k7ydJvFmNKDyG\n" +
                "7Tg6dClgMSSDr9+fszxSQO8e/MhigZlA3ajFStihH3E0PbSDspL+Vwo3jYxeaU3Z\n" +
                "9fVS+uqzRO+bfAo6n/7lncg1os48HHUruAvtwKdbTXJabONdpxhY+r+GjeohABhz\n" +
                "X73sld0u9XgsUgZtC7TEB8mrNFXrSkn6e3oSskjNT8ETISuYX5e9/AaRXzgSqUqw\n" +
                "RUWZz2VrKuVtPycnSo3ITTe4m4SHJ7xrK0SrMZ5Rawlhpcu7TZF4LPqMdAzN+2XS\n" +
                "6CDl9lDq6yI608/cpVwRj+FG6gYGd5fCQCfRukBj+GjAMJ4rtLcebxNh7zqoxflo\n" +
                "1Swgcg2t0/A7xvgV/CX1dNg3NE2DTnVh72gkATQKj5TsoVRR2CndlF+b9ljljTMW\n" +
                "YiM0AknwBYZm3KEuHBynzNxHUhk6Dbe8wWv2wAxF/eOnGGtlFiFHz3gDE2OJy4xJ\n" +
                "HhP6mAQ1UU6N0JxCPRvywiTfpiAFfO5C/xCKC0rlXgE7EY/wxW+5NnWPiRdNxetD\n" +
                "oti8ydeOFbR1mLUUT7Ug6H53Rm9ZcEnMVXjrtqQLU7o/j63vbO5uO4MkOUkxRvBV\n" +
                "ETgAY68uE6+aPVqasifvJT6k/3VvsIfmv38cbW73EqB6JvRsZVLmij83Zosoa2PD\n" +
                "8XP27OjWPabwRLdBuji2uGpK27AcfD4C0ehL+v+WHzU6bQFTp/D2nq4gziojSaej\n" +
                "uM98tUXrcxSrnNd24CqC1vzy5kj8Bq+h3akltiV/eG7QEtDaZAheWSLSiZJE+T/H\n" +
                "WWXczswVkc24Po3gBcn8bx+zhnqekYgOithEPdNPI1HQA5LrT34549gp+aYy+vkE\n" +
                "ZNjVeV74Ok84l2cjLm8k6MwdIdtDt9EvT6xxWJi8GGRtR2bJnZSByEuzB5GT7Z3s\n" +
                "dPENV3cCsQsEzO6tHgCvSvfuIkqdWMzo8GOloHTYm23ihfTYUyYldMuDYHF1MC1F\n" +
                "te8B6rVghhmXEG6YaiUo3BRIE9ye1M1f/lpiJ4pit22Od7FBiKx5PMjDF8+ITzeO\n" +
                "mJ7OtBG/0f/+o76fjbZQXFsgRbHSMWgvdhHNb6iM87tNmZJpdZSfY2lu1Aszsw/t\n" +
                "neuuGAVJ9sRpck2PGionEYRaGCNK7ajNZJBVEZn/zyp44iKEWvSyeuTHrmt7xFGB\n" +
                "jNIHiqAaFOli/YCTuXtaVYuIqnp1e27USKiHFj/ijG0bbQCT2bur9REA7x/ug/zL\n" +
                "S9HPsS6VhioqJsamG6xpl51h9NLaO2lNyrmByapVtCg/R2WZ2t80fDuNifT1+ONk\n" +
                "Tlufz0hF2GQpb0qst7YZImcs0y1/r4GIOTvnaPhEjfv4ymi1bKNvQennwed4Eu2A\n" +
                "UXcF35Bblwilz3xunPbSdNMPW4UIc+GixY8RNDB9i9nMqPhlXW059c+RNHITE/WX\n" +
                "+EIMgUYKMg8suxlQzMLl2kSWJjUyeC5VUIIt09a6Vnj9OWrPDeTnhYHjvrKdIPMY\n" +
                "QfwaWLuUZozKyJbRsPeeEVXveEOEH4m3zpfyIC6Wv5OXBM2Ysdys3DzAJUgO/NXh\n" +
                "vHZprKnJlFTitUO3ySuw/q4lJFCt8VsMXceEoNzOspCwhtCiN0miXbA9D1biLAqR\n" +
                "+CDpQnpTUlJW6nDRGb/y3CmEjW37/DXr5CcaQ8ADkAVeaZMypFF6T2TWEar59SYP\n" +
                "-----END RSA PRIVATE KEY-----\n";
        }

        @CheckForNull
        public Secret getPassphrase() {
            return Secret.fromString("passphrase");
        }

        @NonNull
        public List<String> getPrivateKeys() {
            return Collections.singletonList(getPrivateKey());
        }
    };

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
        sshd.setPublickeyAuthenticator((s, publicKey, serverSession) -> user.getUsername().equals(s));
        sshd.setUserAuthFactories(Collections.singletonList(new UserAuthPublicKeyFactory()));
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
                .getSession()) {

                MinaSSHPublicKeyAuthenticator instance = new MinaSSHPublicKeyAuthenticator(connection, user);
                assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
                assertThat(instance.canAuthenticate(), is(true));
                assertThat(instance.authenticate(), is(true));
                assertThat(instance.isAuthenticated(), is(true));
            }
        }
    }

    @Test
    public void testAuthenticateWithPassphrase() throws Exception {
        try (SshClient sshClient = SshClient.setUpDefaultClient()) {
            sshClient.start();
            try (ClientSession connection = sshClient
                .connect(userWithPassphrase.getUsername(), sshd.getHost(), sshd.getPort())
                .verify(15, TimeUnit.SECONDS)
                .getSession()) {

                MinaSSHPublicKeyAuthenticator instance = new MinaSSHPublicKeyAuthenticator(connection, userWithPassphrase);
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
                .verify(15, TimeUnit.SECONDS)
                .getSession()) {

                SSHAuthenticator<Object, StandardUsernameCredentials> instance = SSHAuthenticator.newInstance(connection, user);
                assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
                assertThat(instance.canAuthenticate(), is(true));
                assertThat(instance.authenticate(), is(true));
                assertThat(instance.isAuthenticated(), is(true));
            }

        }
    }

    @Test
    public void testFactoryWithPassphrase() throws Exception {
        try (SshClient sshClient = SshClient.setUpDefaultClient()) {
            sshClient.start();
            try (ClientSession connection = sshClient
                .connect(userWithPassphrase.getUsername(), sshd.getHost(), sshd.getPort())
                .verify(15, TimeUnit.SECONDS)
                .getSession()) {

                SSHAuthenticator<Object, StandardUsernameCredentials> instance = SSHAuthenticator.newInstance(connection, userWithPassphrase);
                assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
                assertThat(instance.canAuthenticate(), is(true));
                assertThat(instance.authenticate(), is(true));
                assertThat(instance.isAuthenticated(), is(true));
            }

        }
    }
}
