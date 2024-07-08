package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.domains.Domain;
import hudson.security.ACL;
import jenkins.security.FIPS140;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Iterator;

import static org.junit.Assert.*;

public class BasicSSHUserPrivateKeyFIPSTest {

    @ClassRule
    public static FlagRule<String> fipsFlag = FlagRule.systemProperty(FIPS140.class.getName() + ".COMPLIANCE", "true");

    @Rule public JenkinsRule r = new JenkinsRule();

    @BeforeClass
    public static void ensureBCIsAvailable() {
        // Tests running without jenkins need the provider
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    @Test
    @Issue("JENKINS-73408")
    @WithoutJenkins
    public void nonCompliantKeysLaunchExceptionTest() throws IOException {
        assertThrows(IllegalArgumentException.class, () -> new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "rsa512", "user",
                getKey("rsa512"), "password", "Invalid size key"));
        assertThrows(IllegalArgumentException.class, () -> new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "openssh-rsa1024", "user",
                getKey("openssh-rsa1024"), "password", "Invalid key format"));
        new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "ed25519", "user",
                getKey("ed25519"), "password", "Elliptic curve accepted key");
        new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "rsa1024", "user",
                getKey("rsa1024"), "password", "RSA 1024 accepted key");
        new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "unencrypted-rsa1024", "user",
                getKey("unencrypted-rsa1024"), null, "RSA 1024 with no encryption accepted key");
        assertThrows(IllegalArgumentException.class, () -> new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "rsa1024", "user",
                getKey("rsa1024"), "NOT-password", "Wrong password avoids getting size or algorithm"));
        assertThrows(IllegalArgumentException.class, () -> new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "dsa2048", "user",
                getKey("dsa2048"), null, "DSA is not accepted"));
    }

    @Test
    @Issue("JENKINS-73408")
    public void invalidKeyIsNotSavedInFIPSModeTest() throws IOException {
        BasicSSHUserPrivateKey entry = new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "rsa1024", "user", getKey("rsa1024"), "password", "RSA 1024 accepted key");
        Iterator<CredentialsStore> stores = CredentialsProvider.lookupStores(r.jenkins).iterator();
        assertTrue(stores.hasNext());
        CredentialsStore store = stores.next();
        store.addCredentials(Domain.global(), entry);
        store.save();
        // Valid key is saved
        SSHUserPrivateKey cred = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentialsInItem(SSHUserPrivateKey.class, null, ACL.SYSTEM2),
                CredentialsMatchers.withId("rsa1024"));
        assertNotNull(cred);
        assertThrows(IllegalArgumentException.class, () -> store.addCredentials(Domain.global(),
                new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "rsa512", "user", getKey("rsa512"), "password", "Invalid size key")));
        store.save();
        // Invalid key threw an exception, so it wasn't saved
        cred = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentialsInItem(SSHUserPrivateKey.class, null, ACL.SYSTEM2),
                CredentialsMatchers.withId("rsa512"));
        assertNull(cred);
    }

    @Test
    @LocalData
    @Issue("JENKINS-73408")
    public void invalidKeysAreRemovedOnStartupTest() {
        SSHUserPrivateKey cred = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentialsInItem(SSHUserPrivateKey.class, null, ACL.SYSTEM2),
                CredentialsMatchers.withId("valid-rsa-key"));
        assertNotNull(cred);
        cred = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentialsInItem(SSHUserPrivateKey.class, null, ACL.SYSTEM2),
                CredentialsMatchers.withId("invalid-rsa-key"));
        assertNull(cred);
    }

    private BasicSSHUserPrivateKey.DirectEntryPrivateKeySource getKey(String file) throws IOException {
        String keyText = FileUtils.readFileToString(Paths.get("src/test/resources/com/cloudbees/jenkins/plugins/sshcredentials/impl/BasicSSHUserPrivateKeyFIPSTest/nonCompliantKeysLaunchExceptionTest").resolve(file).toFile(), Charset.defaultCharset());
        return new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(keyText);
    }
}
