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
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.util.Iterator;

import static org.junit.Assert.*;

public class BasicSSHUserPrivateKeyFIPSTest {

    @ClassRule
    public static FlagRule<String> fipsFlag = FlagRule.systemProperty(FIPS140.class.getName() + ".COMPLIANCE", "true");

    @Rule public JenkinsRule r = new JenkinsRule();

    @Test
    @Issue("JENKINS-73408")
    public void nonCompliantKeysLaunchExceptionTest() throws IOException {
        new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "no-key", "user",
                null, null, "no key provided doesn't throw exceptions");
        assertThrows(IllegalArgumentException.class, () -> new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "nopass-openssh-ed25519", "user",
                getKey("openssh-ed25519-nopass"), null, "openssh ED25519 with no encryption is not compliant"));
        assertThrows(IllegalArgumentException.class, () -> new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "rsa1024", "user",
                getKey("rsa1024"), "fipsvalidpassword", "Invalid size key"));
        assertThrows(IllegalArgumentException.class, () -> new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "openssh-rsa1024", "user",
                getKey("openssh-rsa1024"), "fipsvalidpassword", "Invalid key format"));
        new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "ed25519", "user",
                getKey("ed25519"), "fipsvalidpassword", "Elliptic curve accepted key");
        new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "rsa2048", "user",
                getKey("rsa2048"), "fipsvalidpassword", "RSA 2048 accepted key");
        assertThrows(IllegalArgumentException.class, () -> new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "rsa1024-short-pass", "user",
                getKey("unencrypted-rsa1024"), "password", "password shorter than 14 chatacters is invalid"));
        new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "unencrypted-rsa2048", "user",
                getKey("unencrypted-rsa2048"), null, "RSA 2048 with no encryption is valid");
        assertThrows(IllegalArgumentException.class, () -> new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "rsa2048-wrong-pass", "user",
                getKey("rsa2048"), "NOT-fipsvalidpassword", "Wrong password avoids getting size or algorithm"));
        assertThrows(IllegalArgumentException.class, () -> new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "dsa2048", "user",
                getKey("dsa2048"), "fipsvalidpassword", "DSA is not accepted"));
        assertThrows(IllegalArgumentException.class, () -> new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "not-a-key", "user",
                getKey("not-a-key"), "fipsvalidpassword", "Provided data is not a key"));
    }

    @Test
    @Issue("JENKINS-73408")
    public void invalidKeyIsNotSavedInFIPSModeTest() throws IOException {
        BasicSSHUserPrivateKey entry = new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "rsa2048", "user", getKey("rsa2048"), "fipsvalidpassword", "RSA 1024 accepted key");
        Iterator<CredentialsStore> stores = CredentialsProvider.lookupStores(r.jenkins).iterator();
        assertTrue(stores.hasNext());
        CredentialsStore store = stores.next();
        store.addCredentials(Domain.global(), entry);
        store.save();
        // Valid key is saved
        SSHUserPrivateKey cred = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentialsInItem(SSHUserPrivateKey.class, null, ACL.SYSTEM2),
                CredentialsMatchers.withId("rsa2048"));
        assertNotNull(cred);
        assertThrows(IllegalArgumentException.class, () -> store.addCredentials(Domain.global(),
                new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "rsa1024", "user", getKey("rsa1024"), "fipsvalidpassword", "Invalid size key")));
        store.save();
        // Invalid key threw an exception, so it wasn't saved
        cred = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentialsInItem(SSHUserPrivateKey.class, null, ACL.SYSTEM2),
                CredentialsMatchers.withId("rsa1024"));
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
