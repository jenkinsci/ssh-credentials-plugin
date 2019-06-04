package com.cloudbees.jenkins.plugins.sshcredentials.jcasc;

import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import io.jenkins.plugins.casc.misc.ExportImportRoundTripAbstractTest;
import jenkins.model.Jenkins;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class ExportImportRoundTripCasCSSHCredentialsTest extends ExportImportRoundTripAbstractTest {
    @Override
    public void assertConfiguredAsExpected(RestartableJenkinsRule restartableJenkinsRule, String s) {
        List<StandardUsernamePasswordCredentials> creds = CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, Jenkins.getInstanceOrNull(), null, Collections.emptyList());
        assertEquals(1, creds.size());
        StandardUsernamePasswordCredentials cred = creds.get(0);
        assertEquals("userid", cred.getId());
        assertEquals("username-of-userid", cred.getUsername());
        assertEquals("password-of-userid", cred.getPassword().getPlainText());

        List<BasicSSHUserPrivateKey> creds2 = CredentialsProvider.lookupCredentials(BasicSSHUserPrivateKey.class,Jenkins.getInstanceOrNull(), null, Collections.emptyList());
        assertEquals(1, creds2.size());
        BasicSSHUserPrivateKey cred2 = creds2.get(0);
        assertEquals("userid2", cred2.getId());
        assertEquals("username-of-userid2", cred2.getUsername());
        assertEquals("passphrase-of-userid2", cred2.getPassphrase().getPlainText());
        assertEquals("the description of userid2", cred2.getDescription());
        assertEquals(1, cred2.getPrivateKeySource().getPrivateKeys().size());
        String directKey = cred2.getPrivateKeySource().getPrivateKeys().get(0);
        assertEquals("sp0ds9d+skkfjf", directKey);
    }

    @Override
    public String stringInLogExpected() {
        return "passphrase = passphrase-of-userid2";
    }
}
