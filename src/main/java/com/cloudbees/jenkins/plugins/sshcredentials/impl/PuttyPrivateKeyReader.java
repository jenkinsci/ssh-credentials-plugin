package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import hudson.util.Secret;
import org.jenkinsci.plugins.variant.OptionalExtension;
import org.kohsuke.putty.PuTTYKey;

import java.io.IOException;
import java.io.StringReader;

@OptionalExtension(requirePlugins = {"trilead-api"})
public class PuttyPrivateKeyReader implements SSHUserPrivateKey.PrivateKeyReader {

    @Override
    public boolean accept(String privateKey) throws IOException {
        return PuTTYKey.isPuTTYKeyFile(new StringReader(privateKey));
    }

    @Override
    public String toOpenSSH(String privateKey, Secret passphrase) throws IOException {
        // strictly we should be encrypting the openssh version with the passphrase, but
        // if the key we pass back does not have a passphrase, then the passphrase will not be
        // checked, so not an issue.
        return new PuTTYKey(new StringReader(privateKey),
                passphrase == null ? "" : passphrase.getPlainText())
                .toOpenSSH();
    }
}
