//TODO: this snippet, as well as ids in passphrase and private key fields can be removed once https://issues.jenkins.io/browse/JENKINS-65616 is completed
var passphraseElement = document.getElementById('sshCredentials_passphrase');
var privateKeyElement = document.getElementById('sshCredentials_privateKey');

passphraseElement.addEventListener("change", event => {
    var newEvent = new Event("change")
    privateKeyElement.dispatchEvent(newEvent)
})