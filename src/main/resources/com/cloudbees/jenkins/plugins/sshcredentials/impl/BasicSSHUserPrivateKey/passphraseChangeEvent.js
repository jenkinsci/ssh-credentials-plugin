var passphraseElement = document.getElementById('privateKeyPassphrase');
var privateKeyElement = document.getElementById('privateKey');

passphraseElement.addEventListener("change", event => {
  var newEvent = new Event("change")
  privateKeyElement.dispatchEvent(newEvent)
})