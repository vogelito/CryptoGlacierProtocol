const bip32 = require("ripple-bip32");
const bip39 = require("bip39");
const EthereumTx = require('ethereumjs-tx').Transaction
const { prompt } = require('enquirer');
const util = require('util');

/*
 * User sanity checking
 */
const glacier_questions = [
  "Are you running this on a computer WITHOUT a network connection of any kind?",
  "Have the wireless cards in this computer been physically removed?",
  "Are you running on battery power?",
  "Are you running on an operating system booted from a USB drive?",
  "Is your screen hidden from view of windows, cameras, and other people?",
  "Are smartphones and all other nearby devices turned off and in a Faraday bag?"
]

function checkGlacierReponse(response) {
  if(response["question"] == false) {
    console.log("\n Safety check failed. Exiting.")
    process.exit(1)
  }
}

async function safetyCheck() {
  for (i = 0; i < glacier_questions.length; i++) {
    const response = await prompt({
      type: 'confirm',
      name: 'question',
      message: glacier_questions[i]
    });
    checkGlacierReponse(response)
  }
  console.log("\n\nSafety checks completed")
}

/*
 * Write a QR code and then read it back to try and detect any tricksy malware tampering with it.
 *  name: <string> short description of the data
 *  filename: <string> filename for storing the QR code
 *  data: <string> the data to be encoded
 */
async function writeAndVerifyQRCode(name, filename, data) {
  const exec = util.promisify(require('child_process').exec);
  await exec("qrencode -s 5 -o {0} '{1}'".format(filename, data), { shell: true });
  const { stdout, stderr } = await exec("zbarimg --set '*.enable=0' --set 'qr.enable=1' --quiet --raw {0}".format(filename), { shell: true });
  if (stdout.trim() != data) {
    console.log("********************************************************************")
    console.log("WARNING: {0} QR code could not be verified properly. This could be a sign of a security breach.".format(name))
    console.log("********************************************************************")
    process.exit(1)
  }

  console.log("QR code for {0} written to {1}".format(name, filename))
}

/*
 * Simple String.format() in javascript
 * Source: https://coderwall.com/p/flonoa/simple-string-format-in-javascript
 */
String.prototype.format = function() {
  a = this;
  for (k in arguments) {
    a = a.replace("{" + k + "}", arguments[k])
  }
  return a
}

async function getMnemonic() {
  // Get the mnemonic and validate it
  console.log("\nYou will now need to enter your 24 mnemonic phrase word by word")
  while (true) {
    const response = await prompt({
      type: 'confirm',
      name: 'question',
      message: "Are you ready?"
    });
    if (response.question === true) break;
  }
  words = []
  // Array needs to be cloned or enquirer will mess with the reference of the array
  const choices = [...bip39.wordlists.english]
  for (i = 0; i < 24; i++) {
    const word = await prompt({
      type: 'autocomplete',
      name: 'word',
      message: 'Pick the next word:',
      choices: choices
    });
    words.push(word.word)
  }
  const mnemonic = words.join(' ')
  if (!bip39.validateMnemonic(mnemonic)) {
    console.log("\n\nExiting, mnemonic is invalid")
    process.exit(1)
  }

  return mnemonic
}

function write(file, text) {
  return new Promise((resolve, reject) => {
    fs.writeFile(file, text, err => {
      if (err) reject(err);
      else resolve();
    });
  });
}

async function setupEthereum(m, i, e) {
  const derivedPath = m.derivePath("m/44'/60'/0'/0/0")
  const keyPair = derivedPath.keyPair.getKeyPairs()
  const privateKey = Buffer.from(keyPair.privateKey.substring(2), "hex")

  // Build a new TX from user input
  const data = await prompt([{
    type: 'input',
    name: 'gasPrice',
    message: "What is the gas price (in GWei)?",
    result(answer) {
      return parseInt(parseFloat(answer.replace(/,/g, ''))*1000000000).toString(16);
    },
    validate(answer) {
      return !isNaN(answer);
    }
  }]);

  const txParams = {
    nonce: '0x00',
    gasPrice: '0x' + data.gasPrice,
    gasLimit: '0x5208',
    to: '0x0000000000000000000000000000000000000000',
    value: '0x00',
  }

  const tx = new EthereumTx(txParams)
  tx.sign(privateKey)
  const txToBroadcast = '0x' + tx.serialize().toString('hex')
  console.log(txToBroadcast)
  writeAndVerifyQRCode("Ether Nonce 0 Tx", "tx0.png", txToBroadcast)
}

(async() => {

  // Sanity checks
  await safetyCheck()

  var mnemonic = await getMnemonic()
  console.log("BIP39 Mnemonic:\t\t\t\t{0}".format(mnemonic))

  // Get the seed, derive the address and key pairs
  const seed = bip39.mnemonicToSeed(mnemonic)
  const m = bip32.fromSeedBuffer(seed)
  await setupEthereum(m)

})();
