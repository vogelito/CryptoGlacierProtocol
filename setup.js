const ArgumentParser = require('argparse').ArgumentParser;
const bip32 = require("ripple-bip32");
const bip39 = require("bip39");
const bitcoinjs = require('bitcoinjs-lib')
const clone = require('lodash.clonedeep')
const fs = require('fs');
const jswallet = require("ethereumjs-wallet");
const keypairs = require("ripple-keypairs");
const networks = bitcoinjs.networks
const { prompt } = require('enquirer');
const script = bitcoinjs.script
const sha256 = require('js-sha256');
const sign = require("ripple-sign-keypairs");
const util = require('util');
const WAValidator = require('wallet-address-validator');

//////////////////////////////////////////////////////////////////////////////////////////////////
//
// Ported from galcier protocol
// Source: https://github.com/GlacierProtocol/GlacierProtocol/blob/1c0c3f647441e144fd043466ebe0aee67342da08/glacierscript.py
//
//////////////////////////////////////////////////////////////////////////////////////////////////

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
 *  Reads random seed (of at least min_length hexadecimal characters) from standard input
 *    returns => string
 */
async function readRngSeedInteractive(minLength = 20) {
  var charLength = minLength * 2

  var seed = "";
  while (true) {
    const response = await prompt({
      type: 'input',
      name: 'seed',
      message: "Enter at least {0} characters of computer entropy. Spaces are OK, and will be ignored:".format(charLength)
    });
    seed = response.seed;
    seed = unchunk(seed);
    if (validateRngSeed(seed)) break;
  }
  return seed
}

/*
 *  Validates random hexadecimal seed
 *    returns => <boolean>
 */
function validateRngSeed(seed, minLength) {
  if (seed.length < minLength) {
    console.log("Error: Computer entropy must be at least {0} characters long".format(minLength))
    return false
  }

  if (seed.length % 2 != 0) {
    console.log("Error: Computer entropy must contain an even number of characters.")
    return false
  }

  if (!isHex(seed)) {
    console.log("Error: Illegal character. Computer entropy must be composed of hexadecimal characters only (0-9, a-f).")
    return false
  }

  return true
}

/*
 *  Reads and validates 62 dice rolls from standard input, as a string of consecutive integers
 *    Returns a string representing the dice rolls
 *    returns => <string>
 */
async function readDiceSeedInteractive(minLength = 62) {
  var dice = "";
  while (true) {
    const response = await prompt({
      type: 'input',
      name: 'dice',
      message: 'Enter {0} dice rolls (example: 62543 16325 21341...) Spaces are OK, and will be ignored:'.format(minLength)
    });
    dice = response.dice;
    dice = unchunk(dice);
    if (validateDiceSeed(dice, minLength)) break;
  }
  return dice
}

/*
 *  Validates dice data (i.e. ensures at least 62 digits between 1 and 6).
 *    returns => <boolean>
 */
function validateDiceSeed(dice, minLength) {
  if (dice.length < minLength) {
    console.log("Error: You must provide at least {0} dice rolls".format(minLength))
    return false;
  }

  for (const die of dice) {
    i = parseInt(die)
    if (i < 1 || i > 6 || isNaN(i)) {
      console.log("Error: Dice rolls must be between 1 and 6.")
      return false;
    }
  }
  return true;
}

/*
 *  Remove spaces in string
 */
function unchunk(string) {
    return string.replace(/ +/g, "");
}

/*
 * Splits a string into chunks of [length] characters, for easy human readability
 * Source: https://stackoverflow.com/a/7033662/5490854
 */
function chunkString(str, length) {
  return str.match(new RegExp('.{1,' + length + '}', 'g'));
}

/*
 *  A thin wrapper around the hashlib SHA256 library to provide a more functional interface
*/
function hashSHA256(s) {
  var m = sha256.create();
  m.update(s);
  return m.hex();
}

/*
 * Generate a random string for the user from /dev/random
 */
async function generateRngSeed(length = 20) {
  console.log("Making a random data string....")
  console.log("If strings don't appear right away, please continually move your mouse cursor. These movements generate entropy which is used to create random data.\n")

  const exec = util.promisify(require('child_process').exec);
  const { stdout, stderr } = await exec("xxd -l {0} -p /dev/random".format(length), { shell: true });
  var seed = stdout.replace('\n', '')

  return seed
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

  //console.log("QR code for {0} written to {1}".format(name, filename))
}

/*
 *  Return xor of two hex strings.
 *  An XOR of two pieces of data will be as random as the input with the most randomness.
 *  We can thus combine two entropy sources in this way as a safeguard against one source being
 *  compromised in some way.
 *  For details, see http://crypto.stackexchange.com/a/17660
 *
 *  returns => <string> in hex format
 *
 *  Source: https://stackoverflow.com/a/30651307/5490854
*/
function xorHexString(a, b) {
  if (a.length != b.length) {
    console.log("Exiting: tried to xor strings of unequal length")
    process.exit(1)
  }

  var res = "",
      i = a.length,
      j = b.length;
  while (i-->0 && j-->0)
      res = (parseInt(a.charAt(i), 16) ^ parseInt(b.charAt(j), 16)).toString(16) + res;
  return res;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//
// CryptoGlacierScript
//
//////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Check if a string is a valid hexadecimal number
 * Source: https://github.com/roryrjb/is-hex/blob/771446c62ab548cbed372c8bf8bb183c46bc2dc3/is-hex.js
 */
function isHex(h) {
  var hexRegEx = /([0-9]|[a-f])/gim
  return typeof h === 'string' &&
    (h.match(hexRegEx) || []).length === h.length
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

function isValidJson(str) {
    try {
        JSON.parse(str);
    } catch (e) {
        return false;
    }
    return true;
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

/*
 * With help from: https://gist.github.com/clarkmoody/0a788d2e012ffe339bb7d3873e47c081
 */
async function setupElectron(seed, initOrCheck) {
  networks.bitcoin.bip32.outputScript = (pubkey) => {
    return script.pubKeyHash.output.encode(
      bitcoinjs.crypto.hash160(pubkey))
  }
  networks.p2wsh = clone(networks.bitcoin)
  networks.p2wsh.bip32 = {
    public: 0x02aa7ed3,
    private: 0x02aa7a99,
    outputScript: (pubkey) => {
      return script.witnessPubKeyHash.output.encode(
        bitcoinjs.crypto.hash160(pubkey))
    }
  }

  await deriveElectronMasterPublicKey(networks.p2wsh, seed, "Bitcoin Master Public Key", "Zpub", "m/48'/0'/0'/2'", initOrCheck)
  await deriveElectronMasterPublicKey(networks.p2wsh, seed, "Litecoin Master Public Key", "Zpub", "m/48'/2'/0'/2'", initOrCheck)
  await deriveElectronMasterPublicKey(networks.bitcoin, seed, "BitcoinCash Master Public Key", "xpub", "m/44'/145'/0'", initOrCheck)
}

async function deriveElectronMasterPublicKey(network, seed, coin, type, path, i) {
  const rootNode = bitcoinjs.HDNode.fromSeedHex(seed, network)
  const accountNode = rootNode.derivePath(path)
  const pubkey = accountNode.derive(0).derive(0).getPublicKeyBuffer()
  const address = bitcoinjs.address.fromOutputScript(network.bip32.outputScript(pubkey))
  const masterPubkey = accountNode.neutered().toBase58()
  console.log("{0} ({1}):\t{2}".format(coin, type, masterPubkey))
  await writeAndVerifyQRCode(coin, "{0}.png".format(coin.replace(/\s+/g, '_').toLowerCase()), masterPubkey)
}

async function setupEthereum(m, i, e) {
  const derivedPath = m.derivePath("m/44'/60'/0'/0/0")
  const keyPair = derivedPath.keyPair.getKeyPairs()
  const privateKey = keyPair.privateKey.substring(2)
  const wallet = jswallet.fromPrivateKey(Buffer.from(privateKey, "hex"));

  const js = wallet.toV3("cryptoglacier")
  await write("ethereum.json", JSON.stringify(js, null, 4));
  const address = "0x" + js.address
  await writeAndVerifyQRCode("ethereum", "ethereum_address.png", address)
  // Only print the ethereum address and private key on init
  if (i) {
    console.log("Ethereum Address:\t\t\t" + address)
    console.log("Ethereum Private Key:\t\t\t0x" + privateKey)
  }

  if (e) {
    const confirmAddress = await prompt({
      type: 'confirm',
      name: 'question',
      message: "Is your expected ethereum address: " + address + "?"
    });
    console.log("Wrote ethereum.json file with keystore information for import into multisigweb")
  }
}

async function setupRipple(m, i) {
  const derivedPath = m.derivePath("m/44'/144'/0'/0/0")
  const address = derivedPath.getAddress()
  const keyPair = derivedPath.keyPair.getKeyPairs()
  if (i) {
    console.log("Ripple Address:\t\t\t\t" + address)
    await writeAndVerifyQRCode("Ripple", "ripple_address.png", address)
    console.log("Ripple Private Key:\t\t\t" + keyPair.privateKey.substring(2))
    return
  }

  var dataToSign = {};
  const choice = await prompt({
    type: 'select',
    name: 'choice',
    message: 'What are you trying to do?',
    choices: ["Create a new Transaction", "Sign a Transaction"]
  });

  if (choice.choice == "Create a new Transaction") {

    // Build a new TX from user input
    const data = await prompt([{
      type: 'input',
      name: 'Account',
      message: 'From which account are you withdrawing?',
      validate(answer) {
        return WAValidator.validate(answer, 'XRP');
      }
    }, {
      type: 'input',
      name: 'Destination',
      message: "What is the destination account?",
      validate(answer) {
        return WAValidator.validate(answer, 'XRP');
      }
    }, {
      type: 'input',
      name: 'DestinationTag',
      message: "What is the destination account's TAG?",
      result(answer) {
        return parseInt(answer);
      },
      validate(answer) {
        return !isNaN(answer);
      }
    }, {
      type: 'input',
      name: 'Amount',
      message: "What is the amount in XRP?",
      result(answer) {
        return parseInt(parseFloat(answer.replace(/,/g, ''))*1000000).toString();
      },
      validate(answer) {
        return !isNaN(parseFloat(answer.replace(/,/g, '')));
      }
    }, {
      type: 'input',
      name: 'Sequence',
      message: "What is the sequence number?",
      result(answer) {
        return parseInt(answer);
      },
      validate(answer) {
        return !isNaN(answer) && parseInt(answer) >= 0;
      }
    }]);
    data.TransactionType = "Payment"
    data.Fee = "100"
    dataToSign = JSON.stringify(data, null, 0)
  } else {
    // Ask the user to paste the TX to sign
    const txToSign = await prompt({
      type: 'input',
      name: 'json',
      initial: 'paste json',
      message: "JSON to sign",
      validate(answer) {
        return isValidJson(answer);
      }
    });
    dataToSign = txToSign.json
  }

  const option = { signAs: address }
  const signedTx = sign(dataToSign, keyPair, option)
  json_string = JSON.stringify(signedTx.txJson, null, 0)
  console.log(json_string)

  // If this is the last signature, output it in broadcastable format
  const response = await prompt({
    type: 'confirm',
    name: 'question',
    message: "Are you the last signatory?"
  });
  if (response.question === true) {
    // Construct it so it can be broadcasted with the xrpl websocket tool
    var json = {}
    json.id = "submit_multisigned_cryptoglacier"
    json.command = "submit_multisigned"
    json.tx_json = signedTx.txJson
    json_string = JSON.stringify(json, null, 0)
  }

  console.log("\n\nSUCCESS! Transaction signed!\n\n====")
  console.log(json_string)
  console.log("====\n\n")

  console.log("Writting QR Code ripple_tx.png\n\n")
  await writeAndVerifyQRCode("Ripple Transaction", "ripple_tx.png", json_string)
}

(async() => {

  // Parse arguments
  // TODO: need a way to signal transactions of a specific type
  const parser = new ArgumentParser({
    version: '0.0.1',
    addHelp:true,
    description: 'CryptoGlacier Setup'
  });
  parser.addArgument(
    [ '-c', '--check' ],
    {
      action: 'storeTrue',
      help: 'Runs script on check mode'
    }
  );
  parser.addArgument(
    [ '-e', '--ether' ],
    {
      action: 'storeTrue',
      help: 'Runs script on ether mode'
    }
  );
  parser.addArgument(
    [ '-i', '--init' ],
    {
      action: 'storeTrue',
      help: 'Runs script on init mode'
    }
  );
  parser.addArgument(
    [ '-x', '--xrp' ],
    {
      action: 'storeTrue',
      help: 'Runs script on xrp mode'
    }
  );
  const args = parser.parseArgs();
  const initMode = args.init
  const checkMode = args.check
  const etherMode = args.ether
  const xrpMode = args.xrp

  // First sanity check
  await safetyCheck()

  const initOrCheck = (initMode || checkMode)

  // diceSeedHash comes from user input on both init and check modes
  var diceSeedString;
  if (initOrCheck) {
    diceSeedString = await readDiceSeedInteractive()
  }
  // rngSeed is genered on init mode and comes from user input on check mode
  var rngSeed;
  if (initMode) {
    rngSeed = await generateRngSeed()
  } else if (checkMode) {
    rngSeed = await readRngSeedInteractive();
  }

  var mnemonic = ""
  if (initOrCheck) {
    // Compute entropy if on init or check modes
    const diceSeedHash = hashSHA256(diceSeedString)
    const rngSeedHash = hashSHA256(rngSeed)
    const hexPrivateKey = xorHexString(diceSeedHash, rngSeedHash)
    console.log("Dice entropy: \t\t\t\t{0}".format(chunkString(diceSeedString, 4).join(' ')))
    console.log("Generated Computer entropy:\t\t{0}".format(chunkString(rngSeed, 4).join(' ')))
    console.log("Final entropy:\t\t\t\t{0}".format(hexPrivateKey))
    mnemonic = bip39.entropyToMnemonic(hexPrivateKey)
  } else {
    // Else ask user to input mnemonic
    mnemonic = await getMnemonic()
  }
  console.log("BIP39 Mnemonic:\t\t\t\t{0}".format(mnemonic))

  // Get the seed, derive the address and key pairs
  const seed = bip39.mnemonicToSeed(mnemonic)

  if (initOrCheck) await setupElectron(seed.toString('hex'), initOrCheck)
  const m = bip32.fromSeedBuffer(seed)
  if (initOrCheck || etherMode) await setupEthereum(m, initOrCheck, etherMode)
  if (initOrCheck || xrpMode) await setupRipple(m, initOrCheck)

})();
