const ArgumentParser = require('argparse').ArgumentParser;
const bip39 = require("bip39");
const bip32 = require("ripple-bip32");
const fs = require('fs');
const jswallet = require("ethereumjs-wallet");
const keypairs = require("ripple-keypairs");
const { prompt } = require('enquirer');
const sha256 = require('js-sha256');
const sign = require("ripple-sign-keypairs");

String.prototype.format = function() {
  a = this;
  for (k in arguments) {
    a = a.replace("{" + k + "}", arguments[k])
  }
  return a
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//
// From galcier protocol, user sanity checking
//
//////////////////////////////////////////////////////////////////////////////////////////////////
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

//////////////////////////////////////////////////////////////////////////////////////////////////
//
// From galcier protocol
//
//////////////////////////////////////////////////////////////////////////////////////////////////


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
 * Check if a string is a valid hexadecimal number
 * From: https://github.com/roryrjb/is-hex/blob/771446c62ab548cbed372c8bf8bb183c46bc2dc3/is-hex.js
 * (MIT)
 */

function isHex(h) {
  var hexRegEx = /([0-9]|[a-f])/gim
  return typeof h === 'string' &&
    (h.match(hexRegEx) || []).length === h.length
}

/*
 *  Reads and validates 62 dice rolls from standard input, as a string of consecutive integers
 *    Returns a string representing the dice rolls
 *    returns => <string>
 */

async function readDiceSeedInteractive() {
  var dice = "";
  while (true) {
    const response = await prompt({
      type: 'input',
      name: 'dice',
      message: 'Enter 62 dice rolls (example: 62543 16325 21341...) Spaces are OK, and will be ignored:'
    });
    dice = response.dice;
    dice = unchunk(dice);
    if (validateDiceSeed(dice)) break;
  }
  return dice
}

/*
 *  Validates dice data (i.e. ensures at least 62 digits between 1 and 6).
 *    returns => <boolean>
 */
function validateDiceSeed(dice) {
  if (dice.length < 62) {
    console.log("Error: You must provide at least 62 dice rolls")
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
async function random(length = 20) {
  console.log("Making a random data string....")
  console.log("If strings don't appear right away, please continually move your mouse cursor. These movements generate entropy which is used to create random data.\n")

  const util = require('util');
  const exec = util.promisify(require('child_process').exec);
  const { stdout, stderr } = await exec("xxd -l {0} -p /dev/random".format(length), { shell: true });
  var seed = stdout.replace('\n', '')

  var computerEntropy = chunkString(seed, 4).join(' ')
  console.log("Generated Computer entropy: {0}\n\n".format(computer_entropy))
  return unchunk(computerEntropy)
}



/////////////////////
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


async function setupEthereum(m, i) {
  const derivedPath = m.derivePath("m/44'/60'/0'/0/0")
  const keyPair = derivedPath.keyPair.getKeyPairs()
  const privateKey = keyPair.privateKey.substring(2)
  const wallet = jswallet.fromPrivateKey(Buffer.from(privateKey, "hex"));
  if (i) {
    const js = wallet.toV3("dummydummy")
    console.log("Ethereum Address:\t\t0x" + js.address)
    console.log("Ethereum private key is:\t0x" + privateKey)
    console.log("")
    return
  }

  password = ""
  while (true) {
    const pw1 = await prompt({
      type: 'password',
      name: 'value',
      message: "Please enter a password to encrypt your ethereum wallet (at least 8 characters)"
    });
    const pw2 = await prompt({
      type: 'password',
      name: 'value',
      message: "Please confirm your password"
    });
    if (pw1.value == pw2.value && pw1.value.length >= 8) {
      password = pw1.value
      break
    }

    console.log("Passwords didn't match or less than 8 characters.\n\nPlease try again...")
  }
  const js = wallet.toV3(password)

  const confirmAddress = await prompt({
    type: 'confirm',
    name: 'question',
    message: "Is your expected ethereum address: 0x" + js.address + "?"
  });

  await write("ethereum.json", JSON.stringify(js, null, 4));
  console.log("Wrote ethereum.json file with keystore information for import into multisigweb")
}

async function setupRipple(m, i) {
  const derivedPath = m.derivePath("m/44'/144'/0'/0/0")
  const address = derivedPath.getAddress()
  const keyPair = derivedPath.keyPair.getKeyPairs()
  if (i) {
    console.log("Ripple Address:\t\t\t" + address)
    console.log("Ripple private key:\t\t" + keyPair.privateKey.substring(2))
    return
  }
  // TODO: is this necessary? Should we be offering the option to sign here instead?
  const confirmAddress = await prompt({
    type: 'confirm',
    name: 'question',
    message: "Is your ripple address " + address + "?"
  });
  if (confirmAddress.question === false) {
    console.log("\n\nExiting. Unexpected ripple address derived from 24 seed words")
    process.exit(1)
  }
}

(async() => {

  // Parse arguments
  const parser = new ArgumentParser({
    version: '0.0.1',
    addHelp:true,
    description: 'CryptoGlacier Setup'
  });
  parser.addArgument(
    [ '-i', '--init' ],
    {
      action: 'storeTrue',
      help: 'Runs script on init mode'
    }
  );
  parser.addArgument(
    [ '-c', '--check' ],
    {
      action: 'storeTrue',
      help: 'Runs script on check mode'
    }
  );
  const args = parser.parseArgs();
  const mnemonic = await getMnemonic()
  const initMode = args.init
  const checkMode = args.check

  // diceSeedHash is required on init or check modes
  var diceSeedHash;
  if (initMode || checkMode) {
    const diceSeedString = await readDiceSeedInteractive()
    diceSeedHash = hashSHA256(diceSeedString)
  }
  if (initMode) {
    await random()
    process.exit(1);
  } else if(checkMode) {
    const rngSeed = await readRngSeedInteractive();
  }
  //await safetyCheck()
  //const mnemonic = await getMnemonic()
  // Get the seed, derive the address and key pairs
  const seed = bip39.mnemonicToSeed(mnemonic)
  const m = bip32.fromSeedBuffer(seed)
  await setupEthereum(m, initMode)
  await setupRipple(m, initMode)

})();
