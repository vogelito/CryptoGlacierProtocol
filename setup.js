const ArgumentParser = require('argparse').ArgumentParser;
const bip39 = require("bip39");
const bip32 = require("ripple-bip32");
const jswallet = require("ethereumjs-wallet");
const keypairs = require("ripple-keypairs");
const { prompt } = require('enquirer');
const sign = require("ripple-sign-keypairs");
const fs = require('fs');

// From galcier protocol:
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

function isValidJson(str) {
    try {
        JSON.parse(str);
    } catch (e) {
        return false;
    }
    return true;
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
    description: 'Glacier Setup'
  });
  parser.addArgument(
    [ '-i', '--integrity' ],
    {
      action: 'storeTrue',
      help: 'Runs script on integrity checking mode'
    }
  );
  const args = parser.parseArgs();
  const integrity = args.integrity

  await safetyCheck()
  const mnemonic = await getMnemonic()

  // Get the seed, derive the address and key pairs
  const seed = bip39.mnemonicToSeed(mnemonic)
  const m = bip32.fromSeedBuffer(seed)
  await setupEthereum(m, integrity)
  await setupRipple(m, integrity)

})();
