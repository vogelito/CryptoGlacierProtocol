# cryptoglacierscript
Scripts for Crypto Glacier Protocol, the multi-blockchain, multi-device cold storage protocol based on the popular Glacier Protocol

## Install

```
git clone git@github.com:vogelito/cryptoglacierscript.git
cd cryptoglacierscript
npm i
```

## Usage
```
node setup.js
```

## Releasing
```
shasum -a 256 CryptoGlacier.pdf README.md mnemonic_entropy.py package.json package-lock.json setup.js > SHA256SUMS
gpg --armor --detach-sign --output SHA256SUMS.sig SHA256SUMS
```
