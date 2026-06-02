/**
 * Derive raw private keys from a BIP-39 mnemonic.
 *
 * OWS (@open-wallet-standard/core) does not expose private keys — it returns
 * mnemonics from exportWallet. Callers that need raw keys derive them here.
 *
 * EVM:    BIP-44 secp256k1, path m/44'/60'/0'/0/<index>
 * Solana: SLIP-0010 ed25519, path m/44'/501'/<index>'/0' (Phantom convention)
 */

import { Buffer } from "node:buffer";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { HDKey } from "@scure/bip32";
import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha512.js";
import { Keypair } from "@solana/web3.js";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function toHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function bytesToBase58(bytes) {
  let num = 0n;
  for (const b of bytes) num = num * 256n + BigInt(b);
  let out = "";
  while (num > 0n) {
    const rem = Number(num % 58n);
    out = BASE58_ALPHABET[rem] + out;
    num = num / 58n;
  }
  for (const b of bytes) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}

/**
 * SLIP-0010 ed25519 derivation. Only hardened steps are valid.
 * @param {Uint8Array} seed - BIP-39 seed (64 bytes)
 * @param {number[]} pathIndices - hardened indices already OR'd with 0x80000000
 * @returns {Uint8Array} 32-byte private seed (input to Keypair.fromSeed)
 */
function deriveEd25519(seed, pathIndices) {
  const masterKey = new TextEncoder().encode("ed25519 seed");
  let I = hmac(sha512, masterKey, seed);
  let key = I.slice(0, 32);
  let chain = I.slice(32);

  for (const idx of pathIndices) {
    const data = new Uint8Array(1 + 32 + 4);
    data[0] = 0x00;
    data.set(key, 1);
    data[33] = (idx >>> 24) & 0xff;
    data[34] = (idx >>> 16) & 0xff;
    data[35] = (idx >>> 8) & 0xff;
    data[36] = idx & 0xff;
    I = hmac(sha512, chain, data);
    key = I.slice(0, 32);
    chain = I.slice(32);
  }
  return key;
}

const HARDENED = 0x80000000;

export function deriveEvmKey(mnemonic, index = 0) {
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new Error("Invalid mnemonic");
  }
  const seed = mnemonicToSeedSync(mnemonic);
  const node = HDKey.fromMasterSeed(seed).derive(`m/44'/60'/0'/0/${index}`);
  if (!node.privateKey) throw new Error("EVM derivation produced no private key");
  return {
    privateKey: "0x" + toHex(node.privateKey),
    address: null, // viem could derive; left null to avoid extra dep at this layer
    path: `m/44'/60'/0'/0/${index}`,
  };
}

export function deriveSolanaKey(mnemonic, index = 0) {
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new Error("Invalid mnemonic");
  }
  const seed = mnemonicToSeedSync(mnemonic);
  const path = [44 | HARDENED, 501 | HARDENED, index | HARDENED, 0 | HARDENED];
  const privSeed = deriveEd25519(seed, path);
  const kp = Keypair.fromSeed(privSeed);
  const secret64 = kp.secretKey; // 32 priv + 32 pub
  return {
    privateKeyBase58: bytesToBase58(secret64),
    privateKeyHex: toHex(secret64.slice(0, 32)),
    address: kp.publicKey.toBase58(),
    path: `m/44'/501'/${index}'/0'`,
  };
}
