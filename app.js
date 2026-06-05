const STORAGE_KEYS = {
  identity: "securemsg_identity_v2",
  encryptedPrivateBundle: "securemsg_encrypted_private_bundle_v2",
  addressBook: "securemsg_address_book_v2"
};

const RSA_MODULUS_LENGTH = 4096;
const PBKDF2_ITERATIONS = 250000;

const els = {};

document.addEventListener("DOMContentLoaded", () => {
  bindElements();
  bindEvents();
  refreshAll();
});

function byId(id) {
  return document.getElementById(id);
}

function bindElements() {
  els.statusBox = byId("statusBox");

  els.createIdentityBtn = byId("createIdentityBtn");
  els.refreshBtn = byId("refreshBtn");

  els.showAddressBtn = byId("showAddressBtn");
  els.importAddressBtn = byId("importAddressBtn");
  els.deleteAddressBtn = byId("deleteAddressBtn");

  els.copyPublicKeyBtn = byId("copyPublicKeyBtn");
  els.copyPrivateKeyBtn = byId("copyPrivateKeyBtn");
  els.copyAddressBtn = byId("copyAddressBtn");
  els.copyEncryptedBtn = byId("copyEncryptedBtn");
  els.copyDecryptedBtn = byId("copyDecryptedBtn");

  els.clearOutputBtn = byId("clearOutputBtn");

  els.recipientSelect = byId("recipientSelect");

  els.messageInput = byId("messageInput");
  els.encryptBtn = byId("encryptBtn");

  els.outputBox = byId("outputBox");
  els.encryptedOutput = byId("encryptedOutput");

  els.publicKeyBox = byId("publicKeyBox");
  els.privateKeyBox = byId("privateKeyBox");

  els.myAddressBox = byId("myAddressBox");
  els.importAddressBox = byId("importAddressBox");

  els.decryptInput = byId("decryptInput");
  els.decryptTopBtn = byId("decryptTopBtn");
  els.decryptBtn = byId("decryptBtn");
  els.decryptedOutput = byId("decryptedOutput");

  els.identityDialog = byId("identityDialog");
  els.identityName = byId("identityName");
  els.identityEmail = byId("identityEmail");
  els.identityPassword = byId("identityPassword");
  els.identityPasswordConfirm = byId("identityPasswordConfirm");
  els.confirmCreateIdentityBtn = byId("confirmCreateIdentityBtn");

  els.passwordDialog = byId("passwordDialog");
  els.passwordDialogTitle = byId("passwordDialogTitle");
  els.runtimePassword = byId("runtimePassword");
  els.confirmPasswordBtn = byId("confirmPasswordBtn");
}

function on(element, event, handler) {
  if (element) {
    element.addEventListener(event, handler);
  }
}

function bindEvents() {
  on(els.createIdentityBtn, "click", openIdentityDialog);
  on(els.confirmCreateIdentityBtn, "click", handleCreateIdentity);

  on(els.showAddressBtn, "click", handleShowMyAddress);
  on(els.importAddressBtn, "click", handleImportAddress);
  on(els.deleteAddressBtn, "click", handleDeleteAddress);

  on(els.refreshBtn, "click", refreshAll);

  on(els.clearOutputBtn, "click", () => {
    setOutput("");
  });

  on(els.encryptBtn, "click", handleEncrypt);
  on(els.decryptTopBtn, "click", handleDecrypt);
  on(els.decryptBtn, "click", handleDecrypt);

  on(els.copyPublicKeyBtn, "click", () => copyText(getPublicKeyDisplay()));
  on(els.copyPrivateKeyBtn, "click", () => copyText(getEncryptedPrivateBundle()));
  on(els.copyAddressBtn, "click", () => copyText(getMyAddressText()));
  on(els.copyEncryptedBtn, "click", () => copyText(getEncryptedOutputText()));
  on(els.copyDecryptedBtn, "click", () => copyText(els.decryptedOutput?.value || ""));
}

function ensureWebCrypto() {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error(
      "WebCrypto is not available. Use HTTPS or http://localhost. Do not open the file directly with file://."
    );
  }
}

function storageGetJson(key, fallback) {
  const raw = localStorage.getItem(key);
  if (!raw) return fallback;

  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function storageSetJson(key, value) {
  localStorage.setItem(key, JSON.stringify(value, null, 2));
}

function getIdentity() {
  return storageGetJson(STORAGE_KEYS.identity, null);
}

function setIdentity(identity) {
  storageSetJson(STORAGE_KEYS.identity, identity);
}

function getEncryptedPrivateBundle() {
  return localStorage.getItem(STORAGE_KEYS.encryptedPrivateBundle) || "";
}

function setEncryptedPrivateBundle(blob) {
  localStorage.setItem(STORAGE_KEYS.encryptedPrivateBundle, blob);
}

function getAddressBook() {
  return storageGetJson(STORAGE_KEYS.addressBook, {});
}

function setAddressBook(book) {
  storageSetJson(STORAGE_KEYS.addressBook, book);
}

function identityExists() {
  return Boolean(getIdentity() && getEncryptedPrivateBundle());
}

function makeContactKey(name, fingerprint) {
  return `${name} | ${fingerprint}`;
}

function refreshAll() {
  refreshStatus();
  refreshKeyBoxes();
  refreshAddressBoxes();
  refreshAddressDropdown();
}

function refreshStatus() {
  if (!els.statusBox) return;

  const identity = getIdentity();
  const book = getAddressBook();

  const identityStatus = identity
    ? `${identity.name} | ${identity.fingerprint}`
    : "missing";

  els.statusBox.textContent =
    `Identity: ${identityStatus}\n` +
    `Saved addresses: ${Object.keys(book).length}\n` +
    `Private key storage: encrypted locally in this browser\n` +
    `Crypto: RSA-OAEP + AES-GCM + RSA-PSS`;
}

function refreshKeyBoxes() {
  if (els.publicKeyBox) {
    els.publicKeyBox.value = getPublicKeyDisplay();
  }

  if (els.privateKeyBox) {
    els.privateKeyBox.value = getEncryptedPrivateBundle();
  }
}

function refreshAddressBoxes() {
  if (els.myAddressBox) {
    try {
      els.myAddressBox.value = identityExists() ? buildMyAddress() : "";
    } catch {
      els.myAddressBox.value = "";
    }
  }
}

function refreshAddressDropdown() {
  if (!els.recipientSelect) return;

  const book = getAddressBook();
  els.recipientSelect.innerHTML = "";

  const contacts = Object.entries(book)
    .map(([key, contact]) => ({ key, contact }))
    .sort((a, b) => a.contact.name.localeCompare(b.contact.name));

  for (const item of contacts) {
    const option = document.createElement("option");
    const emailPart = item.contact.email ? ` <${item.contact.email}>` : "";

    option.value = item.key;
    option.textContent = `${item.contact.name}${emailPart} | ${item.contact.fingerprint}`;

    els.recipientSelect.appendChild(option);
  }
}

function getPublicKeyDisplay() {
  const identity = getIdentity();

  if (!identity) return "";

  return (
    `ENCRYPTION PUBLIC KEY\n\n${identity.encryption_public_key}\n\n` +
    `SIGNING PUBLIC KEY\n\n${identity.signing_public_key}`
  );
}

function getMyAddressText() {
  if (els.myAddressBox && els.myAddressBox.value.trim()) {
    return els.myAddressBox.value.trim();
  }

  return buildMyAddress();
}

function getEncryptedOutputText() {
  if (els.encryptedOutput) {
    return els.encryptedOutput.value.trim();
  }

  if (els.outputBox) {
    return els.outputBox.value.trim();
  }

  return "";
}

function setOutput(text) {
  if (els.encryptedOutput) {
    els.encryptedOutput.value = text;
  } else if (els.outputBox) {
    els.outputBox.value = text;
  }
}

function openIdentityDialog() {
  if (identityExists()) {
    const ok = confirm(
      "A local identity already exists.\n\n" +
      "Overwrite it?\n\n" +
      "Old messages encrypted to the old key may become unreadable."
    );

    if (!ok) return;
  }

  els.identityName.value = "";
  els.identityEmail.value = "";
  els.identityPassword.value = "";
  els.identityPasswordConfirm.value = "";

  els.identityDialog.showModal();
}

async function handleCreateIdentity(event) {
  event.preventDefault();

  try {
    ensureWebCrypto();

    const name = els.identityName.value.trim();
    const email = els.identityEmail.value.trim();
    const password = els.identityPassword.value;
    const confirmPassword = els.identityPasswordConfirm.value;

    if (!name) throw new Error("Name is required.");
    if (!password) throw new Error("Password cannot be empty.");
    if (password !== confirmPassword) throw new Error("Passwords do not match.");

    const encryptionPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: RSA_MODULUS_LENGTH,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );

    const signingPair = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: RSA_MODULUS_LENGTH,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["sign", "verify"]
    );

    const encryptionPublicSpki = await crypto.subtle.exportKey("spki", encryptionPair.publicKey);
    const encryptionPrivatePkcs8 = await crypto.subtle.exportKey("pkcs8", encryptionPair.privateKey);

    const signingPublicSpki = await crypto.subtle.exportKey("spki", signingPair.publicKey);
    const signingPrivatePkcs8 = await crypto.subtle.exportKey("pkcs8", signingPair.privateKey);

    const encryptionPublicPem = derToPem(encryptionPublicSpki, "PUBLIC KEY");
    const signingPublicPem = derToPem(signingPublicSpki, "PUBLIC KEY");

    const fingerprint = await combinedFingerprint(encryptionPublicSpki, signingPublicSpki);

    const privateBundle = {
      encryption_private_pkcs8: arrayBufferToB64(encryptionPrivatePkcs8),
      signing_private_pkcs8: arrayBufferToB64(signingPrivatePkcs8)
    };

    const encryptedPrivateBundle = await encryptPrivateBundle(privateBundle, password);

    const identity = {
      name,
      email,
      fingerprint,
      encryption_public_key: encryptionPublicPem,
      signing_public_key: signingPublicPem
    };

    setIdentity(identity);
    setEncryptedPrivateBundle(encryptedPrivateBundle);

    const myAddress = buildAddressFromIdentity(identity);
    const parsed = await parseAddressAsync(myAddress);
    addContact(parsed);

    els.identityDialog.close();
    refreshAll();

    alert(`Identity created.\n\nFingerprint:\n${fingerprint}`);
  } catch (err) {
    alert(`Identity creation error:\n\n${err.message}`);
  }
}

function buildAddressFromIdentity(identity) {
  const address = {
    type: "SECUREADDR",
    version: 1,
    name: identity.name,
    email: identity.email || "",
    fingerprint: identity.fingerprint,
    encryption_public_key: identity.encryption_public_key,
    signing_public_key: identity.signing_public_key
  };

  return `SECUREADDR:v1:${jsonToB64(address)}`;
}

function buildMyAddress() {
  const identity = getIdentity();

  if (!identity) {
    throw new Error("No identity exists. Create/register your key first.");
  }

  return buildAddressFromIdentity(identity);
}

function handleShowMyAddress() {
  try {
    const address = buildMyAddress();

    if (els.myAddressBox) {
      els.myAddressBox.value = address;
    } else {
      setOutput(address);
    }
  } catch (err) {
    alert(`Address error:\n\n${err.message}`);
  }
}

async function handleImportAddress() {
  try {
    let pasted = "";

    if (els.importAddressBox) {
      pasted = els.importAddressBox.value.trim();
    }

    if (!pasted && els.outputBox) {
      pasted = els.outputBox.value.trim();
    }

    if (!pasted && els.decryptInput) {
      pasted = els.decryptInput.value.trim();
    }

    if (!pasted) {
      throw new Error("Paste a SECUREADDR:v1:... block first.");
    }

    const address = await parseAddressAsync(pasted);
    addContact(address);
    refreshAll();

    alert(
      `Address imported.\n\n` +
      `Name: ${address.name}\n` +
      `Fingerprint: ${address.fingerprint}`
    );
  } catch (err) {
    alert(`Import error:\n\n${err.message}`);
  }
}

function handleDeleteAddress() {
  const key = els.recipientSelect?.value;

  if (!key) {
    alert("Select an address first.");
    return;
  }

  const ok = confirm(`Delete selected address?\n\n${key}`);

  if (!ok) return;

  const book = getAddressBook();
  delete book[key];
  setAddressBook(book);
  refreshAll();
}

function addContact(address) {
  const required = [
    "type",
    "version",
    "name",
    "fingerprint",
    "encryption_public_key",
    "signing_public_key"
  ];

  for (const field of required) {
    if (!(field in address)) {
      throw new Error(`Address is missing field: ${field}`);
    }
  }

  if (address.type !== "SECUREADDR") {
    throw new Error("This is not a SECUREADDR address.");
  }

  const key = makeContactKey(address.name, address.fingerprint);
  const book = getAddressBook();

  book[key] = {
    name: address.name,
    email: address.email || "",
    fingerprint: address.fingerprint,
    encryption_public_key: address.encryption_public_key,
    signing_public_key: address.signing_public_key
  };

  setAddressBook(book);
}

async function parseAddressAsync(addressBlob) {
  const cleaned = addressBlob.trim();

  if (!cleaned.startsWith("SECUREADDR:v1:")) {
    throw new Error("Address must start with SECUREADDR:v1:");
  }

  const encoded = cleaned.split("SECUREADDR:v1:", 2)[1];
  const address = b64ToJson(encoded);

  if (address.type !== "SECUREADDR") {
    throw new Error("This is not a SECUREADDR address.");
  }

  const encryptionSpki = pemToDer(address.encryption_public_key);
  const signingSpki = pemToDer(address.signing_public_key);

  const calculated = await combinedFingerprint(encryptionSpki, signingSpki);

  if (address.fingerprint !== calculated) {
    throw new Error("Address fingerprint does not match the included public keys.");
  }

  return address;
}

function getSelectedRecipient() {
  const key = els.recipientSelect?.value;

  if (!key) {
    throw new Error("No recipient selected. Import or create an address first.");
  }

  const book = getAddressBook();
  const recipient = book[key];

  if (!recipient) {
    throw new Error("Selected recipient was not found.");
  }

  return recipient;
}

async function handleEncrypt() {
  try {
    ensureWebCrypto();

    const plaintext = els.messageInput?.value.trim();

    if (!plaintext) {
      throw new Error("Write a message first.");
    }

    const recipient = getSelectedRecipient();
    const encrypted = await encryptAndSignMessage(plaintext, recipient);

    setOutput(encrypted);
  } catch (err) {
    alert(`Encryption error:\n\n${err.message}`);
  }
}

async function handleDecrypt() {
  try {
    ensureWebCrypto();

    const blob = els.decryptInput?.value.trim();

    if (!blob) {
      throw new Error("Paste a SECUREMSG:v1:... block first.");
    }

    const decrypted = await decryptAndVerifyMessage(blob);

    if (els.decryptedOutput) {
      els.decryptedOutput.value = decrypted;
    }
  } catch (err) {
    alert(`Decrypt error:\n\n${err.message}`);
  }
}

async function encryptAndSignMessage(plaintext, recipient) {
  const identity = getIdentity();

  if (!identity) {
    throw new Error("No identity exists. Create/register your key first.");
  }

  const password = await askRuntimePassword("Private key password");
  const privateBundle = await decryptPrivateBundle(password);

  const signingPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    b64ToBytes(privateBundle.signing_private_pkcs8),
    {
      name: "RSA-PSS",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const recipientEncryptionPublicKey = await crypto.subtle.importKey(
    "spki",
    pemToDer(recipient.encryption_public_key),
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    false,
    ["encrypt"]
  );

  const aesKey = await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );

  const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce
    },
    aesKey,
    new TextEncoder().encode(plaintext)
  );

  const encryptedAesKey = await crypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    recipientEncryptionPublicKey,
    rawAesKey
  );

  const message = {
    type: "SECUREMSG",
    version: 1,
    sender_name: identity.name,
    sender_email: identity.email || "",
    sender_fingerprint: identity.fingerprint,
    recipient_name: recipient.name,
    recipient_fingerprint: recipient.fingerprint,
    algorithm: "RSA-4096-OAEP-SHA256 + AES-256-GCM + RSA-PSS-SHA256",
    encrypted_key: arrayBufferToB64(encryptedAesKey),
    nonce: bytesToB64(nonce),
    ciphertext: arrayBufferToB64(ciphertext)
  };

  const signature = await crypto.subtle.sign(
    {
      name: "RSA-PSS",
      saltLength: 32
    },
    signingPrivateKey,
    canonicalJsonBytes(message)
  );

  const packageData = {
    message,
    signature: arrayBufferToB64(signature)
  };

  return `SECUREMSG:v1:${jsonToB64(packageData)}`;
}

async function decryptAndVerifyMessage(blob) {
  const identity = getIdentity();

  if (!identity) {
    throw new Error("No identity exists. Create/register your key first.");
  }

  const cleaned = blob.trim();

  if (!cleaned.startsWith("SECUREMSG:v1:")) {
    throw new Error("Message must start with SECUREMSG:v1:");
  }

  const encoded = cleaned.split("SECUREMSG:v1:", 2)[1];
  const packageData = b64ToJson(encoded);

  const message = packageData.message;
  const signature = b64ToBytes(packageData.signature);

  if (message.recipient_fingerprint !== identity.fingerprint) {
    throw new Error(
      "This message is not encrypted for your current identity.\n\n" +
      `Message recipient fingerprint: ${message.recipient_fingerprint}\n` +
      `Your fingerprint: ${identity.fingerprint}`
    );
  }

  const sender = findContactByFingerprint(message.sender_fingerprint);

  if (!sender) {
    throw new Error("Sender is not in your address book. Import their address first.");
  }

  const calculatedSenderFingerprint = await combinedFingerprint(
    pemToDer(sender.encryption_public_key),
    pemToDer(sender.signing_public_key)
  );

  if (message.sender_fingerprint !== calculatedSenderFingerprint) {
    throw new Error("Sender fingerprint does not match their imported public keys.");
  }

  const senderSigningPublicKey = await crypto.subtle.importKey(
    "spki",
    pemToDer(sender.signing_public_key),
    {
      name: "RSA-PSS",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    {
      name: "RSA-PSS",
      saltLength: 32
    },
    senderSigningPublicKey,
    signature,
    canonicalJsonBytes(message)
  );

  if (!valid) {
    throw new Error("Invalid signature. Message may be forged or modified.");
  }

  const password = await askRuntimePassword("Private key password");
  const privateBundle = await decryptPrivateBundle(password);

  const encryptionPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    b64ToBytes(privateBundle.encryption_private_pkcs8),
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    false,
    ["decrypt"]
  );

  const rawAesKey = await crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    encryptionPrivateKey,
    b64ToBytes(message.encrypted_key)
  );

  const aesKey = await crypto.subtle.importKey(
    "raw",
    rawAesKey,
    {
      name: "AES-GCM"
    },
    false,
    ["decrypt"]
  );

  const plaintextBytes = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: b64ToBytes(message.nonce)
    },
    aesKey,
    b64ToBytes(message.ciphertext)
  );

  const plaintext = new TextDecoder().decode(plaintextBytes);
  const emailLine = message.sender_email ? `Email: ${message.sender_email}\n` : "";

  return (
    `From: ${message.sender_name}\n` +
    emailLine +
    `Signature: VALID\n` +
    `Sender fingerprint: ${message.sender_fingerprint}\n` +
    `Recipient: ${message.recipient_name}\n` +
    `Recipient fingerprint: ${message.recipient_fingerprint}\n\n` +
    plaintext
  );
}

function findContactByFingerprint(fingerprint) {
  const book = getAddressBook();

  for (const contact of Object.values(book)) {
    if (contact.fingerprint === fingerprint) {
      return contact;
    }
  }

  return null;
}

async function encryptPrivateBundle(privateBundle, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await derivePasswordKey(password, salt);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce
    },
    key,
    new TextEncoder().encode(JSON.stringify(privateBundle))
  );

  const packageData = {
    type: "SECUREPRIVATE",
    version: 1,
    kdf: "PBKDF2-SHA256",
    iterations: PBKDF2_ITERATIONS,
    encryption: "AES-256-GCM",
    salt: bytesToB64(salt),
    nonce: bytesToB64(nonce),
    ciphertext: arrayBufferToB64(ciphertext)
  };

  return `SECUREPRIVATE:v1:${jsonToB64(packageData)}`;
}

async function decryptPrivateBundle(password) {
  const blob = getEncryptedPrivateBundle();

  if (!blob.startsWith("SECUREPRIVATE:v1:")) {
    throw new Error("Encrypted private key is missing or invalid.");
  }

  const encoded = blob.split("SECUREPRIVATE:v1:", 2)[1];
  const packageData = b64ToJson(encoded);

  const key = await derivePasswordKey(password, b64ToBytes(packageData.salt));

  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: b64ToBytes(packageData.nonce)
      },
      key,
      b64ToBytes(packageData.ciphertext)
    );

    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new Error("Wrong password or damaged encrypted private key.");
  }
}

async function derivePasswordKey(password, salt) {
  const passwordBytes = new TextEncoder().encode(password);

  const baseKey = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

function askRuntimePassword(title) {
  return new Promise((resolve, reject) => {
    els.passwordDialogTitle.textContent = title;
    els.runtimePassword.value = "";

    let resolved = false;

    const cleanup = () => {
      els.confirmPasswordBtn.removeEventListener("click", onConfirm);
      els.passwordDialog.removeEventListener("close", onClose);
    };

    const onConfirm = (event) => {
      event.preventDefault();

      const password = els.runtimePassword.value;

      if (!password) {
        alert("Password is required.");
        return;
      }

      resolved = true;
      cleanup();
      els.passwordDialog.close();
      resolve(password);
    };

    const onClose = () => {
      cleanup();

      if (!resolved) {
        reject(new Error("Password prompt cancelled."));
      }
    };

    els.confirmPasswordBtn.addEventListener("click", onConfirm);
    els.passwordDialog.addEventListener("close", onClose, { once: true });

    els.passwordDialog.showModal();
    els.runtimePassword.focus();
  });
}

async function combinedFingerprint(encryptionSpki, signingSpki) {
  const encryptionBytes = new Uint8Array(encryptionSpki);
  const signingBytes = new Uint8Array(signingSpki);

  const combined = new Uint8Array(encryptionBytes.length + signingBytes.length);
  combined.set(encryptionBytes, 0);
  combined.set(signingBytes, encryptionBytes.length);

  const digest = await crypto.subtle.digest("SHA-256", combined);

  return bytesToHex(new Uint8Array(digest)).slice(0, 32);
}

function canonicalJsonBytes(obj) {
  return new TextEncoder().encode(stableStringify(obj));
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  const keys = Object.keys(value).sort();

  return `{${keys.map((key) => {
    return `${JSON.stringify(key)}:${stableStringify(value[key])}`;
  }).join(",")}}`;
}

function derToPem(buffer, label) {
  const b64 = arrayBufferToB64(buffer);
  const lines = b64.match(/.{1,64}/g).join("\n");

  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function pemToDer(pem) {
  const clean = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");

  return b64ToBytes(clean);
}

function jsonToB64(obj) {
  return bytesToB64(new TextEncoder().encode(JSON.stringify(obj)));
}

function b64ToJson(b64) {
  return JSON.parse(new TextDecoder().decode(b64ToBytes(b64)));
}

function arrayBufferToB64(buffer) {
  return bytesToB64(new Uint8Array(buffer));
}

function bytesToB64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function b64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function copyText(text) {
  if (!text) {
    alert("Nothing to copy.");
    return;
  }

  await navigator.clipboard.writeText(text);
}
