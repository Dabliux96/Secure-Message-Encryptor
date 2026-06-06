"use strict";

const STORAGE_KEYS = Object.freeze({
  publicIdentity: "securemsg_public_identity_v3",
  addressBook: "securemsg_address_book_v3"
});

const APP_NAME = "SecureMessageEncryptor";
const APP_VERSION = 3;

const RSA_MODULUS_LENGTH = 4096;
const RSA_PUBLIC_EXPONENT = new Uint8Array([1, 0, 1]);

const PBKDF2_ITERATIONS = 600000;

const MAX_NAME_CHARS = 80;
const MAX_EMAIL_CHARS = 254;
const MAX_ADDRESS_CHARS = 30000;
const MAX_MESSAGE_CHARS = 2_000_000;
const MAX_PRIVATE_BACKUP_CHARS = 500000;
const MAX_PLAINTEXT_CHARS = 500000;

const FINGERPRINT_RE = /^[a-f0-9]{64}$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const MESSAGE_ALGORITHM = "RSA-OAEP-SHA256 + AES-256-GCM + RSA-PSS-SHA256";
const PRIVATE_BUNDLE_ALGORITHM = "PBKDF2-SHA256 + AES-256-GCM";

const memoryState = {
  identity: null,
  encryptedPrivateBackup: "",
  encryptionPrivateKey: null,
  signingPrivateKey: null,
  unlockedFingerprint: "",
  unlockedAt: 0
};

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
  els.verifyContactBtn = byId("verifyContactBtn");
  els.deleteAddressBtn = byId("deleteAddressBtn");

  els.exportPrivateKeyBtn = byId("exportPrivateKeyBtn");
  els.importPrivateKeyBtn = byId("importPrivateKeyBtn");
  els.lockPrivateKeyBtn = byId("lockPrivateKeyBtn");

  els.copyPublicKeyBtn = byId("copyPublicKeyBtn");
  els.copyAddressBtn = byId("copyAddressBtn");
  els.copyEncryptedBtn = byId("copyEncryptedBtn");
  els.copyDecryptedBtn = byId("copyDecryptedBtn");

  els.clearOutputBtn = byId("clearOutputBtn");

  els.recipientSelect = byId("recipientSelect");

  els.messageInput = byId("messageInput");
  els.encryptBtn = byId("encryptBtn");

  els.outputBox = byId("outputBox");

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
  on(els.verifyContactBtn, "click", handleVerifySelectedContact);
  on(els.deleteAddressBtn, "click", handleDeleteAddress);

  on(els.exportPrivateKeyBtn, "click", handleExportEncryptedPrivateBackup);
  on(els.importPrivateKeyBtn, "click", handleImportEncryptedPrivateBackup);
  on(els.lockPrivateKeyBtn, "click", lockPrivateKeys);

  on(els.refreshBtn, "click", refreshAll);
  on(els.clearOutputBtn, "click", clearOutputs);

  on(els.encryptBtn, "click", handleEncrypt);
  on(els.decryptTopBtn, "click", handleDecrypt);
  on(els.decryptBtn, "click", handleDecrypt);

  on(els.copyPublicKeyBtn, "click", () => copyText(getPublicKeyDisplay(), "public key"));
  on(els.copyAddressBtn, "click", () => copyText(getMyAddressText(), "address"));
  on(els.copyEncryptedBtn, "click", () => copyText(getEncryptedOutputText(), "encrypted message"));
  on(els.copyDecryptedBtn, "click", () => copyText(els.decryptedOutput?.value || "", "decrypted message"));
}

/* Browser and storage */

function ensureWebCrypto() {
  if (!window.isSecureContext) {
    throw new Error("This page must run in a secure context. Use HTTPS or http://localhost.");
  }

  if (!window.crypto || !window.crypto.subtle) {
    throw new Error("WebCrypto is not available in this browser/context.");
  }
}

function storageGetJson(key, fallback) {
  const raw = localStorage.getItem(key);

  if (!raw) {
    return fallback;
  }

  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function storageSetJson(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

function getPublicIdentity() {
  return storageGetJson(STORAGE_KEYS.publicIdentity, null);
}

function setPublicIdentity(identity) {
  validatePublicIdentity(identity);
  storageSetJson(STORAGE_KEYS.publicIdentity, identity);
}

function getAddressBook() {
  const book = storageGetJson(STORAGE_KEYS.addressBook, {});
  return typeof book === "object" && book !== null && !Array.isArray(book) ? book : {};
}

function setAddressBook(book) {
  storageSetJson(STORAGE_KEYS.addressBook, book);
}

function identityExists() {
  return Boolean(getPublicIdentity());
}

function unlockedPrivateKeysExist() {
  return Boolean(memoryState.encryptionPrivateKey && memoryState.signingPrivateKey && memoryState.unlockedFingerprint);
}

function makeContactKey(fingerprint) {
  assertFingerprint(fingerprint, "Contact fingerprint");
  return fingerprint;
}

/* UI */

function refreshAll() {
  refreshStatus();
  refreshKeyBoxes();
  refreshAddressBoxes();
  refreshAddressDropdown();
}

function clearOutputs() {
  if (els.outputBox) els.outputBox.value = "";
  if (els.decryptedOutput) els.decryptedOutput.value = "";
}

function refreshStatus() {
  if (!els.statusBox) return;

  const identity = getPublicIdentity();
  const book = getAddressBook();

  const identityStatus = identity
    ? `${identity.name} | ${shortFingerprint(identity.fingerprint)}`
    : "missing";

  const unlockStatus = unlockedPrivateKeysExist()
    ? `unlocked in memory | ${new Date(memoryState.unlockedAt).toLocaleString()}`
    : "locked or not imported";

  els.statusBox.textContent =
    `Identity: ${identityStatus}\n` +
    `Private key: ${unlockStatus}\n` +
    `Saved public addresses: ${Object.keys(book).length}\n` +
    `Private key storage: user-controlled encrypted backup only\n` +
    `Crypto: ${MESSAGE_ALGORITHM}`;
}

function refreshKeyBoxes() {
  if (els.publicKeyBox) {
    els.publicKeyBox.value = getPublicKeyDisplay();
  }

  if (els.privateKeyBox) {
    els.privateKeyBox.value =
      "Private key is not displayed or stored in localStorage.\n\n" +
      "After creating an identity, download and safely store the encrypted private backup file.\n\n" +
      "To decrypt/sign later, import/unlock that backup file.";
  }
}

function refreshAddressBoxes() {
  if (!els.myAddressBox) return;

  try {
    els.myAddressBox.value = identityExists() ? buildMyAddress() : "";
  } catch {
    els.myAddressBox.value = "";
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
    const trustPart = item.contact.trust === "verified" ? "verified" : "unverified";

    option.value = item.key;
    option.textContent = `${item.contact.name}${emailPart} | ${shortFingerprint(item.contact.fingerprint)} | ${trustPart}`;

    els.recipientSelect.appendChild(option);
  }
}

function getPublicKeyDisplay() {
  const identity = getPublicIdentity();

  if (!identity) return "";

  return (
    `ENCRYPTION PUBLIC KEY\n\n${identity.encryption_public_key}\n\n` +
    `SIGNING PUBLIC KEY\n\n${identity.signing_public_key}\n\n` +
    `FINGERPRINT\n\n${identity.fingerprint}`
  );
}

function getMyAddressText() {
  if (els.myAddressBox && els.myAddressBox.value.trim()) {
    return els.myAddressBox.value.trim();
  }

  return buildMyAddress();
}

function getEncryptedOutputText() {
  return els.outputBox?.value.trim() || "";
}

function setOutput(text) {
  if (els.outputBox) {
    els.outputBox.value = text;
  }
}

/* Identity */

function openIdentityDialog() {
  if (identityExists()) {
    const ok = confirm(
      "A public identity already exists in this browser.\n\n" +
      "Creating a new one replaces the current public identity and locks any private key in memory.\n\n" +
      "Make sure you exported your encrypted private backup first.\n\n" +
      "Continue?"
    );

    if (!ok) return;
  }

  if (els.identityName) els.identityName.value = "";
  if (els.identityEmail) els.identityEmail.value = "";
  if (els.identityPassword) els.identityPassword.value = "";
  if (els.identityPasswordConfirm) els.identityPasswordConfirm.value = "";

  els.identityDialog?.showModal();
}

async function handleCreateIdentity(event) {
  event.preventDefault();

  try {
    ensureWebCrypto();

    const name = cleanName(els.identityName?.value || "");
    const email = cleanEmail(els.identityEmail?.value || "");
    const passwordPair = readAndClearPasswordInputs(els.identityPassword, els.identityPasswordConfirm);

    if (!name) throw new Error("Name is required.");
    if (!passwordPair.password) throw new Error("Password cannot be empty.");
    if (passwordPair.password !== passwordPair.confirmPassword) {
      throw new Error("Passwords do not match.");
    }

    const encryptionPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: RSA_MODULUS_LENGTH,
        publicExponent: RSA_PUBLIC_EXPONENT,
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );

    const signingPair = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: RSA_MODULUS_LENGTH,
        publicExponent: RSA_PUBLIC_EXPONENT,
        hash: "SHA-256"
      },
      true,
      ["sign", "verify"]
    );

    const encryptionPublicSpki = await crypto.subtle.exportKey("spki", encryptionPair.publicKey);
    const signingPublicSpki = await crypto.subtle.exportKey("spki", signingPair.publicKey);

    const encryptionPrivatePkcs8 = await crypto.subtle.exportKey("pkcs8", encryptionPair.privateKey);
    const signingPrivatePkcs8 = await crypto.subtle.exportKey("pkcs8", signingPair.privateKey);

    const encryptionPublicPem = derToPem(encryptionPublicSpki, "PUBLIC KEY");
    const signingPublicPem = derToPem(signingPublicSpki, "PUBLIC KEY");

    const fingerprint = await combinedFingerprint(encryptionPublicSpki, signingPublicSpki);

    const identity = {
      type: "SECUREIDENTITY",
      version: APP_VERSION,
      app: APP_NAME,
      created_at: nowIso(),
      name,
      email,
      fingerprint,
      encryption_public_key: encryptionPublicPem,
      signing_public_key: signingPublicPem
    };

    validatePublicIdentity(identity);

    const privateBundle = {
      type: "SECUREPRIVATEPLAINTEXT",
      version: APP_VERSION,
      app: APP_NAME,
      fingerprint,
      created_at: identity.created_at,
      encryption_private_pkcs8: arrayBufferToB64(encryptionPrivatePkcs8),
      signing_private_pkcs8: arrayBufferToB64(signingPrivatePkcs8)
    };

    const encryptedBackup = await encryptPrivateBundle(privateBundle, passwordPair.password);
    await unlockPrivateKeysFromBundle(privateBundle, identity);

    setPublicIdentity(identity);
    memoryState.identity = identity;
    memoryState.encryptedPrivateBackup = encryptedBackup;

    addContact(buildContactFromIdentity(identity, "verified"));

    els.identityDialog?.close();
    refreshAll();

    downloadTextFile(`securemsg-private-backup-${shortFingerprint(fingerprint)}.txt`, encryptedBackup);

    alert(
      "Identity created.\n\n" +
      "An encrypted private-key backup was downloaded.\n\n" +
      "Store it safely. Without it, you cannot decrypt old messages after closing/reloading the page.\n\n" +
      `Fingerprint:\n${fingerprint}`
    );
  } catch (err) {
    alert(`Identity creation error:\n\n${safeErrorMessage(err)}`);
  }
}

async function handleExportEncryptedPrivateBackup() {
  try {
    const identity = getPublicIdentity();

    if (!identity) throw new Error("No identity exists.");

    if (!memoryState.encryptedPrivateBackup) {
      throw new Error(
        "No encrypted private backup is currently loaded in memory.\n\n" +
        "This app does not store private key material in localStorage.\n\n" +
        "Use the backup file you downloaded when creating the identity."
      );
    }

    downloadTextFile(`securemsg-private-backup-${shortFingerprint(identity.fingerprint)}.txt`, memoryState.encryptedPrivateBackup);
  } catch (err) {
    alert(`Export error:\n\n${safeErrorMessage(err)}`);
  }
}

async function handleImportEncryptedPrivateBackup() {
  try {
    ensureWebCrypto();

    const backupText = await chooseTextFile(".txt,.securemsg,text/plain");
    assertMaxLength(backupText, MAX_PRIVATE_BACKUP_CHARS, "Private key backup");

    const password = await askRuntimePassword("Private key backup password");
    const privateBundle = await decryptPrivateBundle(backupText, password);

    const identity = getPublicIdentity();

    if (!identity) {
      throw new Error("Create or import the matching public identity/address first.");
    }

    if (privateBundle.fingerprint !== identity.fingerprint) {
      throw new Error(
        "This private key backup does not match the current public identity.\n\n" +
        `Backup fingerprint: ${privateBundle.fingerprint}\n` +
        `Current identity: ${identity.fingerprint}`
      );
    }

    await unlockPrivateKeysFromBundle(privateBundle, identity);

    memoryState.encryptedPrivateBackup = backupText;
    refreshAll();

    alert("Private key backup imported and unlocked in memory.");
  } catch (err) {
    alert(`Private key import error:\n\n${safeErrorMessage(err)}`);
  }
}

async function unlockPrivateKeysFromBundle(privateBundle, identity) {
  validatePlainPrivateBundle(privateBundle);
  validatePublicIdentity(identity);

  if (privateBundle.fingerprint !== identity.fingerprint) {
    throw new Error("Private bundle fingerprint does not match identity.");
  }

  const encryptionPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    b64ToBytesStrict(privateBundle.encryption_private_pkcs8, "Encryption private key"),
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    false,
    ["decrypt"]
  );

  const signingPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    b64ToBytesStrict(privateBundle.signing_private_pkcs8, "Signing private key"),
    {
      name: "RSA-PSS",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  memoryState.identity = identity;
  memoryState.encryptionPrivateKey = encryptionPrivateKey;
  memoryState.signingPrivateKey = signingPrivateKey;
  memoryState.unlockedFingerprint = identity.fingerprint;
  memoryState.unlockedAt = Date.now();
}

function lockPrivateKeys() {
  memoryState.encryptionPrivateKey = null;
  memoryState.signingPrivateKey = null;
  memoryState.unlockedFingerprint = "";
  memoryState.unlockedAt = 0;

  if (els.decryptedOutput) els.decryptedOutput.value = "";

  refreshAll();
}

/* Addresses */

function buildContactFromIdentity(identity, trust = "unverified") {
  validatePublicIdentity(identity);

  return {
    type: "SECURECONTACT",
    version: APP_VERSION,
    app: APP_NAME,
    imported_at: nowIso(),
    trust,
    name: identity.name,
    email: identity.email || "",
    fingerprint: identity.fingerprint,
    encryption_public_key: identity.encryption_public_key,
    signing_public_key: identity.signing_public_key
  };
}

function buildAddressFromIdentity(identity) {
  validatePublicIdentity(identity);

  const address = {
    type: "SECUREADDR",
    version: APP_VERSION,
    app: APP_NAME,
    created_at: identity.created_at || nowIso(),
    name: identity.name,
    email: identity.email || "",
    fingerprint: identity.fingerprint,
    encryption_public_key: identity.encryption_public_key,
    signing_public_key: identity.signing_public_key
  };

  return `SECUREADDR:v${APP_VERSION}:${jsonToB64(address)}`;
}

function buildMyAddress() {
  const identity = getPublicIdentity();

  if (!identity) {
    throw new Error("No public identity exists. Create an identity first.");
  }

  return buildAddressFromIdentity(identity);
}

function handleShowMyAddress() {
  try {
    const address = buildMyAddress();

    if (els.myAddressBox) {
      els.myAddressBox.value = address;
    }

    setOutput(address);
  } catch (err) {
    alert(`Address error:\n\n${safeErrorMessage(err)}`);
  }
}

async function handleImportAddress() {
  try {
    let pasted = "";

    if (els.importAddressBox) pasted = els.importAddressBox.value.trim();
    if (!pasted && els.outputBox) pasted = els.outputBox.value.trim();
    if (!pasted && els.decryptInput) pasted = els.decryptInput.value.trim();

    if (!pasted) throw new Error("Paste a SECUREADDR block first.");

    const address = await parseAddressAsync(pasted);

    const trust = confirm(
      "Address parsed successfully.\n\n" +
      "Only mark this contact as verified if you checked the fingerprint through another trusted channel.\n\n" +
      `Name: ${address.name}\n` +
      `Fingerprint: ${address.fingerprint}\n\n` +
      "Mark as verified?"
    ) ? "verified" : "unverified";

    addContact({
      ...address,
      type: "SECURECONTACT",
      trust,
      imported_at: nowIso()
    });

    refreshAll();

    alert(
      `Address imported.\n\n` +
      `Name: ${address.name}\n` +
      `Fingerprint: ${address.fingerprint}\n` +
      `Trust: ${trust}`
    );
  } catch (err) {
    alert(`Import error:\n\n${safeErrorMessage(err)}`);
  }
}

function addContact(contact) {
  validateContact(contact);

  const key = makeContactKey(contact.fingerprint);
  const book = getAddressBook();

  book[key] = {
    type: "SECURECONTACT",
    version: APP_VERSION,
    app: APP_NAME,
    imported_at: contact.imported_at || nowIso(),
    trust: contact.trust || "unverified",
    name: contact.name,
    email: contact.email || "",
    fingerprint: contact.fingerprint,
    encryption_public_key: contact.encryption_public_key,
    signing_public_key: contact.signing_public_key
  };

  setAddressBook(book);
}

async function parseAddressAsync(addressBlob) {
  assertMaxLength(addressBlob, MAX_ADDRESS_CHARS, "Address");

  const cleaned = addressBlob.trim();
  const prefix = `SECUREADDR:v${APP_VERSION}:`;

  if (!cleaned.startsWith(prefix)) {
    throw new Error(`Address must start with ${prefix}`);
  }

  const encoded = cleaned.slice(prefix.length);
  const address = b64ToJsonStrict(encoded, "Address payload");

  validateAddressObject(address);

  const encryptionSpki = pemToDer(address.encryption_public_key);
  const signingSpki = pemToDer(address.signing_public_key);

  await importPublicEncryptionKey(address.encryption_public_key);
  await importPublicSigningKey(address.signing_public_key);

  const calculated = await combinedFingerprint(encryptionSpki, signingSpki);

  if (address.fingerprint !== calculated) {
    throw new Error("Address fingerprint does not match the included public keys.");
  }

  return address;
}

function handleVerifySelectedContact() {
  try {
    const key = els.recipientSelect?.value;
    if (!key) throw new Error("Select a contact first.");

    const book = getAddressBook();
    const contact = book[key];
    if (!contact) throw new Error("Selected contact was not found.");

    const ok = confirm(
      "Mark this contact as verified only if you checked this fingerprint through a trusted channel.\n\n" +
      `${contact.name}\n${contact.fingerprint}\n\n` +
      "Mark as verified?"
    );

    if (!ok) return;

    contact.trust = "verified";
    book[key] = contact;
    setAddressBook(book);
    refreshAll();
  } catch (err) {
    alert(`Verification error:\n\n${safeErrorMessage(err)}`);
  }
}

function handleDeleteAddress() {
  const key = els.recipientSelect?.value;

  if (!key) {
    alert("Select an address first.");
    return;
  }

  const book = getAddressBook();
  const contact = book[key];

  if (!contact) {
    alert("Selected address was not found.");
    return;
  }

  const ok = confirm(`Delete selected address?\n\n${contact.name}\n${contact.fingerprint}`);

  if (!ok) return;

  delete book[key];
  setAddressBook(book);
  refreshAll();
}

function getSelectedRecipient() {
  const key = els.recipientSelect?.value;

  if (!key) throw new Error("No recipient selected. Import or create an address first.");

  const book = getAddressBook();
  const recipient = book[key];

  if (!recipient) throw new Error("Selected recipient was not found.");

  validateContact(recipient);

  if (recipient.trust !== "verified") {
    const ok = confirm(
      "This recipient is not marked as verified.\n\n" +
      "Encrypting to an unverified key can send the message to an attacker if the address was substituted.\n\n" +
      `Recipient: ${recipient.name}\n` +
      `Fingerprint: ${recipient.fingerprint}\n\n` +
      "Continue anyway?"
    );

    if (!ok) throw new Error("Encryption cancelled because recipient is unverified.");
  }

  return recipient;
}

function findContactByFingerprint(fingerprint) {
  assertFingerprint(fingerprint, "Fingerprint");

  const book = getAddressBook();
  const contact = book[fingerprint];

  if (!contact) return null;

  validateContact(contact);
  return contact;
}

/* Encrypt/decrypt */

async function handleEncrypt() {
  try {
    ensureWebCrypto();

    const plaintext = els.messageInput?.value || "";
    assertMaxLength(plaintext, MAX_PLAINTEXT_CHARS, "Plaintext");

    if (!plaintext.trim()) throw new Error("Write a message first.");

    const identity = getPublicIdentity();

    if (!identity) throw new Error("No identity exists. Create an identity first.");

    if (!unlockedPrivateKeysExist()) {
      await unlockPrivateKeysFromPrompt();
    }

    const recipient = getSelectedRecipient();
    const encrypted = await encryptAndSignMessage(plaintext, recipient);

    setOutput(encrypted);
  } catch (err) {
    alert(`Encryption error:\n\n${safeErrorMessage(err)}`);
  }
}

async function handleDecrypt() {
  try {
    ensureWebCrypto();

    const blob = els.decryptInput?.value.trim() || "";

    if (!blob) throw new Error("Paste a SECUREMSG block first.");

    if (!unlockedPrivateKeysExist()) {
      await unlockPrivateKeysFromPrompt();
    }

    const decrypted = await decryptAndVerifyMessage(blob);

    if (els.decryptedOutput) {
      els.decryptedOutput.value = decrypted;
    }
  } catch (err) {
    alert(`Decrypt error:\n\n${safeErrorMessage(err)}`);
  }
}

async function unlockPrivateKeysFromPrompt() {
  if (unlockedPrivateKeysExist()) return;

  if (!memoryState.encryptedPrivateBackup) {
    const ok = confirm(
      "Your private key is not unlocked in memory.\n\n" +
      "Import your encrypted private-key backup file now?"
    );

    if (!ok) throw new Error("Private key is locked.");

    await handleImportEncryptedPrivateBackup();
    return;
  }

  const password = await askRuntimePassword("Private key password");
  const privateBundle = await decryptPrivateBundle(memoryState.encryptedPrivateBackup, password);
  const identity = getPublicIdentity();

  if (!identity) throw new Error("No public identity exists.");

  await unlockPrivateKeysFromBundle(privateBundle, identity);
}

async function encryptAndSignMessage(plaintext, recipient) {
  const identity = getPublicIdentity();

  if (!identity) throw new Error("No identity exists.");

  validatePublicIdentity(identity);
  validateContact(recipient);

  if (!unlockedPrivateKeysExist()) throw new Error("Private signing key is locked.");

  if (memoryState.unlockedFingerprint !== identity.fingerprint) {
    throw new Error("Unlocked private key does not match current identity.");
  }

  const recipientEncryptionPublicKey = await importPublicEncryptionKey(recipient.encryption_public_key);

  const protectedHeader = {
    type: "SECUREMSG",
    version: APP_VERSION,
    app: APP_NAME,
    algorithm: MESSAGE_ALGORITHM,
    message_id: bytesToHex(crypto.getRandomValues(new Uint8Array(16))),
    created_at: nowIso(),
    sender_fingerprint: identity.fingerprint,
    recipient_fingerprint: recipient.fingerprint
  };

  const aad = canonicalJsonBytes(protectedHeader);

  const aesKey = await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );

  const rawAesKeyBytes = new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  let encryptedAesKey;
  let ciphertext;

  try {
    ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: aad
      },
      aesKey,
      new TextEncoder().encode(plaintext)
    );

    encryptedAesKey = await crypto.subtle.encrypt(
      {
        name: "RSA-OAEP",
        label: aad
      },
      recipientEncryptionPublicKey,
      rawAesKeyBytes
    );
  } finally {
    wipeBytes(rawAesKeyBytes);
  }

  const signedBody = {
    protected_header: protectedHeader,
    encrypted_key: arrayBufferToB64(encryptedAesKey),
    nonce: bytesToB64(nonce),
    ciphertext: arrayBufferToB64(ciphertext)
  };

  const signature = await crypto.subtle.sign(
    {
      name: "RSA-PSS",
      saltLength: 32
    },
    memoryState.signingPrivateKey,
    canonicalJsonBytes(signedBody)
  );

  const packageData = {
    type: "SECUREMSGPACKAGE",
    version: APP_VERSION,
    app: APP_NAME,
    signed_body: signedBody,
    signature: arrayBufferToB64(signature)
  };

  return `SECUREMSG:v${APP_VERSION}:${jsonToB64(packageData)}`;
}

async function decryptAndVerifyMessage(blob) {
  assertMaxLength(blob, MAX_MESSAGE_CHARS, "Message");

  const identity = getPublicIdentity();

  if (!identity) throw new Error("No identity exists. Create an identity first.");

  validatePublicIdentity(identity);

  if (!unlockedPrivateKeysExist()) throw new Error("Private decryption key is locked.");

  if (memoryState.unlockedFingerprint !== identity.fingerprint) {
    throw new Error("Unlocked private key does not match current identity.");
  }

  const cleaned = blob.trim();
  const prefix = `SECUREMSG:v${APP_VERSION}:`;

  if (!cleaned.startsWith(prefix)) {
    throw new Error(`Message must start with ${prefix}`);
  }

  const encoded = cleaned.slice(prefix.length);
  const packageData = b64ToJsonStrict(encoded, "Message package");

  validateMessagePackage(packageData);

  const signedBody = packageData.signed_body;
  const protectedHeader = signedBody.protected_header;

  if (protectedHeader.recipient_fingerprint !== identity.fingerprint) {
    throw new Error(
      "This message is not encrypted for your current identity.\n\n" +
      `Message recipient fingerprint: ${protectedHeader.recipient_fingerprint}\n` +
      `Your fingerprint: ${identity.fingerprint}`
    );
  }

  const sender = findContactByFingerprint(protectedHeader.sender_fingerprint);

  if (!sender) {
    throw new Error("Sender is not in your address book. Import their address first.");
  }

  const senderFingerprint = await combinedFingerprint(
    pemToDer(sender.encryption_public_key),
    pemToDer(sender.signing_public_key)
  );

  if (protectedHeader.sender_fingerprint !== senderFingerprint) {
    throw new Error("Sender fingerprint does not match their imported public keys.");
  }

  const senderSigningPublicKey = await importPublicSigningKey(sender.signing_public_key);

  const valid = await crypto.subtle.verify(
    {
      name: "RSA-PSS",
      saltLength: 32
    },
    senderSigningPublicKey,
    b64ToBytesStrict(packageData.signature, "Signature"),
    canonicalJsonBytes(signedBody)
  );

  if (!valid) throw new Error("Invalid signature. Message may be forged or modified.");

  const aad = canonicalJsonBytes(protectedHeader);

  const rawAesKey = await crypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
      label: aad
    },
    memoryState.encryptionPrivateKey,
    b64ToBytesStrict(signedBody.encrypted_key, "Encrypted AES key")
  );

  const rawAesKeyBytes = new Uint8Array(rawAesKey);

  let plaintextBytes;

  try {
    const aesKey = await crypto.subtle.importKey(
      "raw",
      rawAesKeyBytes,
      {
        name: "AES-GCM"
      },
      false,
      ["decrypt"]
    );

    plaintextBytes = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: b64ToBytesStrict(signedBody.nonce, "Message nonce"),
        additionalData: aad
      },
      aesKey,
      b64ToBytesStrict(signedBody.ciphertext, "Ciphertext")
    );
  } finally {
    wipeBytes(rawAesKeyBytes);
  }

  const plaintext = new TextDecoder().decode(plaintextBytes);

  return (
    `From fingerprint: ${protectedHeader.sender_fingerprint}\n` +
    `Signature: VALID\n` +
    `Message ID: ${protectedHeader.message_id}\n` +
    `Created: ${protectedHeader.created_at}\n` +
    `Recipient fingerprint: ${protectedHeader.recipient_fingerprint}\n\n` +
    plaintext
  );
}

/* Private backup */

async function encryptPrivateBundle(privateBundle, password) {
  validatePlainPrivateBundle(privateBundle);

  const salt = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const key = await derivePasswordKey(password, salt);

  const header = {
    type: "SECUREPRIVATE",
    version: APP_VERSION,
    app: APP_NAME,
    algorithm: PRIVATE_BUNDLE_ALGORITHM,
    kdf: "PBKDF2-SHA256",
    iterations: PBKDF2_ITERATIONS,
    encryption: "AES-256-GCM",
    fingerprint: privateBundle.fingerprint,
    created_at: nowIso(),
    salt: bytesToB64(salt),
    nonce: bytesToB64(nonce)
  };

  const aad = canonicalJsonBytes(header);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: aad
    },
    key,
    new TextEncoder().encode(JSON.stringify(privateBundle))
  );

  const packageData = {
    header,
    ciphertext: arrayBufferToB64(ciphertext)
  };

  return `SECUREPRIVATE:v${APP_VERSION}:${jsonToB64(packageData)}`;
}

async function decryptPrivateBundle(blob, password) {
  assertMaxLength(blob, MAX_PRIVATE_BACKUP_CHARS, "Private key backup");

  const cleaned = blob.trim();
  const prefix = `SECUREPRIVATE:v${APP_VERSION}:`;

  if (!cleaned.startsWith(prefix)) {
    throw new Error(`Private backup must start with ${prefix}`);
  }

  const encoded = cleaned.slice(prefix.length);
  const packageData = b64ToJsonStrict(encoded, "Private backup package");

  validatePrivateBackupPackage(packageData);

  const header = packageData.header;
  const salt = b64ToBytesStrict(header.salt, "Private backup salt");
  const nonce = b64ToBytesStrict(header.nonce, "Private backup nonce");
  const ciphertext = b64ToBytesStrict(packageData.ciphertext, "Private backup ciphertext");

  const key = await derivePasswordKey(password, salt);
  const aad = canonicalJsonBytes(header);

  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: aad
      },
      key,
      ciphertext
    );

    const privateBundle = JSON.parse(new TextDecoder().decode(plaintext));
    validatePlainPrivateBundle(privateBundle);

    if (privateBundle.fingerprint !== header.fingerprint) {
      throw new Error("Private backup fingerprint mismatch.");
    }

    return privateBundle;
  } catch {
    throw new Error("Wrong password or damaged encrypted private key backup.");
  }
}

async function derivePasswordKey(password, salt) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("Password is required.");
  }

  if (!(salt instanceof Uint8Array) || salt.length < 16) {
    throw new Error("Invalid KDF salt.");
  }

  const passwordBytes = new TextEncoder().encode(password);

  try {
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
  } finally {
    wipeBytes(passwordBytes);
  }
}

/* Validation */

function validatePublicIdentity(identity) {
  if (!identity || typeof identity !== "object" || Array.isArray(identity)) {
    throw new Error("Invalid public identity.");
  }

  if (identity.type !== "SECUREIDENTITY") throw new Error("Invalid identity type.");
  if (identity.version !== APP_VERSION) throw new Error("Unsupported identity version.");
  if (identity.app !== APP_NAME) throw new Error("Invalid identity app.");

  validateName(identity.name, "Identity name");
  validateEmail(identity.email || "", "Identity email");
  assertFingerprint(identity.fingerprint, "Identity fingerprint");

  validatePem(identity.encryption_public_key, "Encryption public key");
  validatePem(identity.signing_public_key, "Signing public key");
}

function validateAddressObject(address) {
  if (!address || typeof address !== "object" || Array.isArray(address)) {
    throw new Error("Invalid address object.");
  }

  if (address.type !== "SECUREADDR") throw new Error("Invalid address type.");
  if (address.version !== APP_VERSION) throw new Error("Unsupported address version.");
  if (address.app !== APP_NAME) throw new Error("Invalid address app.");

  validateName(address.name, "Address name");
  validateEmail(address.email || "", "Address email");
  assertFingerprint(address.fingerprint, "Address fingerprint");

  validatePem(address.encryption_public_key, "Address encryption public key");
  validatePem(address.signing_public_key, "Address signing public key");
}

function validateContact(contact) {
  if (!contact || typeof contact !== "object" || Array.isArray(contact)) {
    throw new Error("Invalid contact.");
  }

  if (contact.type && contact.type !== "SECURECONTACT" && contact.type !== "SECUREADDR") {
    throw new Error("Invalid contact type.");
  }

  validateName(contact.name, "Contact name");
  validateEmail(contact.email || "", "Contact email");
  assertFingerprint(contact.fingerprint, "Contact fingerprint");

  validatePem(contact.encryption_public_key, "Contact encryption public key");
  validatePem(contact.signing_public_key, "Contact signing public key");

  const trust = contact.trust || "unverified";

  if (!["verified", "unverified", "revoked"].includes(trust)) {
    throw new Error("Invalid contact trust state.");
  }

  if (trust === "revoked") {
    throw new Error("Contact key is revoked.");
  }
}

function validatePlainPrivateBundle(bundle) {
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) {
    throw new Error("Invalid private bundle.");
  }

  if (bundle.type !== "SECUREPRIVATEPLAINTEXT") throw new Error("Invalid private bundle type.");
  if (bundle.version !== APP_VERSION) throw new Error("Unsupported private bundle version.");
  if (bundle.app !== APP_NAME) throw new Error("Invalid private bundle app.");

  assertFingerprint(bundle.fingerprint, "Private bundle fingerprint");

  if (typeof bundle.encryption_private_pkcs8 !== "string") {
    throw new Error("Missing encryption private key.");
  }

  if (typeof bundle.signing_private_pkcs8 !== "string") {
    throw new Error("Missing signing private key.");
  }

  b64ToBytesStrict(bundle.encryption_private_pkcs8, "Encryption private key");
  b64ToBytesStrict(bundle.signing_private_pkcs8, "Signing private key");
}

function validatePrivateBackupPackage(packageData) {
  if (!packageData || typeof packageData !== "object" || Array.isArray(packageData)) {
    throw new Error("Invalid private backup package.");
  }

  const header = packageData.header;

  if (!header || typeof header !== "object" || Array.isArray(header)) {
    throw new Error("Invalid private backup header.");
  }

  if (header.type !== "SECUREPRIVATE") throw new Error("Invalid private backup type.");
  if (header.version !== APP_VERSION) throw new Error("Unsupported private backup version.");
  if (header.app !== APP_NAME) throw new Error("Invalid private backup app.");
  if (header.algorithm !== PRIVATE_BUNDLE_ALGORITHM) throw new Error("Unsupported private backup algorithm.");
  if (header.kdf !== "PBKDF2-SHA256") throw new Error("Unsupported private backup KDF.");
  if (header.encryption !== "AES-256-GCM") throw new Error("Unsupported private backup encryption.");
  if (header.iterations !== PBKDF2_ITERATIONS) throw new Error("Unexpected private backup KDF iterations.");

  assertFingerprint(header.fingerprint, "Private backup fingerprint");

  const salt = b64ToBytesStrict(header.salt, "Private backup salt");
  const nonce = b64ToBytesStrict(header.nonce, "Private backup nonce");

  if (salt.length !== 32) throw new Error("Invalid private backup salt length.");
  if (nonce.length !== 12) throw new Error("Invalid private backup nonce length.");

  b64ToBytesStrict(packageData.ciphertext, "Private backup ciphertext");
}

function validateMessagePackage(packageData) {
  if (!packageData || typeof packageData !== "object" || Array.isArray(packageData)) {
    throw new Error("Invalid message package.");
  }

  if (packageData.type !== "SECUREMSGPACKAGE") throw new Error("Invalid message package type.");
  if (packageData.version !== APP_VERSION) throw new Error("Unsupported message package version.");
  if (packageData.app !== APP_NAME) throw new Error("Invalid message package app.");

  const signedBody = packageData.signed_body;

  if (!signedBody || typeof signedBody !== "object" || Array.isArray(signedBody)) {
    throw new Error("Invalid signed body.");
  }

  validateProtectedHeader(signedBody.protected_header);

  const encryptedKey = b64ToBytesStrict(signedBody.encrypted_key, "Encrypted AES key");
  const nonce = b64ToBytesStrict(signedBody.nonce, "Message nonce");
  const ciphertext = b64ToBytesStrict(signedBody.ciphertext, "Ciphertext");
  const signature = b64ToBytesStrict(packageData.signature, "Signature");

  if (encryptedKey.length < 256) throw new Error("Encrypted AES key is too short.");
  if (nonce.length !== 12) throw new Error("Invalid message nonce length.");
  if (ciphertext.length < 16) throw new Error("Ciphertext is too short.");
  if (signature.length < 256) throw new Error("Signature is too short.");
}

function validateProtectedHeader(header) {
  if (!header || typeof header !== "object" || Array.isArray(header)) {
    throw new Error("Invalid protected header.");
  }

  if (header.type !== "SECUREMSG") throw new Error("Invalid message type.");
  if (header.version !== APP_VERSION) throw new Error("Unsupported message version.");
  if (header.app !== APP_NAME) throw new Error("Invalid message app.");
  if (header.algorithm !== MESSAGE_ALGORITHM) throw new Error("Unsupported message algorithm.");

  if (!/^[a-f0-9]{32}$/.test(header.message_id)) {
    throw new Error("Invalid message ID.");
  }

  if (!ISO_DATE_RE.test(header.created_at)) {
    throw new Error("Invalid message timestamp.");
  }

  assertFingerprint(header.sender_fingerprint, "Sender fingerprint");
  assertFingerprint(header.recipient_fingerprint, "Recipient fingerprint");
}

function validateName(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be text.`);
  if (!value.trim()) throw new Error(`${label} is required.`);
  if (value.length > MAX_NAME_CHARS) throw new Error(`${label} is too long.`);
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} contains invalid control characters.`);
}

function validateEmail(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be text.`);
  if (value.length > MAX_EMAIL_CHARS) throw new Error(`${label} is too long.`);
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} contains invalid control characters.`);
}

function validatePem(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be text.`);
  if (value.length > 10000) throw new Error(`${label} is too large.`);
  if (!value.includes("-----BEGIN PUBLIC KEY-----") || !value.includes("-----END PUBLIC KEY-----")) {
    throw new Error(`${label} is not a public PEM key.`);
  }
}

function assertMaxLength(value, max, label) {
  if (typeof value !== "string") throw new Error(`${label} must be text.`);
  if (value.length > max) throw new Error(`${label} is too large.`);
}

function assertFingerprint(value, label) {
  if (typeof value !== "string" || !FINGERPRINT_RE.test(value)) {
    throw new Error(`${label} is not a valid fingerprint.`);
  }
}

/* Crypto helpers */

async function importPublicEncryptionKey(pem) {
  validatePem(pem, "Encryption public key");

  return crypto.subtle.importKey(
    "spki",
    pemToDer(pem),
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    false,
    ["encrypt"]
  );
}

async function importPublicSigningKey(pem) {
  validatePem(pem, "Signing public key");

  return crypto.subtle.importKey(
    "spki",
    pemToDer(pem),
    {
      name: "RSA-PSS",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );
}

async function combinedFingerprint(encryptionSpki, signingSpki) {
  const encryptionBytes = toUint8Array(encryptionSpki);
  const signingBytes = toUint8Array(signingSpki);

  const domain = new TextEncoder().encode(`${APP_NAME}:fingerprint:v${APP_VERSION}:`);
  const combined = new Uint8Array(domain.length + encryptionBytes.length + signingBytes.length);

  combined.set(domain, 0);
  combined.set(encryptionBytes, domain.length);
  combined.set(signingBytes, domain.length + encryptionBytes.length);

  const digest = await crypto.subtle.digest("SHA-256", combined);
  return bytesToHex(new Uint8Array(digest));
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

/* Encoding */

function derToPem(buffer, label) {
  const b64 = arrayBufferToB64(buffer);
  const lines = b64.match(/.{1,64}/g)?.join("\n") || "";
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function pemToDer(pem) {
  if (typeof pem !== "string") throw new Error("PEM must be text.");

  const clean = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");

  return b64ToBytesStrict(clean, "PEM body");
}

function jsonToB64(obj) {
  return bytesToB64(new TextEncoder().encode(JSON.stringify(obj)));
}

function b64ToJsonStrict(b64, label) {
  const bytes = b64ToBytesStrict(b64, label);
  const text = new TextDecoder().decode(bytes);

  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
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

function b64ToBytesStrict(b64, label = "base64") {
  if (typeof b64 !== "string") {
    throw new Error(`${label} must be a string.`);
  }

  const clean = b64.trim();

  if (!clean || clean.length % 4 !== 0) {
    throw new Error(`${label} is not valid base64.`);
  }

  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
    throw new Error(`${label} is not valid base64.`);
  }

  let binary;

  try {
    binary = atob(clean);
  } catch {
    throw new Error(`${label} could not be decoded.`);
  }

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

function toUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new Error("Expected bytes.");
}

/* File, clipboard, password, misc */

function readAndClearPasswordInputs(passwordElement, confirmElement) {
  const password = passwordElement?.value || "";
  const confirmPassword = confirmElement?.value || "";

  if (passwordElement) passwordElement.value = "";
  if (confirmElement) confirmElement.value = "";

  return { password, confirmPassword };
}

function askRuntimePassword(title) {
  return new Promise((resolve, reject) => {
    if (!els.passwordDialog || !els.runtimePassword || !els.confirmPasswordBtn) {
      reject(new Error("Password dialog is missing from the page."));
      return;
    }

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
      els.runtimePassword.value = "";

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
        els.runtimePassword.value = "";
        reject(new Error("Password prompt cancelled."));
      }
    };

    els.confirmPasswordBtn.addEventListener("click", onConfirm);
    els.passwordDialog.addEventListener("close", onClose, { once: true });

    els.passwordDialog.showModal();
    els.runtimePassword.focus();
  });
}

function downloadTextFile(filename, text) {
  const blob = new Blob([text], {
    type: "text/plain;charset=utf-8"
  });

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  link.rel = "noopener";

  document.body.appendChild(link);
  link.click();
  link.remove();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function chooseTextFile(accept = ".txt,text/plain") {
  return new Promise((resolve, reject) => {
    const input = document.createElement("input");

    input.type = "file";
    input.accept = accept;

    input.addEventListener("change", async () => {
      const file = input.files?.[0];

      if (!file) {
        reject(new Error("No file selected."));
        return;
      }

      if (file.size > MAX_PRIVATE_BACKUP_CHARS) {
        reject(new Error("Selected file is too large."));
        return;
      }

      try {
        resolve(await file.text());
      } catch {
        reject(new Error("Could not read selected file."));
      }
    }, { once: true });

    input.click();
  });
}

async function copyText(text, label = "text") {
  if (!text) {
    alert("Nothing to copy.");
    return;
  }

  if (label === "decrypted message") {
    const ok = confirm("Copy decrypted plaintext to clipboard?\n\nClipboard history tools may retain it.");
    if (!ok) return;
  }

  await navigator.clipboard.writeText(text);
}

function cleanName(value) {
  const cleaned = String(value || "").trim().replace(/\s+/g, " ");
  validateName(cleaned, "Name");
  return cleaned;
}

function cleanEmail(value) {
  const cleaned = String(value || "").trim();
  validateEmail(cleaned, "Email");
  return cleaned;
}

function shortFingerprint(fingerprint) {
  if (!fingerprint || fingerprint.length < 16) return fingerprint || "";
  return `${fingerprint.slice(0, 8)}...${fingerprint.slice(-8)}`;
}

function nowIso() {
  return new Date().toISOString();
}

function wipeBytes(bytes) {
  if (bytes && typeof bytes.fill === "function") {
    bytes.fill(0);
  }
}

function safeErrorMessage(err) {
  if (!err || typeof err.message !== "string") {
    return "Unknown error.";
  }

  return err.message.slice(0, 1000);
}
