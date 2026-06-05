const APP_NAME = "Secure Message Encryptor";

const STORAGE_KEYS = {
  identity: "securemsg_identity",
  encryptedPrivateKey: "securemsg_encrypted_private_key",
  publicKeyPem: "securemsg_public_key_pem",
  addressBook: "securemsg_address_book"
};

const RSA_MODULUS_LENGTH = 4096;
const PBKDF2_ITERATIONS = 250000;

const els = {};

document.addEventListener("DOMContentLoaded", () => {
  bindElements();
  bindEvents();
  refreshAll();
});

function bindElements() {
  els.statusBox = document.getElementById("statusBox");
  els.recipientSelect = document.getElementById("recipientSelect");

  els.createIdentityBtn = document.getElementById("createIdentityBtn");
  els.showAddressBtn = document.getElementById("showAddressBtn");
  els.importAddressBtn = document.getElementById("importAddressBtn");
  els.deleteAddressBtn = document.getElementById("deleteAddressBtn");
  els.refreshBtn = document.getElementById("refreshBtn");
  els.clearOutputBtn = document.getElementById("clearOutputBtn");

  els.encryptBtn = document.getElementById("encryptBtn");
  els.decryptTopBtn = document.getElementById("decryptTopBtn");

  els.messageInput = document.getElementById("messageInput");
  els.outputBox = document.getElementById("outputBox");
  els.publicKeyBox = document.getElementById("publicKeyBox");
  els.privateKeyBox = document.getElementById("privateKeyBox");
  els.decryptInput = document.getElementById("decryptInput");
  els.decryptedOutput = document.getElementById("decryptedOutput");

  els.identityDialog = document.getElementById("identityDialog");
  els.identityName = document.getElementById("identityName");
  els.identityEmail = document.getElementById("identityEmail");
  els.identityPassword = document.getElementById("identityPassword");
  els.identityPasswordConfirm = document.getElementById("identityPasswordConfirm");
  els.confirmCreateIdentityBtn = document.getElementById("confirmCreateIdentityBtn");

  els.passwordDialog = document.getElementById("passwordDialog");
  els.passwordDialogTitle = document.getElementById("passwordDialogTitle");
  els.runtimePassword = document.getElementById("runtimePassword");
  els.confirmPasswordBtn = document.getElementById("confirmPasswordBtn");
}

function bindEvents() {
  els.createIdentityBtn.addEventListener("click", openIdentityDialog);
  els.confirmCreateIdentityBtn.addEventListener("click", handleCreateIdentity);

  els.showAddressBtn.addEventListener("click", handleShowMyAddress);
  els.importAddressBtn.addEventListener("click", handleImportAddress);
  els.deleteAddressBtn.addEventListener("click", handleDeleteAddress);

  els.refreshBtn.addEventListener("click", refreshAll);
  els.clearOutputBtn.addEventListener("click", () => {
    els.outputBox.value = "";
  });

  els.encryptBtn.addEventListener("click", handleEncrypt);
  els.decryptTopBtn.addEventListener("click", handleDecrypt);
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

function getAddressBook() {
  return storageGetJson(STORAGE_KEYS.addressBook, {});
}

function setAddressBook(book) {
  storageSetJson(STORAGE_KEYS.addressBook, book);
}

function getPublicKeyPem() {
  return localStorage.getItem(STORAGE_KEYS.publicKeyPem) || "";
}

function setPublicKeyPem(pem) {
  localStorage.setItem(STORAGE_KEYS.publicKeyPem, pem);
}

function getEncryptedPrivateKeyBlob() {
  return localStorage.getItem(STORAGE_KEYS.encryptedPrivateKey) || "";
}

function setEncryptedPrivateKeyBlob(blob) {
  localStorage.setItem(STORAGE_KEYS.encryptedPrivateKey, blob);
}

function identityExists() {
  return Boolean(
    getIdentity() &&
    getPublicKeyPem() &&
    getEncryptedPrivateKeyBlob()
  );
}

function makeContactKey(name, fingerprint) {
  return `${name} | ${fingerprint}`;
}

function refreshAll() {
  refreshStatus();
  refreshAddressDropdown();
  refreshKeyBoxes();
}

function refreshStatus() {
  const identity = getIdentity();
  const addressBook = getAddressBook();

  const identityStatus = identity
    ? `${identity.name} | ${identity.fingerprint}`
    : "missing";

  els.statusBox.textContent =
    `Identity: ${identityStatus}\n` +
    `Saved addresses: ${Object.keys(addressBook).length}\n` +
    `Storage: browser localStorage\n` +
    `Crypto: WebCrypto RSA-OAEP + AES-GCM + RSA-PSS`;
}

function refreshAddressDropdown() {
  const addressBook = getAddressBook();
  els.recipientSelect.innerHTML = "";

  const contacts = Object.entries(addressBook)
    .map(([key, contact]) => ({ key, contact }))
    .sort((a, b) => {
      const aName = a.contact.name.toLowerCase();
      const bName = b.contact.name.toLowerCase();
      return aName.localeCompare(bName);
    });

  for (const item of contacts) {
    const emailPart = item.contact.email ? ` <${item.contact.email}>` : "";
    const option = document.createElement("option");
    option.value = item.key;
    option.textContent = `${item.contact.name}${emailPart} | ${item.contact.fingerprint}`;
    els.recipientSelect.appendChild(option);
  }
}

function refreshKeyBoxes() {
  els.publicKeyBox.value = getPublicKeyPem();
  els.privateKeyBox.value = getEncryptedPrivateKeyBlob();
}

function openIdentityDialog() {
  if (identityExists()) {
    const ok = confirm(
      "A local identity already exists.\n\n" +
      "Overwrite it?\n\n" +
      "Warning: old messages encrypted to the old key may become unreadable."
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
    const name = els.identityName.value.trim();
    const email = els.identityEmail.value.trim();
    const password = els.identityPassword.value;
    const confirmPassword = els.identityPasswordConfirm.value;

    if (!name) throw new Error("Name is required.");
    if (!password) throw new Error("Password cannot be empty.");
    if (password !== confirmPassword) throw new Error("Passwords do not match.");

    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: RSA_MODULUS_LENGTH,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );

    const publicSpki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privatePkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    const publicPem = derToPem(publicSpki, "PUBLIC KEY");
    const fingerprint = await fingerprintSpki(publicSpki);

    const encryptedPrivateBlob = await encryptPrivateKeyPkcs8(privatePkcs8, password);

    const identity = {
      name,
      email,
      fingerprint
    };

    setIdentity(identity);
    setPublicKeyPem(publicPem);
    setEncryptedPrivateKeyBlob(encryptedPrivateBlob);

    const address = buildAddressFromIdentity(identity, publicPem);
    addContact(parseAddress(address));

    els.identityDialog.close();
    refreshAll();

    alert(`Identity created for ${name}\n\nFingerprint:\n${fingerprint}`);
  } catch (err) {
    alert(`Identity creation error:\n\n${err.message}`);
  }
}

function buildAddressFromIdentity(identity, publicPem) {
  const addressData = {
    type: "SECUREADDR",
    version: 1,
    name: identity.name,
    email: identity.email || "",
    fingerprint: identity.fingerprint,
    public_key: publicPem
  };

  return `SECUREADDR:v1:${jsonToB64(addressData)}`;
}

function buildMyAddress() {
  const identity = getIdentity();
  const publicPem = getPublicKeyPem();

  if (!identity || !publicPem) {
    throw new Error("No local identity found. Create/register your key first.");
  }

  return buildAddressFromIdentity(identity, publicPem);
}

async function handleShowMyAddress() {
  try {
    els.outputBox.value = buildMyAddress();
  } catch (err) {
    alert(`Address error:\n\n${err.message}`);
  }
}

function handleImportAddress() {
  try {
    let pasted = els.outputBox.value.trim();

    if (!pasted) {
      pasted = els.decryptInput.value.trim();
    }

    if (!pasted) {
      throw new Error("Paste a SECUREADDR:v1:... block into the output box or decrypt input box first.");
    }

    const address = parseAddress(pasted);
    addContact(address);
    refreshAll();

    alert(
      `Address imported:\n\n` +
      `${address.name}\n` +
      `${address.email || ""}\n\n` +
      `Fingerprint:\n${address.fingerprint}`
    );
  } catch (err) {
    alert(`Import error:\n\n${err.message}`);
  }
}

function handleDeleteAddress() {
  const selectedKey = els.recipientSelect.value;

  if (!selectedKey) {
    alert("Select an address first.");
    return;
  }

  const ok = confirm(`Delete this address?\n\n${selectedKey}`);

  if (!ok) return;

  const book = getAddressBook();
  delete book[selectedKey];
  setAddressBook(book);
  refreshAll();
}

function addContact(addressData) {
  const required = ["type", "version", "name", "fingerprint", "public_key"];

  for (const field of required) {
    if (!(field in addressData)) {
      throw new Error(`Address is missing field: ${field}`);
    }
  }

  if (addressData.type !== "SECUREADDR") {
    throw new Error("This is not a SECUREADDR address.");
  }

  const key = makeContactKey(addressData.name, addressData.fingerprint);

  const book = getAddressBook();

  book[key] = {
    name: addressData.name,
    email: addressData.email || "",
    fingerprint: addressData.fingerprint,
    public_key: addressData.public_key
  };

  setAddressBook(book);
}

function parseAddress(addressBlob) {
  const cleaned = addressBlob.trim();

  if (!cleaned.startsWith("SECUREADDR:v1:")) {
    throw new Error("Address must start with SECUREADDR:v1:");
  }

  const encoded = cleaned.split("SECUREADDR:v1:", 2)[1];
  const addressData = b64ToJson(encoded);

  const publicDer = pemToDer(addressData.public_key);
  return crypto.subtle.digest("SHA-256", publicDer).then((digest) => {
    const calculated = bytesToHex(new Uint8Array(digest)).slice(0, 32);

    if (addressData.fingerprint !== calculated) {
      throw new Error("Address fingerprint does not match the included public key.");
    }

    return addressData;
  });
}