<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />

  <meta
    http-equiv="Content-Security-Policy"
    content="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; connect-src 'none'; upgrade-insecure-requests"
  />

  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="referrer" content="no-referrer" />
  <title>Secure Message Encryptor</title>
  <link rel="stylesheet" href="style.css" />
</head>

<body>
  <main class="app-shell">
    <section class="hero card">
      <div>
        <h1>Secure Message Encryptor</h1>
        <p>
          Local-only browser encryption app. Create an identity, export your encrypted private-key backup,
          exchange public addresses, encrypt messages, and verify signatures.
        </p>
      </div>

      <div id="statusBox" class="status-box" aria-live="polite">
        Loading status...
      </div>
    </section>

    <section class="notice card">
      <strong>Usage:</strong>
      <br>1. Click on "Create identity" (under "Identity & Addresses") to create a new identity.
      <br>2. In the pop up window that will open, add your name, email address (optional), and password. After doing so, a private key file will be downloaded by your browser.
      <br>3. Click on "Import private key" under Identity & Addresses. Select the key file that you just downloaded to import your private key.
      <br>4. You will now have a public address (middle text box under "Identity & Addresses"). Share this public address with your recipient to add you to their contact list.
      <br>5. At the same time, ask for your recipient's public address via a secure channel, and past it in "import public address".
      <br>6. Click on the "Import address" button to import your contact's address.
      <br>7. Use the Encryption section to write your plain text message, select your recipient from the "Encrypt to" list, and click on "Encrypt and sign".
      <br>8. Your secure message will appear under the "Encrypted output" textbox. You can send this to your contact externally via a secure channel.
      <br>9. To decrypt a message, have your contact send you their encrypted message. Then, paste it in the Decryption section, and click on "Decrypt and verify". The decrypted message will then appear in the Decrypted message textbox.
    </section>

    <section class="controls card">
      <div class="control-grid">
        <button id="showAddressBtn">Show my address</button>
        <button id="verifyContactBtn">Verify selected contact</button>
        <button id="deleteAddressBtn" class="danger">Delete selected contact</button>
        <button id="refreshBtn">Refresh</button>
        <button id="clearOutputBtn">Clear outputs</button>
        <button id="clearLocalDataBtn" class="danger">Clear local public data</button>
      </div>
    </section>

    <section class="main-grid">
      <section class="card panel identity-addresses-panel">
        <h3>Identity &amp; Addresses</h3>

        <section class="card panel keys-panel">
          <div class="panel-header">
            <h2>Public identity</h2>
          </div>

          <div class="identity-button-grid">
            <button id="copyPublicKeyBtn" class="small">Copy public keys</button>
            <button id="createIdentityBtn" class="primary">Create identity</button>
            <button id="exportPrivateKeyBtn">Export private backup</button>
            <button id="importPrivateKeyBtn">Import private key</button>
            <button id="lockPrivateKeyBtn">Lock private key</button>
          </div>

          <div class="keys-grid">
            <div>
              <label for="publicKeyBox">Public key</label>
              <textarea
                id="publicKeyBox"
                readonly
                spellcheck="false"
                placeholder="Public keys appear here."
              ></textarea>
            </div>
          </div>

          <textarea id="privateKeyBox" hidden readonly spellcheck="false"></textarea>
        </section>

        <section class="card panel address-panel">
          <div class="panel-header">
            <h2>My public address</h2>
          </div>

          <textarea
            id="myAddressBox"
            readonly
            spellcheck="false"
            placeholder="Your SECUREADDR block appears here after creating an identity."
          ></textarea>
        </section>

        <section class="card panel import-panel">
          <div class="panel-header">
            <h2>Import public address</h2>
          </div>

          <textarea
            id="importAddressBox"
            spellcheck="false"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            placeholder="Paste someone else's SECUREADDR block here."
          ></textarea>

          <button id="importAddressBtn">Import address</button>
        </section>
      </section>

      <section class="card panel encrypt-decrypt-panel">
        <h3>Encryption and Decryption</h3>

        <section class="crypto-group encryption-group">
          <h2>Encryption</h2>

          <section class="card panel message-panel">
            <div class="panel-header">
              <h2>Message to encrypt</h2>
              <button id="copyEncryptedBtn" class="small">Copy encrypted</button>
            </div>

            <textarea
              id="messageInput"
              spellcheck="false"
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              placeholder="Write normal text here..."
            ></textarea>

            <div class="button-row">
              <label for="recipientSelect">Encrypt to:</label>
              <select id="recipientSelect" aria-label="Recipient address"></select>
              <button id="encryptBtn" class="primary">Encrypt and sign</button>
            </div>
          </section>

          <section class="card panel output-panel">
            <div class="panel-header">
              <h2>Encrypted output / shared data</h2>
              <button id="copyAddressBtn" class="small">Copy address</button>
            </div>

            <textarea
              id="outputBox"
              spellcheck="false"
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              placeholder="Encrypted messages or your address appear here."
            ></textarea>
          </section>
        </section>

        <section class="crypto-group decryption-group">
          <h2>Decryption</h2>

          <section class="card panel decrypt-input-panel">
            <div class="panel-header">
              <h2>Paste encrypted SECUREMSG</h2>
            </div>

            <textarea
              id="decryptInput"
              spellcheck="false"
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              placeholder="Paste SECUREMSG:v3:... here."
            ></textarea>

            <div class="button-row">
              <button id="decryptBtn" class="primary">Decrypt and verify</button>
              <button id="decryptTopBtn">Decrypt pasted message</button>
            </div>
          </section>

          <section class="card panel decrypted-panel">
            <div class="panel-header">
              <h2>Decrypted message</h2>
              <button id="copyDecryptedBtn" class="small">Copy decrypted</button>
            </div>

            <textarea
              id="decryptedOutput"
              readonly
              spellcheck="false"
              placeholder="Decrypted message and signature status appear here."
            ></textarea>
          </section>
        </section>
      </section>
    </section>
  </main>

  <dialog id="identityDialog" class="modal">
    <form method="dialog" class="modal-content">
      <h2>Create identity</h2>

      <label>
        Name
        <input
          id="identityName"
          type="text"
          maxlength="80"
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck="false"
        />
      </label>

      <label>
        Email address, optional
        <input
          id="identityEmail"
          type="email"
          maxlength="254"
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck="false"
          placeholder="example@email.com"
        />
      </label>

      <label>
        Private backup password
        <input
          id="identityPassword"
          type="password"
          autocomplete="new-password"
          autocorrect="off"
          autocapitalize="off"
          spellcheck="false"
        />
      </label>

      <label>
        Confirm private backup password
        <input
          id="identityPasswordConfirm"
          type="password"
          autocomplete="new-password"
          autocorrect="off"
          autocapitalize="off"
          spellcheck="false"
        />
      </label>

      <p class="small-text">
        This password encrypts your private-key backup file. The app will download that file and will not store it in localStorage.
      </p>

      <div class="modal-actions">
        <button value="cancel">Cancel</button>
        <button id="confirmCreateIdentityBtn" value="default" class="primary">Create and download backup</button>
      </div>
    </form>
  </dialog>

  <dialog id="passwordDialog" class="modal">
    <form method="dialog" class="modal-content">
      <h2 id="passwordDialogTitle">Private key password</h2>

      <label>
        Password
        <input
          id="runtimePassword"
          type="password"
          autocomplete="current-password"
          autocorrect="off"
          autocapitalize="off"
          spellcheck="false"
        />
      </label>

      <div class="modal-actions">
        <button value="cancel">Cancel</button>
        <button id="confirmPasswordBtn" value="default" class="primary">Continue</button>
      </div>
    </form>
  </dialog>

  <script src="app.js"></script>
</body>
</html>
