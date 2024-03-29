function encode(buffer) {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decode(base64urlString) {
  const base64 = base64urlString.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

const form = document.getElementById("create-passkey-form");
const nameInput = document.getElementById("name");
const passwordInput = document.getElementById("password");
const wrongPassword = document.getElementById("wrong-password");
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await fetch("/user/passkey/create/begin", {
    method: "POST",
    body: JSON.stringify({
      name: nameInput.value,
      password: passwordInput.value
    })
  });
  if (res.status === 401) {
    passwordInput.classList.add("invalid-field");
    wrongPassword.classList.remove("invisible");
    return;
  } else if (res.status !== 200) {
    alert("ERROR: status: " + res.status);
    return;
  }
  passwordInput.classList.remove("invalid-field");
  wrongPassword.classList.add("invisible");
  const authOptions = await res.json();
  authOptions.publicKey.user.id = decode(authOptions.publicKey.user.id);
  authOptions.publicKey.challenge = decode(authOptions.publicKey.challenge);
  const webAuthnResponse = await navigator.credentials.create({
    publicKey: {
      ...authOptions.publicKey,
      userVerification: "preferred",
    }
  });
  if (!webAuthnResponse) return;
  const res2 = await fetch("/user/passkey/create/finish", {
    method: "POST",
    body: JSON.stringify({
      id: webAuthnResponse.id,
      type: webAuthnResponse.type,
      rawId: encode(webAuthnResponse.rawId),
      response: {
        attestationObject: encode(webAuthnResponse.response.attestationObject),
        clientDataJSON: encode(webAuthnResponse.response.clientDataJSON)
      }
    })
  });
  if (res2.status !== 201) {
    alert("ERROR: status: " + res2.status);
    return;
  }
  location.href = "/user/passkey"
}, true);
