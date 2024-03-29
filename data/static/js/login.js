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

const passkeyBtn = document.getElementById("use-passkey-btn");
const errorList = document.getElementById("login-error-list");
const invalidCredentialsError = document.getElementById("invalid-credentials");
passkeyBtn.addEventListener("click", async (e) => {
  e.preventDefault()
  console.log("passkey")
  errorList.replaceChildren(invalidCredentialsError)
  errorList.classList.add("invisible");
  invalidCredentialsError.classList.add("invisible");
  console.log("passkey begin")
  const res = await fetch("/user/passkey/verify/begin", { method: "POST" });
  if (res.status !== 200) {
    alert("ERROR: status: " + res.status);
    return;
  }
  const authOptions = await res.json();
  authOptions.publicKey.challenge = decode(authOptions.publicKey.challenge);
  const credential = await navigator.credentials.get({
    publicKey: authOptions.publicKey
  });
  console.log("passkey finish")
  const res2 = await fetch("/user/passkey/verify/finish", {
    method: "POST",
    body: JSON.stringify({
      id: credential.id,
      type: credential.type,
      rawId: encode(credential.rawId),
      response: {
        authenticatorData: encode(credential.response.authenticatorData),
        signature: encode(credential.response.signature),
        userHandle: encode(credential.response.userHandle),
        clientDataJSON: encode(credential.response.clientDataJSON)
      }
    })
  });
  if (res2.status !== 200) {
    if (res2.status === 401) {
      errorList.classList.remove("invisible");
      invalidCredentialsError.classList.remove("invisible");
    } else {
      alert("ERROR: status: " + res2.status)
    }
    return;
  }
  location.href = "/";
}, true);