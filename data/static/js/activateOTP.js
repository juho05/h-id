const secretKey = document.querySelector("#otp-secret");
secretKey.addEventListener("click", () => {
  navigator.clipboard.writeText(secretKey.textContent).then(() => {
    alert("Copied!")
  });
});