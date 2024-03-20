const secretKey = document.querySelector("#otp-secret");
secretKey.addEventListener("click", () => {
  navigator.clipboard.writeText(secretKey.value).then(() => {
    alert("Copied!")
  });
});