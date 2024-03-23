const downloadBtn = document.querySelector("#downloadBtn");
const continueBtn = document.querySelector("#continueBtn");
downloadBtn.addEventListener("click", () => {
  continueBtn.setAttribute("disabled", true);
  setTimeout(() => {
    downloadBtn.classList.add("invisible");
    continueBtn.classList.remove("invisible");
  }, 100);
  setTimeout(() => {
    continueBtn.removeAttribute("disabled");
  }, 500)
});