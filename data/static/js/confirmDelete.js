const cancelBtn = document.querySelector("#cancel-btn");
cancelBtn.addEventListener("click", () => {
  window.history.back();
});