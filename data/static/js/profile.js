const profilePicture = document.querySelector("#profilePicture");
const profilePictureInput = document.querySelector("#profilePictureInput");
const profilePictureSaveHint = document.querySelector("#profilePictureSaveHint");
profilePicture.addEventListener("click", () => {
  profilePictureInput.click();
  profilePictureSaveHint.classList.remove("invisible");
});