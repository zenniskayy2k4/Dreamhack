document.addEventListener("DOMContentLoaded", () => {
  const dials = document.querySelectorAll(".dial");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

  dials.forEach((dial, index) => {
    const upArrow = dial.querySelector(".up-arrow");
    const downArrow = dial.querySelector(".down-arrow");
    const letterDisplay = dial.querySelector(".letter");
    const hiddenInput = dial.querySelector(`input[type="hidden"]`);

    let currentLetterIndex = 0;

    upArrow.addEventListener("click", () => {
      currentLetterIndex =
        (currentLetterIndex - 1 + alphabet.length) % alphabet.length;
      const newLetter = alphabet[currentLetterIndex];
      letterDisplay.textContent = newLetter;
      if (hiddenInput) {
        hiddenInput.value = newLetter;
      }
    });

    downArrow.addEventListener("click", () => {
      currentLetterIndex = (currentLetterIndex + 1) % alphabet.length;
      const newLetter = alphabet[currentLetterIndex];
      letterDisplay.textContent = newLetter;
      if (hiddenInput) {
        hiddenInput.value = newLetter;
      }
    });
    if (hiddenInput) {
      letterDisplay.textContent = hiddenInput.value;
      currentLetterIndex = alphabet.indexOf(hiddenInput.value);
    }
  });
});
