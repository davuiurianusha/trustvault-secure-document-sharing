document.addEventListener("DOMContentLoaded", () => {
  const fileInput = document.getElementById("file");
  const selectedFile = document.getElementById("selected-file");
  if (fileInput && selectedFile) {
    fileInput.addEventListener("change", () => {
      const file = fileInput.files && fileInput.files[0];
      selectedFile.textContent = file
        ? `${file.name} · ${(file.size / 1024).toFixed(1)} KB`
        : "No file selected";
      if (file && file.size > 16 * 1024 * 1024) {
        selectedFile.textContent += " — too large (max 16 MB)";
        selectedFile.classList.add("file-error");
      } else {
        selectedFile.classList.remove("file-error");
      }
    });
  }
  document.querySelectorAll("form[data-confirm]").forEach(form => {
    form.addEventListener("submit", event => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
});
