document.addEventListener("DOMContentLoaded", function() {
    const checkbox = document.querySelector('input[name="IsVerified"]');
    const passwordInputDiv = document.querySelector('input[name="Password"]').closest('.mb-3');

    passwordInputDiv.style.display = "none";

    checkbox.addEventListener("change", function() {
        if (checkbox.checked) {
            passwordInputDiv.style.display = "block";
        } else {
            passwordInputDiv.style.display = "none";
        }
    });
});