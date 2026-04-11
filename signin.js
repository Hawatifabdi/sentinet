// TAB SWITCHING
function switchTab(tab) {
  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".panel");

  tabs.forEach(t => t.classList.remove("active"));
  panels.forEach(p => p.classList.add("hidden"));

  if (tab === "signin") {
    tabs[0].classList.add("active");
    document.getElementById("panel-signin").classList.remove("hidden");
  } else {
    tabs[1].classList.add("active");
    document.getElementById("panel-register").classList.remove("hidden");
  }
}

// SIGN IN
function handleSignIn() {
  const email = document.getElementById("si-email").value;
  const pass = document.getElementById("si-password").value;
  const err = document.getElementById("si-err");

  if (!email || !pass) {
    err.textContent = "Please fill all fields";
    return;
  }

  window.location.href = "index.html";
}

// REGISTER
function handleRegister() {
  const name = document.getElementById("reg-name").value;
  const org = document.getElementById("reg-org").value;
  const pass = document.getElementById("reg-password").value;
  const confirm = document.getElementById("reg-confirm").value;
  const err = document.getElementById("reg-err");

  if (!name || !org || !pass || !confirm) {
    err.textContent = "Fill all fields";
    return;
  }

  if (pass !== confirm) {
    err.textContent = "Passwords do not match";
    return;
  }

  document.getElementById("panel-register").style.display = "none";
  document.getElementById("success-screen").style.display = "block";
  document.getElementById("success-msg").textContent =
    `Welcome ${name}, your account is ready!`;
}