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
async function handleSignIn() {
  const button = document.getElementById("btn-signin");
  const email = document.getElementById("si-email").value.trim();
  const pass = document.getElementById("si-password").value;
  const err = document.getElementById("si-err");
  err.textContent = "";

  if (!email || !pass) {
    err.textContent = "Please fill all fields";
    return;
  }

  if (!window.sentinetAuth) {
    err.textContent = "Firebase did not initialize. Check firebase-config.js and script loading.";
    return;
  }

  setLoading(button, true, "Signing in...");

  try {
    const credential = await window.sentinetAuth.signInWithEmailAndPassword(email, pass);
    saveProfile({
      uid: credential.user.uid,
      fullName: credential.user.displayName || credential.user.email,
      email: credential.user.email,
      organization: DEFAULT_ORGANIZATION,
      role: "Operator",
      profilePending: true,
    });
    window.location.href = "/dashboard";
  } catch (error) {
    console.error("Sign in failed", error);
    err.textContent = authMessage(error);
    setLoading(button, false);
  }
}

// REGISTER
async function handleRegister() {
  const button = document.getElementById("btn-register");
  const name = document.getElementById("reg-name").value.trim();
  const org = document.getElementById("reg-org").value.trim();
  const role = document.getElementById("reg-role").value;
  const email = document.getElementById("reg-email").value.trim();
  const pass = document.getElementById("reg-password").value;
  const confirm = document.getElementById("reg-confirm").value;
  const err = document.getElementById("reg-err");
  err.textContent = "";

  if (!name || !org || !role || role === "Select role" || !email || !pass || !confirm) {
    err.textContent = "Fill all fields";
    return;
  }

  if (pass !== confirm) {
    err.textContent = "Passwords do not match";
    return;
  }

  if (!window.sentinetAuth || !window.sentinetDb) {
    err.textContent = "Firebase did not initialize. Check firebase-config.js and script loading.";
    return;
  }

  setLoading(button, true, "Creating account...");

  try {
    const credential = await window.sentinetAuth.createUserWithEmailAndPassword(email, pass);
    await credential.user.updateProfile({ displayName: name });

    const profile = {
      uid: credential.user.uid,
      fullName: name,
      email,
      organization: org,
      role,
      createdAt: firebase.firestore.FieldValue.serverTimestamp(),
    };

    await window.sentinetDb.collection("users").doc(credential.user.uid).set(profile);
    saveProfile({ ...profile, createdAt: new Date().toISOString() });

    document.getElementById("panel-register").style.display = "none";
    document.getElementById("success-screen").style.display = "block";
    document.getElementById("success-msg").textContent =
      `Welcome ${name}, your ${org} account is ready.`;
  } catch (error) {
    console.error("Registration failed", error);
    err.textContent = error.code && error.code.startsWith("auth/")
      ? authMessage(error)
      : profileMessage(error);
    setLoading(button, false);
  }
}

function setLoading(button, loading, label) {
  if (!button) return;
  if (loading) {
    button.dataset.defaultText = button.textContent.trim();
    button.textContent = label;
    button.disabled = true;
    button.classList.add("is-loading");
    return;
  }

  button.textContent = button.dataset.defaultText || button.textContent;
  button.disabled = false;
  button.classList.remove("is-loading");
}

function authMessage(error) {
  const messages = {
    "auth/api-key-not-valid": "Firebase API key is not valid. Check firebase-config.js.",
    "auth/email-already-in-use": "An account already exists with this email.",
    "auth/invalid-email": "Enter a valid email address.",
    "auth/invalid-credential": "Email or password is incorrect.",
    "auth/operation-not-allowed": "Email/password sign-in is not enabled in Firebase Authentication.",
    "auth/unauthorized-domain": "This domain is not authorized in Firebase. Add 127.0.0.1 and localhost.",
    "auth/wrong-password": "Email or password is incorrect.",
    "auth/user-not-found": "Email or password is incorrect.",
    "auth/weak-password": "Use a password with at least 6 characters.",
    "auth/network-request-failed": "Network error. Check your connection and try again.",
  };
  return messages[error.code] || `Authentication failed: ${error.code || error.message}`;
}

function profileMessage(error) {
  const messages = {
    "permission-denied": "Signed in, but Firestore blocked the user profile. Check your Firestore rules.",
    "unavailable": "Signed in, but Firestore is unavailable. Check that Firestore is enabled.",
    "not-found": "Signed in, but the user profile was not found.",
  };
  return messages[error.code] || `Profile setup failed: ${error.code || error.message}`;
}
