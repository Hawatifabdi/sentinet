const SENTINET_PROFILE_KEY = "sentinetUserProfile";
const DEFAULT_ORGANIZATION = "Default Organization";

function saveProfile(profile) {
  const existing = getSavedProfile() || {};
  const merged = { ...existing, ...profile };
  if (
    profile.organization === DEFAULT_ORGANIZATION &&
    existing.organization &&
    existing.organization !== DEFAULT_ORGANIZATION
  ) {
    merged.organization = existing.organization;
  }
  localStorage.setItem(SENTINET_PROFILE_KEY, JSON.stringify(merged));
  return merged;
}

function getSavedProfile() {
  try {
    return JSON.parse(localStorage.getItem(SENTINET_PROFILE_KEY)) || null;
  } catch {
    return null;
  }
}

function clearProfile() {
  localStorage.removeItem(SENTINET_PROFILE_KEY);
}

function profileInitials(name, email) {
  const source = (name || email || "User").trim();
  const words = source.split(/\s+/).filter(Boolean);
  if (words.length >= 2) {
    return `${words[0][0]}${words[1][0]}`.toUpperCase();
  }
  return source.slice(0, 2).toUpperCase();
}

function renderSignedInUser(profile) {
  const nameEl = document.querySelector(".sb-user-name");
  const roleEl = document.querySelector(".sb-user-role");
  const avatarEl = document.querySelector(".sb-avatar");

  if (nameEl) nameEl.textContent = profile.fullName || profile.email || "Signed in user";
  if (roleEl) roleEl.textContent = profile.role || profile.organization || "Operator";
  if (avatarEl) avatarEl.textContent = profileInitials(profile.fullName, profile.email);
}

function announceProfile(profile) {
  window.dispatchEvent(new CustomEvent("sentinet-profile-ready", { detail: profile }));
}

async function loadUserProfile(user) {
  const fallback = {
    uid: user.uid,
    fullName: user.displayName || user.email,
    email: user.email,
    organization: DEFAULT_ORGANIZATION,
    role: "Operator",
  };

  const doc = await window.sentinetDb.collection("users").doc(user.uid).get();
  const profile = doc.exists ? { ...fallback, ...doc.data(), uid: user.uid, email: user.email } : fallback;
  const savedProfile = saveProfile(profile);
  renderSignedInUser(savedProfile);
  announceProfile(savedProfile);
  return savedProfile;
}

function requireSignedInUser() {
  const saved = getSavedProfile();
  if (saved) {
    renderSignedInUser(saved);
    setTimeout(() => announceProfile(saved), 0);
  }

  window.sentinetAuth.onAuthStateChanged(async user => {
    if (!user) {
      clearProfile();
      window.location.href = "/signin.html";
      return;
    }

    try {
      await loadUserProfile(user);
    } catch (error) {
      console.error("Could not load user profile", error);
      const fallback = {
        uid: user.uid,
        fullName: user.displayName || user.email,
        email: user.email,
        organization: DEFAULT_ORGANIZATION,
        role: "Operator",
      };
      const savedFallback = saveProfile(fallback);
      renderSignedInUser(savedFallback);
      announceProfile(savedFallback);
    }
  });
}

async function sentinetSignOut() {
  clearProfile();
  await window.sentinetAuth.signOut();
  window.location.href = "/signin.html";
}
