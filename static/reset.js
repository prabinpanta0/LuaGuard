// reset.js for reset.html

document.addEventListener('DOMContentLoaded', function() {
  const form = document.getElementById('reset-form');
  const pwInput = document.getElementById('reset-password');
  const pwConfirm = document.getElementById('reset-password-confirm');
  const mfaInput = document.getElementById('reset-mfa');
  const msg = document.getElementById('reset-msg');
  const tokenInput = document.getElementById('reset-token');

  // Extract token from URL
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get('token');
  if (token) tokenInput.value = token;

  function isStrongPassword(password) {
    if (typeof password !== 'string' || password.length < 8) return false;
    if (!/[a-z]/.test(password)) return false;
    if (!/[A-Z]/.test(password)) return false;
    if (!/[0-9]/.test(password)) return false;
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/.test(password)) return false;
    return true;
  }

  form.addEventListener('submit', function(e) {
    e.preventDefault();
    const password = pwInput.value;
    const confirm = pwConfirm.value;
    const mfa = mfaInput.value;
    if (!isStrongPassword(password)) {
      msg.textContent = 'Password must be at least 8 characters and include uppercase, lowercase, number, and symbol.';
      msg.style.color = 'red';
      return;
    }
    if (password !== confirm) {
      msg.textContent = 'Passwords do not match.';
      msg.style.color = 'red';
      return;
    }
    msg.textContent = '';
    const payload = {
      token: tokenInput.value,
      new_password: password,
      mfa_code: mfa
    };
    fetch('/reset-password', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    }).then(r => r.json()).then(res => {
      if (res.message) {
        msg.textContent = res.message;
        msg.style.color = 'green';
        setTimeout(() => window.location.href = '/static/login.html', 2000);
      } else if (res.error) {
        msg.textContent = res.error;
        msg.style.color = 'red';
      }
    }).catch(() => {
      msg.textContent = 'Server error.';
      msg.style.color = 'red';
    });
  });
});
