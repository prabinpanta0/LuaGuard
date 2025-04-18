document.addEventListener('DOMContentLoaded', function() {
  const form = document.getElementById('auth-form');
  const modeInput = document.getElementById('mode');
  const formTitle = document.getElementById('form-title');
  const toggleBtn = document.getElementById('toggle-mode');
  const pwInput = document.getElementById('password');
  const pwStrength = document.getElementById('pw-strength');
  const captchaQ = document.getElementById('captcha-q');
  const formMsg = document.getElementById('form-msg');
  const mfaSection = document.getElementById('mfa-section');
  const mfaInput = document.getElementById('mfa-input');
  const forgotLink = document.getElementById('forgot-link');

  // Hide MFA section by default (only if present)
  if (mfaSection) mfaSection.style.display = 'none';

  // Add support for showing/hiding MFA, email verify, and risk sections
  function showSection(id, show) {
    const el = document.getElementById(id);
    if (el) el.classList[show ? 'add' : 'remove']('active');
  }
  // Example: showSection('mfa-section', true);

  // Password strength meter (improved)
  pwInput.addEventListener('input', function() {
    const val = pwInput.value;
    let score = 0;
    if (val.length >= 8) score++;
    if (/[A-Z]/.test(val)) score++;
    if (/[a-z]/.test(val)) score++;
    if (/[0-9]/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;
    let msg = ['Too weak', 'Weak', 'Medium', 'Strong', 'Very strong'];
    pwStrength.textContent = msg[score] || '';
    pwStrength.style.color = score >= 3 ? '#22c55e' : '#ef4444';
    if (score < 3) {
      pwInput.style.borderColor = '#ef4444';
    } else {
      pwInput.style.borderColor = '#22c55e';
    }
  });

  // --- Behavioral biometrics collection ---
  let biometrics = {keyTimings: [], mouseMoves: []};
  let lastKeyTime = null;
  pwInput.addEventListener('keydown', function(e) {
    const now = Date.now();
    if (lastKeyTime) {
      biometrics.keyTimings.push(now - lastKeyTime);
    }
    lastKeyTime = now;
  });
  document.addEventListener('mousemove', function(e) {
    biometrics.mouseMoves.push({x: e.clientX, y: e.clientY, t: Date.now()});
    if (biometrics.mouseMoves.length > 100) biometrics.mouseMoves.shift();
  });

  // Toggle between register/login
  toggleBtn.addEventListener('click', function() {
    if (modeInput.value === 'register') {
      modeInput.value = 'login';
      formTitle.textContent = 'Login';
      toggleBtn.textContent = 'Switch to Register';
      form.querySelector('button[type="submit"]').textContent = 'Login';
      if (forgotLink) forgotLink.style.display = 'block';
    } else {
      modeInput.value = 'register';
      formTitle.textContent = 'Register';
      toggleBtn.textContent = 'Switch to Login';
      form.querySelector('button[type="submit"]').textContent = 'Register';
      if (forgotLink) forgotLink.style.display = 'none';
    }
    formMsg.textContent = '';
    fetchCaptcha();
  });

  // On load, show/hide forgot password link based on mode
  if (forgotLink) forgotLink.style.display = (modeInput.value === 'login') ? 'block' : 'none';

  // Fetch CAPTCHA from server
  function fetchCaptcha() {
    fetch('/captcha').then(r => r.json()).then(data => {
      captchaToken = data.token;
      captchaQ.textContent = data.q;
    });
  }
  let captchaToken = '';
  fetchCaptcha();

  // Google reCAPTCHA v3 integration
  const RECAPTCHA_SITE_KEY = '6LctuhwrAAAAAFSGsEiK4JwHpvehHJdTWB_6ZHu-';

  function getRecaptchaToken(action, callback) {
    if (window.grecaptcha && window.grecaptcha.execute) {
      window.grecaptcha.execute(RECAPTCHA_SITE_KEY, {action: action}).then(function(token) {
        callback(token);
      });
    } else {
      console.error('reCAPTCHA not loaded yet');
      callback(''); // Or handle error appropriately
    }
  }

  function getCSRFToken() {
    const m = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/);
    return m ? m[1] : '';
  }

  // Handle form submit
  form.addEventListener('submit', function(e) {
    e.preventDefault();
    formMsg.textContent = '';
    const currentMode = modeInput.value; // e.g., 'login' or 'register'

    getRecaptchaToken(currentMode, function(recaptchaToken) {
      const data = Object.fromEntries(new FormData(form));
      data.recaptcha_token = recaptchaToken;
      data.captcha_token = captchaToken;
      data.csrf_token = getCSRFToken();
      data.biometrics = biometrics;

      fetch('/' + currentMode, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
      }).then(r => r.json()).then(res => {
        if (res.ok) {
          formMsg.style.color = 'green';
          formMsg.textContent = res.msg;
          // If MFA required, redirect to MFA page
          if (res.mfa_required) {
            window.location.href = '/static/mfa.html';
          } else {
            window.location.href = '/static/dashboard.html';
          }
        } else {
          formMsg.style.color = 'red';
          formMsg.textContent = res.msg;
          // If MFA required, show MFA section (only if present)
          if (res.msg && res.msg.toLowerCase().includes('mfa') && mfaSection && mfaInput) {
            mfaSection.style.display = 'block';
            mfaInput.focus();
          }
          // No need to call fetchCaptcha() anymore
        }
      });
    });
  });

  // Load reCAPTCHA v3 script dynamically
  (function() {
    var s = document.createElement('script');
    s.src = `https://www.google.com/recaptcha/api.js?render=${RECAPTCHA_SITE_KEY}`;
    s.async = true;
    s.defer = true;
    document.body.appendChild(s);
  })();

  // Example: showSection('risk-section', true); // To show risk/adaptive UI
});
