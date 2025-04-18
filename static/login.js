// login.js for login.html

document.addEventListener('DOMContentLoaded', function() {
  const form = document.getElementById('login-form');
  const pwInput = document.getElementById('login-password');
  const pwStrength = document.getElementById('login-pw-strength');
  const formMsg = document.getElementById('login-form-msg');
  const forgotLink = document.getElementById('login-forgot-link');

  // Password strength meter (optional for login)
  if (pwInput && pwStrength) {
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
  }

  // Google reCAPTCHA v3 integration
  const RECAPTCHA_SITE_KEY = '6LctuhwrAAAAAFSGsEiK4JwHpvehHJdTWB_6ZHu-';
  function getRecaptchaToken(action, callback) {
    if (window.grecaptcha && window.grecaptcha.execute) {
      window.grecaptcha.execute(RECAPTCHA_SITE_KEY, {action: action}).then(function(token) {
        callback(token);
      });
    } else {
      callback('');
    }
  }

  function getCSRFToken() {
    const m = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/);
    return m ? m[1] : '';
  }

  let captchaToken = '';
  function fetchCaptcha() {
    fetch('/captcha').then(r => r.json()).then(data => {
      captchaToken = data.token;
      // Optionally show data.q to user if you want visible captcha
    });
  }
  fetchCaptcha();

  form.addEventListener('submit', function(e) {
    e.preventDefault();
    formMsg.textContent = '';
    getRecaptchaToken('login', function(recaptchaToken) {
      const data = Object.fromEntries(new FormData(form));
      data.recaptcha_token = recaptchaToken;
      data.captcha_token = captchaToken;
      data.csrf_token = getCSRFToken();
      fetch('/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
      }).then(r => r.json()).then(res => {
        if (res.ok) {
          if (res.mfa_required) {
            window.location.href = '/static/mfa.html';
          } else {
            window.location.href = '/static/dashboard.html';
          }
        } else {
          formMsg.textContent = res.msg;
          formMsg.style.color = 'red';
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
});