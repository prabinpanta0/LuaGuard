// register.js for register.html

document.addEventListener('DOMContentLoaded', function() {
  const form = document.getElementById('register-form');
  const pwInput = document.getElementById('register-password');
  const pwStrength = document.getElementById('register-pw-strength');
  const formMsg = document.getElementById('register-form-msg');

  // Password strength meter
  if (pwInput && pwStrength) {
    pwInput.addEventListener('input', function() {
      const val = pwInput.value;
      let score = 0;
      let msg = ['Too weak', 'Weak', 'Medium', 'Strong', 'Very strong'];
      if (window.zxcvbn) {
        const result = zxcvbn(val);
        score = result.score;
        pwStrength.textContent = msg[score] || '';
        pwStrength.style.color = score >= 3 ? '#22c55e' : '#ef4444';
        if (score < 3) {
          pwInput.style.borderColor = '#ef4444';
        } else {
          pwInput.style.borderColor = '#22c55e';
        }
      } else {
        // fallback: basic check
        if (val.length >= 8) score++;
        if (/[A-Z]/.test(val)) score++;
        if (/[a-z]/.test(val)) score++;
        if (/[0-9]/.test(val)) score++;
        if (/[^A-Za-z0-9]/.test(val)) score++;
        pwStrength.textContent = msg[score] || '';
        pwStrength.style.color = score >= 3 ? '#22c55e' : '#ef4444';
        if (score < 3) {
          pwInput.style.borderColor = '#ef4444';
        } else {
          pwInput.style.borderColor = '#22c55e';
        }
      }
    });
  }

  function isStrongPassword(password) {
    if (typeof password !== 'string' || password.length < 8) return false;
    if (!/[a-z]/.test(password)) return false;
    if (!/[A-Z]/.test(password)) return false;
    if (!/[0-9]/.test(password)) return false;
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/.test(password)) return false;
    return true;
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
    const password = pwInput.value;
    const confirm = document.getElementById('register-password-confirm').value;
    if (window.zxcvbn) {
      const result = zxcvbn(password);
      if (result.score < 3) {
        formMsg.textContent = 'Password is too weak. Please choose a stronger password.';
        formMsg.style.color = 'red';
        return;
      }
    }
    if (!isStrongPassword(password)) {
      formMsg.textContent = 'Password must be at least 8 characters and include uppercase, lowercase, number, and symbol.';
      formMsg.style.color = 'red';
      return;
    }
    if (password !== confirm) {
      formMsg.textContent = 'Passwords do not match.';
      formMsg.style.color = 'red';
      return;
    }
    formMsg.textContent = '';
    getRecaptchaToken('register', function(recaptchaToken) {
      const data = Object.fromEntries(new FormData(form));
      data.recaptcha_token = recaptchaToken;
      data.captcha = captchaAnswer;
      data.captcha_token = captchaToken;
      data.csrf_token = getCSRFToken();
      fetch('/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
      }).then(r => r.json()).then(res => {
        if (res.ok) {
          if (res.mfa_setup) {
            window.location.href = '/static/mfa_setup.html';
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