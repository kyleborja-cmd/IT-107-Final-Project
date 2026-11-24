document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.querySelector('.toggle-password');
  const password = document.querySelector('#password');
  if (toggle && password) toggle.addEventListener('click', () => {
    password.type = password.type === 'password' ? 'text' : 'password';
  });
  const menu = document.querySelector('.menu-toggle');
  const nav = document.querySelector('.main-nav');
  if (menu && nav) menu.addEventListener('click', () => {
    const isOpen = nav.classList.toggle('nav-open');
    menu.setAttribute('aria-expanded', String(isOpen));
  });

  const homeDialog = document.getElementById('dashboard-home-dialog');
  if (homeDialog && typeof homeDialog.showModal === 'function') {
    document.querySelectorAll('[data-dashboard-home]').forEach(link => {
      link.addEventListener('click', event => {
        if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        homeDialog.showModal();
      });
    });
  }

  const waterOptions = document.getElementById('water-options-dialog');
  document.getElementById('water-options-trigger')?.addEventListener('click', () => {
    if (!waterOptions.open) waterOptions.showModal();
  });

  const signOutDialog = document.getElementById('sign-out-dialog');
  if (signOutDialog && typeof signOutDialog.showModal === 'function') {
    document.querySelectorAll('form.logout-form').forEach(form => {
      form.addEventListener('submit', event => {
        event.preventDefault();
        if (!signOutDialog.open) signOutDialog.showModal();
      });
    });
  }

  const compactEvents = document.getElementById('admin-compact-events');
  const eventDashboard = document.getElementById('security-dashboard');
  if (compactEvents || eventDashboard) {
    const key = 'water-go:compact-event-rows';
    try {
      const compact = window.localStorage.getItem(key) === '1';
      if (eventDashboard) eventDashboard.classList.toggle('compact-event-rows', compact);
      if (compactEvents) {
        const status = document.getElementById('admin-settings-status');
        compactEvents.checked = compact;
        compactEvents.addEventListener('change', () => {
          try {
            window.localStorage.setItem(key, compactEvents.checked ? '1' : '0');
            status.textContent = 'Display preference saved.';
          } catch {
            compactEvents.checked = !compactEvents.checked;
            status.textContent = 'This browser could not save the display preference.';
          }
        });
      }
    } catch {
      if (compactEvents) {
        compactEvents.disabled = true;
        document.getElementById('admin-settings-status').textContent = 'Browser storage is unavailable.';
      }
    }
  }

  const loginCooldown = document.querySelector('[data-login-cooldown]');
  if (loginCooldown) {
    const remainingDisplay = loginCooldown.querySelector('[data-cooldown-remaining]');
    const submitButton = document.querySelector('#login-submit');
    const deadline = Date.now() + Math.max(0, Number(loginCooldown.dataset.loginCooldown) || 0) * 1000;

    const updateCooldown = () => {
      const remainingSeconds = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
      if (remainingSeconds <= 0) {
        loginCooldown.textContent = ' Try again now.';
        if (submitButton) submitButton.disabled = false;
        return;
      }
      if (remainingDisplay) remainingDisplay.textContent = String(remainingSeconds);
      window.setTimeout(updateCooldown, 1000);
    };

    updateCooldown();
  }

  const registrationForm = document.querySelector('#register-form');
  if (registrationForm) {
    const username = registrationForm.querySelector('#username');
    const usernameStatus = registrationForm.querySelector('#username-status');
    const csrfToken = registrationForm.querySelector('[name="csrf_token"]').value;
    const usernameMin = Number(registrationForm.dataset.usernameMin);
    const usernameMax = Number(registrationForm.dataset.usernameMax);
    const usernamePattern = new RegExp(`^[A-Za-z][A-Za-z0-9]{${usernameMin - 1},${usernameMax - 1}}$`);
    const usernameLengthMessage = `Username must start with a letter and use ${usernameMin}–${usernameMax} letters or numbers.`;
    let usernameTimer;
    if (username && usernameStatus) {
      username.addEventListener('input', () => {
        window.clearTimeout(usernameTimer);
        const value = username.value.trim();
        if (!usernamePattern.test(value)) {
          usernameStatus.textContent = value ? usernameLengthMessage : '';
          usernameStatus.className = 'field-status not-available';
          return;
        }
        usernameStatus.textContent = 'Checking username availability…';
        usernameStatus.className = 'field-status checking';
        usernameTimer = window.setTimeout(async () => {
          try {
            const response = await fetch('register.php', {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: new URLSearchParams({ action: 'check_username', csrf_token: csrfToken, username: value })
            });
            if (!response.ok) throw new Error('Username availability could not be checked.');
            const result = await response.json();
            if (username.value.trim() !== value) return;
            usernameStatus.textContent = result.message;
            usernameStatus.className = `field-status ${result.available ? 'is-available' : 'not-available'}`;
          } catch (error) {
            usernameStatus.textContent = error.message || 'Username availability could not be checked.';
            usernameStatus.className = 'field-status not-available';
          }
        }, 300);
      });
      if (username.value.trim()) username.dispatchEvent(new Event('input'));
    }

    const passwordInput = registrationForm.querySelector('#password');
    const passwordStrength = registrationForm.querySelector('#password-strength');
    const passwordMeter = registrationForm.querySelector('#password-meter');
    if (passwordInput && passwordStrength) {
      const updateStrength = () => {
        const passwordValue = passwordInput.value;
        const characterTypes = [
          /[a-z]/.test(passwordValue),
          /[A-Z]/.test(passwordValue),
          /[0-9]/.test(passwordValue),
          /[^a-zA-Z0-9]/.test(passwordValue)
        ].filter(Boolean).length;
        const passwordLength = Array.from(passwordValue).length;
        const strength = passwordLength < Number(registrationForm.dataset.passwordMin) || characterTypes < 2 ? 'Weak' :
          passwordLength >= 12 && characterTypes >= 3 ? 'Strong' : 'Medium';
        passwordStrength.textContent = `Password strength: ${strength}`;
        passwordStrength.className = `field-status strength-${strength.toLowerCase()}`;
        if (passwordMeter) {
          passwordMeter.value = strength === 'Weak' ? 0 : strength === 'Medium' ? 1 : 2;
          passwordMeter.setAttribute('aria-valuetext', strength);
        }
        passwordInput.dataset.strength = strength;
      };
      passwordInput.addEventListener('input', updateStrength);
      updateStrength();
    }

    const birthdate = registrationForm.querySelector('#birthdate');
    const ageDisplay = registrationForm.querySelector('#age-display');
    if (birthdate && ageDisplay) {
      birthdate.addEventListener('input', () => {
        if (!birthdate.value) {
          ageDisplay.value = '';
          return;
        }
        const [year, month, day] = birthdate.value.split('-').map(Number);
        const today = new Date();
        let age = today.getFullYear() - year;
        if (today.getMonth() + 1 < month || (today.getMonth() + 1 === month && today.getDate() < day)) age--;
        ageDisplay.value = age >= 0 ? age : '';
      });
      birthdate.dispatchEvent(new Event('input'));
    }

    const extensionSelect = registrationForm.querySelector('#name_extension');
    const extensionOther = registrationForm.querySelector('#name_extension_other');
    if (extensionSelect && extensionOther) {
      const updateExtension = () => {
        const isOther = extensionSelect.value === 'Other';
        extensionOther.hidden = !isOther;
        extensionOther.required = isOther;
      };
      extensionSelect.addEventListener('change', updateExtension);
      updateExtension();
    }

    const questionSelects = Array.from(registrationForm.querySelectorAll('[name^="security_question_"]'));
    const updateQuestionOptions = () => {
      questionSelects.forEach(select => {
        Array.from(select.options).forEach(option => {
          option.disabled = Boolean(option.value && option.value !== select.value &&
            questionSelects.some(other => other !== select && other.value === option.value));
        });
      });
    };
    questionSelects.forEach(select => select.addEventListener('change', updateQuestionOptions));
    updateQuestionOptions();

    registrationForm.addEventListener('submit', event => {
      const value = name => registrationForm.elements.namedItem(name).value.trim();
      const titleCase = /^\p{Lu}\p{Ll}*(?: \p{Lu}\p{Ll}*)*$/u;
      const today = value('birthdate') ? registrationForm.elements.birthdate.max : '';
      const errors = new Map();
      const check = (field, valid, message) => {
        if (!valid && !errors.has(field)) errors.set(field, message);
      };

      check('id_number', /^\d{4}-\d{4}$/.test(value('id_number')), 'ID Number must follow the format xxxx-xxxx.');
      check('username', usernamePattern.test(value('username')), usernameLengthMessage);
      for (const [field, label] of [['first_name', 'First Name'], ['middle_name', 'Middle Name'], ['family_name', 'Last Name']]) {
        const name = value(field);
        if (!name && field === 'middle_name') continue;
        check(field, Boolean(name), label + ' is required.');
        check(field, !/\p{N}/u.test(name), 'Numbers are not allowed in ' + label + '.');
        check(field, /^[\p{L} ]+$/u.test(name), 'Special characters are not allowed in ' + label + '.');
        check(field, !name.includes('  '), 'Double space is not allowed.');
        check(field, !/(.)\1{2}/iu.test(name), 'Three consecutive identical letters are not allowed.');
        check(field, Array.from(name).length >= 2 && Array.from(name).length <= Number(registrationForm.dataset.nameMax), label + ' must be between 2 and 50 characters.');
        check(field, /\p{Ll}/u.test(name) || !/\p{Lu}/u.test(name), 'Do not use all capital letters.');
        check(field, titleCase.test(name), 'First letter of your name must be capital.');
      }
      check('name_extension', value('name_extension') !== 'Other' || /^(I|II|III|IV|IX|X)$/.test(value('name_extension_other')), 'Name Extension must be I, II, III, IV, IX, or X.');
      check('emergency_contact', /^09\d{9}$/.test(value('emergency_contact')), 'Contact number must be 11 digits and start with 09.');
      check('email', registrationForm.elements.email.validity.valid, 'Please enter a valid email address.');
      check('birthdate', Boolean(value('birthdate')), 'Birthdate is required.');
      check('birthdate', value('birthdate') <= today, 'Birthdate cannot be in the future.');
      const age = Number(registrationForm.querySelector('#age-display').value);
      check('birthdate', age >= 18, 'You must be at least 18 years old to register.');
      const street = value('purok_street');
      check('purok_street', !street.includes('  '), 'Double space is not allowed in Purok / Street.');
      check('purok_street', /^[\p{L}\p{N}]+(?: [\p{L}\p{N}]+)*$/u.test(street), 'Purok / Street may contain only letters, numbers, and spaces.');
      check('purok_street', Array.from(street).length >= 2 && Array.from(street).length <= 50, 'Purok / Street must be between 2 and 50 characters.');
      for (const [field, label, maximum] of [['barangay', 'Barangay', 50], ['municipality_city', 'Municipality / City', 50], ['province', 'Province', 50], ['country', 'Country', 100]]) {
        const address = value(field);
        check(field, Array.from(address).length >= 2 && Array.from(address).length <= maximum, label + ' must be between 2 and ' + maximum + ' characters.');
        check(field, titleCase.test(address), 'First letter of each word in ' + label + ' must be capital.');
      }
      check('zip_code', /^\d{4}$/.test(value('zip_code')), 'ZIP Code must be exactly 4 digits.');
      check('password', Boolean(passwordInput.value), 'Password is required.');
      check('password', passwordInput.validity.valid && passwordInput.dataset.strength !== 'Weak', 'Password is weak. Use at least 8 characters and mix at least two character types.');
      check('confirm_password', passwordInput.value === registrationForm.elements.confirm_password.value, 'Passwords do not match.');
      const chosen = questionSelects.map(select => select.value);
      chosen.forEach((question, index) => check('security_question_' + (index + 1), /^Q[1-8]$/.test(question) && chosen.indexOf(question) === index, 'Choose three different security questions from the list.'));
      for (let index = 1; index <= 3; index++) {
        const field = 'security_answer_' + index;
        const answer = value(field);
        check(field, Array.from(answer).length >= 2 && Array.from(answer).length <= 50 && /^\p{L}+(?: \p{L}+)*$/u.test(answer), 'Security answer ' + index + ' must use 2 to 50 letters and spaces, with no double spaces.');
      }
      check('privacy_consent', registrationForm.elements.privacy_consent.checked, 'You must agree to the Privacy Notice to register.');

      registrationForm.querySelectorAll('[data-field-error]').forEach(message => {
        message.textContent = errors.get(message.dataset.fieldError) || '';
      });
      if (errors.size) {
        event.preventDefault();
        registrationForm.elements.namedItem(errors.keys().next().value).focus();
      }
    });
  }
});

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-resend-wait]').forEach(button => {
    const deadline = Date.now() + Number(button.dataset.resendWait) * 1000;
    const update = () => {
      const wait = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
      button.disabled = wait > 0;
      button.textContent = wait ? `Resend OTP (${wait}s)` : 'Resend OTP';
      if (wait) window.setTimeout(update, 1000);
    };
    update();
  });

  document.querySelectorAll('[data-otp-seconds]').forEach(timer => {
    const label = timer.querySelector('[data-otp-time]');
    const deadline = Date.now() + Number(timer.dataset.otpSeconds) * 1000;
    const update = () => {
      const remaining = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
      if (!remaining) {
        timer.textContent = 'Code expired. Request a new code.';
        return;
      }
      label.textContent = `${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, '0')}`;
      window.setTimeout(update, 1000);
    };
    if (label) update();
  });

  const cooldown = document.querySelector('[data-login-cooldown]');
  if (cooldown) {
    const links = document.querySelectorAll('[data-register-link]');
    window.setTimeout(() => {
      links.forEach(link => {
        link.href = 'register.php';
        link.removeAttribute('aria-disabled');
      });
    }, Number(cooldown.dataset.loginCooldown) * 1000);
  }

  const form = document.querySelector('[data-password-strength-form]');
  if (form) {
    const password = form.querySelector('#password');
    password.addEventListener('input', () => {
      const value = password.value;
      const types = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter(pattern => pattern.test(value)).length;
      const length = Array.from(value).length;
      const rating = length >= 12 && types >= 3 ? 2 : (length >= 8 && types >= 2 ? 1 : 0);
      form.querySelector('#password-meter').value = rating;
      form.querySelector('#password-strength').textContent = 'Password strength: ' + ['Weak', 'Medium', 'Strong'][rating];
    });
  }

  if (document.body.hasAttribute('data-idle-seconds')) {
    const { idleSeconds, loginUrl, activityUrl, activityToken } = document.body.dataset;
    const warning = document.getElementById('session-warning-dialog');
    const warningSeconds = warning?.querySelector('[data-session-seconds]');
    const stayButton = warning?.querySelector('[data-stay-signed-in]');
    const signIn = () => window.location.replace(loginUrl + '?idle=1');
    const throttle = 2000;
    let deadline = Date.now() + Number(idleSeconds) * 1000;
    let lastActivity = 0;
    let lastPost = 0;
    let timer;
    let queuedActivity;
    let pending = false;

    function updateTimer() {
      window.clearTimeout(timer);
      const remaining = Math.ceil((deadline - Date.now()) / 1000);
      if (remaining <= 0) {
        if (warningSeconds) warningSeconds.textContent = '0';
        if (activityUrl) syncSession(false);
        else signIn();
        return;
      }
      if (warning && remaining <= 10 && typeof warning.showModal === 'function') {
        warningSeconds.textContent = String(remaining);
        if (!warning.open) warning.showModal();
      } else if (warning?.open) {
        warning.close();
      }
      timer = window.setTimeout(updateTimer, remaining > 10 ? (remaining - 10) * 1000 : 1000);
    }

    async function syncSession(refresh) {
      if (pending) return;
      pending = true;
      if (refresh) lastPost = Date.now();
      if (stayButton) stayButton.disabled = true;
      try {
        const response = await fetch(activityUrl, {
          method: refresh ? 'POST' : 'GET',
          headers: refresh ? { 'X-CSRF-Token': activityToken } : {},
          cache: 'no-store',
          signal: AbortSignal.timeout(5000)
        });
        if (response.status === 401 || response.status === 403) {
          signIn();
          return;
        }
        if (!response.ok) throw new Error('Session status unavailable');
        const { remaining } = await response.json();
        if (!(remaining > 0)) {
          signIn();
          return;
        }
        deadline = Date.now() + remaining * 1000;
      } catch {
        if (Date.now() >= deadline) {
          signIn();
          return;
        }
      } finally {
        pending = false;
        if (stayButton) stayButton.disabled = false;
      }
      updateTimer();
      if (lastActivity > lastPost && document.visibilityState === 'visible') scheduleActivity();
    }

    function scheduleActivity() {
      if (queuedActivity !== undefined || pending) return;
      queuedActivity = window.setTimeout(() => {
        queuedActivity = undefined;
        if (document.visibilityState === 'visible' && Date.now() - lastActivity <= throttle + 500) syncSession(true);
      }, Math.max(0, throttle - (Date.now() - lastPost)));
    }

    stayButton?.addEventListener('click', () => {
      lastActivity = Date.now();
      syncSession(true);
    });
    warning?.addEventListener('cancel', event => event.preventDefault());

    if (activityUrl && document.body.hasAttribute('data-track-dashboard-activity')) {
      const recordActivity = event => {
        if (!event.isTrusted || document.visibilityState !== 'visible' || warning?.open) return;
        if (event.type === 'pointermove' && Math.abs(event.movementX) + Math.abs(event.movementY) < 3) return;
        lastActivity = Date.now();
        scheduleActivity();
      };
      for (const eventType of ['pointerdown', 'pointermove', 'keydown', 'scroll']) {
        document.addEventListener(eventType, recordActivity, { passive: true, capture: true });
      }
    }
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') updateTimer();
    });
    updateTimer();
    window.addEventListener('pageshow', event => {
      if (event.persisted) window.location.reload();
    });
  }
});
