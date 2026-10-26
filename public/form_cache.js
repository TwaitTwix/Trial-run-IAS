(function () {
  const storageKey = 'movie_app_form_cache:' + (location.pathname.split('/').pop() || 'index.php');
  const sensitivePatterns = ['password', 'pass', 'confirm', 'otp', 'verification', 'csrf', 'code'];

  function isSensitiveField(field) {
    if (!field || !field.name) return true;
    const name = field.name.toLowerCase();
    const type = (field.type || '').toLowerCase();
    if (type === 'hidden' || type === 'file' || type === 'submit' || type === 'button' || type === 'reset') {
      return true;
    }
    return sensitivePatterns.some((pattern) => name.includes(pattern));
  }

  function getFields(form) {
    return Array.from(form.querySelectorAll('input, textarea, select')).filter((field) => {
      if (field.disabled || field.name === '') return false;
      if (isSensitiveField(field)) return false;
      return field.type !== 'submit' && field.type !== 'button' && field.type !== 'reset';
    });
  }

  function saveDraft(form) {
    const values = {};
    getFields(form).forEach((field) => {
      if (field.type === 'checkbox' || field.type === 'radio') {
        values[field.name] = field.checked;
      } else {
        values[field.name] = field.value;
      }
    });

    try {
      localStorage.setItem(storageKey, JSON.stringify(values));
    } catch (error) {
      console.warn('Form cache could not be saved.', error);
    }
  }

  function restoreDraft(form) {
    try {
      const raw = localStorage.getItem(storageKey);
      if (!raw) return;
      const values = JSON.parse(raw);
      if (!values || typeof values !== 'object') return;

      getFields(form).forEach((field) => {
        if (!(field.name in values)) return;

        if (field.type === 'checkbox' || field.type === 'radio') {
          field.checked = !!values[field.name];
          return;
        }

        field.value = values[field.name] ?? '';
      });
    } catch (error) {
      console.warn('Form cache could not be restored.', error);
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('form').forEach((form) => {
      restoreDraft(form);

      const fields = getFields(form);
      fields.forEach((field) => {
        field.addEventListener('input', () => saveDraft(form));
        field.addEventListener('change', () => saveDraft(form));
      });
    });
  });
})();
