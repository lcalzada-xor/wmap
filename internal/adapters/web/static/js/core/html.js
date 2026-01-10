/**
 * Safe HTML Tagged Template
 * Sanitizes interpolated values to prevent XSS.
 * 
 * Usage:
 * const userContent = "<script>alert('xss')</script>";
 * const safe = html`<div>${userContent}</div>`;
 * // Result: <div>&lt;script&gt;alert('xss')&lt;/script&gt;</div>
 */

const escapeHTML = (str) => {
    if (typeof str !== 'string') return str;
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
};

export const html = (strings, ...values) => {
    let result = '';
    strings.forEach((string, i) => {
        const val = values[i];
        let safeVal = '';

        if (val !== undefined && val !== null) {
            if (Array.isArray(val)) {
                safeVal = val.join('');
            } else {
                safeVal = escapeHTML(String(val));
            }
        }

        result += string + safeVal;
    });
    return result;
};
