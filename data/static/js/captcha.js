const hCaptcha = document.querySelector('#h-captcha');
if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
hCaptcha.setAttribute('data-theme', 'dark');
} else {
hCaptcha.setAttribute('data-theme', 'light');
}
