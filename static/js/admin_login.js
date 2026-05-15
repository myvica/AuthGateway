function refreshCaptcha() {
    document.getElementById('captcha-img').src = '/admin/captcha?' + new Date().getTime();
}
