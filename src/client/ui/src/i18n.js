import { createI18n } from 'vue-i18n';

const loadLocaleMessages = async (locale) => {
    const response = await fetch(`/locales/${locale}.json`);
    return response.json();
};


const savedLocale = localStorage.getItem('locale') || 'en';

const i18n = createI18n({
    locale: savedLocale,
    fallbackLocale: 'en',
    messages: {},
});


const setLocale = async (locale) => {
    const messages = await loadLocaleMessages(locale);
    i18n.global.setLocaleMessage(locale, messages);
    i18n.locale = locale;
    localStorage.setItem('locale', locale);
};

setLocale(savedLocale);

export { i18n, setLocale };