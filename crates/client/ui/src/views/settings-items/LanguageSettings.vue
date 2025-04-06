<script setup>
import { ref, watch } from 'vue';
import OptionComponent from '@/components/OptionComponent.vue';
import { setLocale, i18n } from '@/i18n';

const options = [
  { label: 'English', value: 'en' },
  { label: 'Русский', value: 'ru' },
];

const selectedValue = ref(i18n.global.locale);

watch(selectedValue, (newValue) => {
  document.body.classList.add('fade-out');

  setTimeout(() => {
    setLocale(newValue).then(
        () => {
          window.location.reload();
        },
        (error) => {
          console.error('Failed to change locale:', error);
          document.body.classList.remove('fade-out');
        }
    );
  }, 500);
});
</script>

<template>

  <h1>{{ $t('settings.language.option_header')}}</h1>
  <OptionComponent
      :options="options"
      v-model="selectedValue"
  />
</template>

<style scoped>
.fade-out {
  opacity: 0;
  transition: opacity 0.3s ease;
}
</style>