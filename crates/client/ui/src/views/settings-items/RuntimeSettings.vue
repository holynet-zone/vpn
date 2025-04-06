<script setup>
import { ref, onMounted, watch } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import OptionComponent from "@/components/OptionComponent.vue";

const STORAGE_KEY = 'selectedRuntime';

const selectedValue = ref(localStorage.getItem(STORAGE_KEY) || null);
const runtimes = ref([]);

onMounted(async () => {
  try {
    runtimes.value = await invoke('get_runtimes').then(
        (runtimes) => runtimes.map((runtime) => ({ label: runtime, value: runtime })),
        (error) => {
          console.error('Failed to get runtimes:', error);
          return [];
        }
    );
    if (!selectedValue.value && runtimes.value.length > 0) {
      selectedValue.value = runtimes.value[0].value;
      localStorage.setItem(STORAGE_KEY, selectedValue.value);
    }
  } catch (error) {
    console.error('Failed to fetch runtimes:', error);
  }
});

watch(selectedValue, (newValue) => {
  localStorage.setItem(STORAGE_KEY, newValue);
});
</script>

<template>
  <h1 class="no-selectable">{{ $t('settings.runtime.label') }}</h1>
  <p>{{ $t('settings.runtime.option_description')}}</p>
  <OptionComponent
      :options="runtimes"
      v-model="selectedValue"
  />
</template>

<style scoped>
p {
  margin-bottom: 20px;
}
</style>