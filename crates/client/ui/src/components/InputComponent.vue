<script setup>
import { ref, watch } from 'vue';

defineProps({
  placeholder: {
    type: String,
    default: '',
  },
  showPasteButton: {
    type: Boolean,
    default: false,
  },
  modelValue: { // Добавляем поддержку v-model
    type: String,
    default: '',
  },
});

const emit = defineEmits(['update:modelValue']); // Добавляем событие для обновления значения

const handlePaste = async () => {
  try {
    const text = await navigator.clipboard.readText();
    emit('update:modelValue', text); // Обновляем значение через v-model
  } catch (error) {
    console.error('Failed to read clipboard:', error);
  }
};
</script>

<template>
  <div class="input-container">
    <input
        :value="modelValue"
    @input="emit('update:modelValue', $event.target.value)"
    type="text"
    :placeholder="placeholder"
    class="input-field"
    />
    <button
        v-if="showPasteButton"
        @click="handlePaste"
        class="paste-button"
    >
      {{ $t('components.input.insert_button') }}
    </button>
  </div>
</template>

<style scoped>
.input-container {
  display: flex;
  align-items: center;
  border: 2px solid var(--section-background-color);
  border-radius: 8px;
  transition: border-color 0.3s ease;
}

.input-container:hover {
  border-color: var(--text-color);
}

.input-container:focus-within {
  border-color: var(--text-color);
}

.input-field {
  flex: 1;
  border: none;
  outline: none;
  font-size: 16px;
  padding: 8px;
  background: transparent;
  color: var(--text-color);
}

.paste-button {
  padding: 8px 12px;
  background-color: var(--text-color);
  color: var(--background-color);
  border: 3px solid var(--text-color);
  border-radius: 0 6px 6px 0;
  cursor: pointer;
  transition: background-color 0.3s ease;
}

.paste-button:hover {
  background-color: var(--text-color);
  color: var(--background-color);
}
</style>