<script setup>
import { ref, watch } from 'vue';

const props = defineProps({
  options: {
    type: Array,
    required: true,
    validator: (value) => {
      return value.every((option) => 'label' in option && 'value' in option);
    },
  },
  modelValue: {
    type: [String, Number],
    default: null,
  },
});

const selectedOption = ref(props.modelValue);
const emit = defineEmits(['update:modelValue']);

const handleSelect = (option) => {
  selectedOption.value = option.value;
  emit('update:modelValue', selectedOption.value);
};

watch(
    () => props.modelValue,
    (newValue) => {
      selectedOption.value = newValue;
    }
);
</script>

<template>
  <div class="option-component">
    <div
        v-for="option in options"
        :key="option.value"
        class="option"
        :class="{ selected: selectedOption === option.value }"
        @click="handleSelect(option)"
    >
      <span class="label">{{ option.label }}</span>
    </div>
  </div>
</template>

<style scoped>
.option-component {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.option {
  padding: 10px;
  border-radius: 8px;
  cursor: pointer;
  transition: background-color 0.3s ease, border-color 0.3s ease;
}

.option:hover {
  background-color: var(--section-background-color);
}

.option.selected {
  background-color: var(--section-background-color);
  border-color: rgba(0, 0, 0, 0.1);
}

.label {
  font-size: 16px;
}
</style>