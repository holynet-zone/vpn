<script setup lang="ts">
import InputComponent from "@/components/InputComponent.vue";
import { ref } from 'vue';

const inputValue = ref('');

const handleContinue = () => {
  console.log('Continue', inputValue.value);
};

</script>

<template>
  <div class="no-selectable">
    <h1>{{ $t('new.label') }}</h1>
    <p>{{ $t('new.description') }}</p>

    <InputComponent
      v-model="inputValue"
      :placeholder="$t('new.insert_placeholder')"
      :showPasteButton="true"
    />

    <button v-if="inputValue.trim()" @click="handleContinue">
      {{ $t('new.continue_button') }}
    </button>

  </div>
</template>

<style scoped>
  p {
    margin-top: 20px;
    margin-bottom: 20px;
  }

  button {
    margin-top: 20px;
    padding: 15px;
    border-radius: 8px;
    background-color: var(--text-color);
    color: var(--background-color);
    border: none;
    cursor: pointer;
    width: 100%;
    transition: background-color 0.3s ease;
  }

  button:active {
    animation: button-press 0.2s forwards;
  }

  @keyframes button-press {
    0% {
      transform: scale(1);
    }
    50% {
      transform: scale(0.95);
    }
    100% {
      transform: scale(1);
    }
  }
</style>