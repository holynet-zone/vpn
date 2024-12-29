<script setup>
import { RouterLink, useRoute } from 'vue-router';

const route = useRoute();
defineProps({
  title: {
    type: String,
    required: true,
  },
  icon: {
    type: String,
    required: false,
  },
  routePath: {
    type: String,
    required: false,
  },
  description: {
    type: String,
    required: false,
  },
});
</script>

<template>
  <div class="settings-item">
    <RouterLink :to="`${route.path}/${routePath}` || '/'" class="settings-link">
      <span v-if="icon" class="material-symbols-rounded icon">{{ icon }}</span>
      <div class="settings-item__content">
        <p class="title">{{ title }}</p>
        <p v-if="description" class="description">{{ description }}</p>
      </div>
      <span class="material-symbols-rounded chevron">chevron_right</span>
    </RouterLink>
  </div>
</template>

<style scoped>
.settings-item {
  margin: 10px 0;
}

.settings-link {
  display: flex;
  align-items: center;
  text-decoration: none;
  color: inherit;
  padding: 10px;
  border-radius: 8px;
  transition: background-color 0.3s ease;
}

.settings-link:hover {
  background-color: var(--section-background-color);
}

.icon {
  margin-right: 10px;
  font-size: 24px;
}

.settings-item__content {
  flex-grow: 1;
}

.settings-item__content .title {
  margin: 0;
  font-size: 18px;
}

.description {
  margin: 4px 0 0;
  font-size: 14px;
  color: var(--text-secondary-color); /* Используем вторичный цвет текста */
}

.chevron {
  margin-left: auto;
  font-size: 24px;
}
</style>