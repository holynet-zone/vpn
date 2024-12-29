<script setup lang="ts">
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import SettingsItem from '@/components/SettingsItem.vue';

const route = useRoute();
const router = useRouter();

const isChildRoute = computed(() => route.path !== '/settings');
const goBack = () => {
  router.push('/settings');
};

</script>

<template>
  <div class="no-selectable">
    <h1 v-if="!isChildRoute">{{ $t('settings.label') }}</h1>

    <button v-if="isChildRoute" @click="goBack" class="back-button">
      <span class="material-symbols-rounded">chevron_left</span>
    </button>

    <!-- Контент дочерних маршрутов -->
    <RouterView v-slot="{ Component }">
      <Transition name="slide-fade" mode="out-in">
        <component class="settings-component-item" :is="Component" />
      </Transition>
    </RouterView>

    <!-- Меню настроек (скрывается на дочерних маршрутах) -->
    <Transition name="fade">
      <div v-if="!isChildRoute" class="settings-list">
        <SettingsItem
            :title="$t('settings.network.label')"
            icon="public"
            routePath="network"
        />
        <SettingsItem
            :title="$t('settings.runtime.label')"
            icon="change_circle"
            routePath="runtime"
        />
        <SettingsItem
            :title="$t('settings.security.label')"
            icon="lock"
            routePath="security"
        />
        <SettingsItem
            :title="$t('settings.language.label')"
            icon="language"
            routePath="language"
        />
        <SettingsItem
            :title="$t('settings.appearance.label')"
            icon="palette"
            routePath="appearance"
        />
        <SettingsItem
            :title="$t('settings.about.label')"
            icon="info"
            routePath="about"
        />
      </div>
    </Transition>
  </div>
</template>

<style>
.settings-list {
  margin-top: 20px; /* Отступ от заголовка */
  border-radius: 12px; /* Скругляем углы */
}

.back-button {
  display: flex;
  align-items: center;
  background: none;
  border: none;
  color: var(--text-color);
  cursor: pointer;
  padding: 0; /* Убираем отступы у кнопки */
  margin-bottom: 20px; /* Отступ снизу */
}

.back-button .material-symbols-rounded {
  font-size: 28px;
}

/* Анимация для меню */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

/* Анимация для контента */



.slide-fade-enter-from,
.slide-fade-leave-to {
  transform: translateX(20px);
  opacity: 0;
}
</style>