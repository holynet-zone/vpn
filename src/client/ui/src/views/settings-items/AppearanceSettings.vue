<script setup lang="ts">
import SettingsItem from "@/components/SettingsItem.vue";
</script>

<template>
  <h1 class="no-selectable">{{ $t('settings.appearance.label') }}</h1>
  <div class="settings-list">
    <SettingsItem
        :title="$t('settings.language.label')"
        routePath="language"
        description="English"
    />
  </div>
</template>

<style scoped>
h1 {
  margin-left: 10px;
}
</style>
