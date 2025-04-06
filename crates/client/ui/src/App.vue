<script setup>
import { RouterLink, RouterView, useRoute } from 'vue-router'

const route = useRoute()
</script>

<template>
  <main>
    <RouterView />
  </main>
  <footer class="no-selectable">
<!--    <img crates="@/assets/icon.svg" alt="Holynet VPN" >-->
    <RouterLink to="/">
      <span :class="['nav-icon', { 'active': route.path === '/' }]">Home</span>
    </RouterLink>
    <RouterLink to="/settings">
      <span :class="['nav-icon', { 'active': route.path.startsWith('/settings') }]">Settings</span>
    </RouterLink>
    <RouterLink to="/add">
      <span :class="['nav-icon', { 'active': route.path.startsWith('/add') }]">Add</span>
    </RouterLink>
  </footer>
</template>

<style>
.nav-icon {
  font-size: 28px;
  cursor: pointer;
}

.nav-icon.active {
  color: #DACCF7;
}
</style>