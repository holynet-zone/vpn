  import { createRouter, createWebHistory } from 'vue-router'
  import HomeView from '../views/HomeView.vue'
  import AddView from '../views/NewView.vue'
  import SettingsView from "@/views/SettingsView.vue";

  import NetworkSettings from "@/views/settings-items/NetworkSettings.vue";
  import SecuritySettings from "@/views/settings-items/SecuritySettings.vue";
  import LanguageSettings from "@/views/settings-items/LanguageSettings.vue";
  import AppearanceSettings from "@/views/settings-items/AppearanceSettings.vue";
  import AboutSettings from "@/views/settings-items/AboutSettings.vue";
  import RuntimeSettings from "@/views/settings-items/RuntimeSettings.vue";

  const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes: [
      {
        path: '/',
        name: 'home',
        component: HomeView,
      },
      {
        path: '/settings',
        name: 'settings',
        component: SettingsView,
        children: [
          { path: 'network', component: NetworkSettings },
          { path: 'runtime', component: RuntimeSettings },
          { path: 'security', component: SecuritySettings },
          { path: 'language', component: LanguageSettings },
          { path: 'appearance', component: AppearanceSettings },
          { path: 'about', component: AboutSettings },
        ],
      },
      {
        path: '/add',
        name: 'add',
        component: AddView,
      },
    ],
  })

  export default router
