import { createRouter, createWebHistory } from "vue-router";
import Signup from "@/views/pages/Register.vue"
const routes = [
  {
    path: '/signup',
    component: Signup,
  },
];


const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;
