import { createApp } from "vue";
import App from "./App.vue";
import router from "./router/routes";

// Axios
import axios from "axios";
axios.defaults.baseURL = "http://localhost:8000/api/";


createApp(App).use(router).mount("#app");
