/*Central Axios instance for all SecureVault API calls.*/

import axios from "axios";
const apiClient = axios.create({
  baseURL: "/api",
  headers: { "Content-Type": "application/json" },
});

// Request interceptors
apiClient.interceptors.request.use((config) => {
  // JWT Bearer token (persisted in localStorage across sessions)
  const token = localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  // Master key (base64-encoded 32-byte PBKDF2 key held in sessionStorage)
  // The server won't need raw password again after initial login.
  const masterKey = sessionStorage.getItem("masterKey");
  if (masterKey) {
    config.headers["X-Master-Key"] = masterKey;
  }
  return config;
});

// Response interceptors
apiClient.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      // Clear credentials
      localStorage.removeItem("token");
      sessionStorage.removeItem("masterKey");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  },
);

export default apiClient;
