import { useState, useCallback } from "react";
import axios from "axios";
import apiClient from "../api/client";
import { deriveMasterKey, exportKeyAsBase64 } from "../utils/crypto";
import type { AuthResponse, ApiError } from "../types";

/*
  Authentication hook:
  After a successful login or register the hook:
   1) Stores the JWT in localStorage (persists across page reloads)
   2) Derives the 256-bit PBKDF2 master key client-side from the password and the salt returned by the server
   3) Exports the master key as base64 and stores it in sessionStorage
  The raw password is never stored or sent to the server again after this
*/

export function useAuth() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const storeSession = useCallback(
    async (data: AuthResponse, password: string): Promise<void> => {
      const masterKey = await deriveMasterKey(password, data.user.ecdhSalt);
      const masterKeyB64 = await exportKeyAsBase64(masterKey);
      localStorage.setItem("token", data.token);
      sessionStorage.setItem("masterKey", masterKeyB64);
    },
    [],
  );

  const login = useCallback(
    async (email: string, password: string): Promise<boolean> => {
      setLoading(true);
      setError(null);
      try {
        const { data } = await apiClient.post<AuthResponse>("/auth/login", {
          email,
          password,
        });
        await storeSession(data, password);
        return true;
      } catch (err) {
        if (axios.isAxiosError(err) && err.response?.data) {
          setError((err.response.data as ApiError).message);
        } else {
          setError("Login failed. Please try again.");
        }
        return false;
      } finally {
        setLoading(false);
      }
    },
    [storeSession],
  );

  const register = useCallback(
    async (email: string, password: string): Promise<boolean> => {
      setLoading(true);
      setError(null);
      try {
        const { data } = await apiClient.post<AuthResponse>("/auth/register", {
          email,
          password,
        });
        await storeSession(data, password);
        return true;
      } catch (err) {
        if (axios.isAxiosError(err) && err.response?.data) {
          setError((err.response.data as ApiError).message);
        } else {
          setError("Registration failed. Please try again.");
        }
        return false;
      } finally {
        setLoading(false);
      }
    },
    [storeSession],
  );

  const logout = useCallback((): void => {
    localStorage.removeItem("token");
    sessionStorage.removeItem("masterKey");
    window.location.href = "/login";
  }, []);

  //True only when both the JWT and the derived master key are present
  const isAuthenticated = (): boolean =>
    !!localStorage.getItem("token") && !!sessionStorage.getItem("masterKey");

  return { login, register, logout, isAuthenticated, loading, error };
}
