/* 
UserSearchInput: autocomplete when searching for other users mail
Queries GET /api/users/search?email=<query> 
*/

import { useRef } from "react";
import type { ChangeEvent } from "react";
import apiClient from "../api/client";
import { sanitizeText } from "../utils/sanitize";

interface UserSuggestion {
  id: string;
  email: string;
}

interface Props {
  value: string;
  suggestions: UserSuggestion[];
  showSuggestions: boolean;
  onChange: (value: string) => void;
  onSuggestions: (suggestions: UserSuggestion[]) => void;
  onShowSuggestions: (show: boolean) => void;
  onSelect: (suggestion: UserSuggestion) => void;
}

export default function UserSearchInput({
  value,
  suggestions,
  showSuggestions,
  onChange,
  onSuggestions,
  onShowSuggestions,
  onSelect,
}: Props) {
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  function handleChange(e: ChangeEvent<HTMLInputElement>) {
    const val = e.target.value;
    onChange(val);

    if (searchTimer.current) clearTimeout(searchTimer.current);

    if (val.trim().length < 2) {
      onSuggestions([]);
      onShowSuggestions(false);
      return;
    }

    searchTimer.current = setTimeout(async () => {
      try {
        const { data } = await apiClient.get<UserSuggestion[]>(
          `/users/search?email=${encodeURIComponent(val.trim())}`,
        );
        onSuggestions(data);
        onShowSuggestions(data.length > 0);
      } catch {
        onSuggestions([]);
        onShowSuggestions(false);
      }
    }, 300);
  }

  return (
    <div className="relative">
      <label className="block text-xs font-medium text-gray-400 mb-1.5">
        Recipient email
      </label>
      <input
        type="email"
        value={value}
        onChange={handleChange}
        onBlur={() => setTimeout(() => onShowSuggestions(false), 150)}
        onFocus={() => {
          if (suggestions.length > 0) onShowSuggestions(true);
        }}
        placeholder="colleague@example.com"
        className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3.5 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
      />
      {showSuggestions && (
        <ul className="absolute z-10 mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg shadow-lg overflow-hidden">
          {suggestions.map((s) => (
            <li key={s.id}>
              <button
                type="button"
                onMouseDown={() => onSelect(s)}
                className="w-full text-left px-3.5 py-2 text-sm text-gray-300 hover:bg-gray-700 transition"
              >
                {sanitizeText(s.email)}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
