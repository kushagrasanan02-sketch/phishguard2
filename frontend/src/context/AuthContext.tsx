import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, AuthState } from '../types';
import { authService } from '../services/api';

interface AuthContextType extends AuthState {
  login: (token: string, refreshToken: string) => Promise<void>;
  logout: () => void;
  refetchUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('phishguard_token'));
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchUser = async () => {
    try {
      if (!token) {
        setUser(null);
        setIsLoading(false);
        return;
      }
      const currentUser = await authService.getCurrentUser();
      setUser(currentUser);
    } catch (err) {
      console.error('Failed to fetch user context:', err);
      localStorage.removeItem('phishguard_token');
      localStorage.removeItem('phishguard_refresh_token');
      setToken(null);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchUser();
  }, [token]);

  const login = async (newToken: string, newRefreshToken: string) => {
    localStorage.setItem('phishguard_token', newToken);
    localStorage.setItem('phishguard_refresh_token', newRefreshToken);
    setToken(newToken);
    await fetchUser();
  };

  const logout = () => {
    localStorage.removeItem('phishguard_token');
    localStorage.removeItem('phishguard_refresh_token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        refetchUser: fetchUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
