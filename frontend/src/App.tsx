import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Bot } from 'lucide-react';
import { AuthProvider } from './context/AuthContext';
import { Layout } from './components/Layout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { GuardAIChat } from './components/GuardAIChat';
import { LandingPage } from './pages/LandingPage';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { DashboardPage } from './pages/DashboardPage';
import { URLScannerPage } from './pages/URLScannerPage';
import { EmailAnalyzerPage } from './pages/EmailAnalyzerPage';
import { ThreatMapPage } from './pages/ThreatMapPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { ReportsPage } from './pages/ReportsPage';
import { AdminPage } from './pages/AdminPage';
import { ProfilePage } from './pages/ProfilePage';

export const App: React.FC = () => {
  const [isChatOpen, setIsChatOpen] = useState(false);

  return (
    <AuthProvider>
      <Router>
        <Routes>
          {/* Public Landing Page */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Authenticated SOC Platform Routes wrapped in Layout */}
          <Route element={<Layout />}>
            <Route element={<ProtectedRoute />}>
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/scanner" element={<URLScannerPage />} />
              <Route path="/email" element={<EmailAnalyzerPage />} />
              <Route path="/threat-map" element={<ThreatMapPage />} />
              <Route path="/history" element={<ScanHistoryPage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/profile" element={<ProfilePage />} />
            </Route>

            {/* Admin Only Route */}
            <Route element={<ProtectedRoute requireAdmin />}>
              <Route path="/admin" element={<AdminPage />} />
            </Route>
          </Route>

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>

        {/* Floating GuardAI Assistant Trigger Button */}
        <div className="fixed bottom-5 right-5 z-40">
          <button
            onClick={() => setIsChatOpen(!isChatOpen)}
            className="p-3.5 rounded-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold shadow-2xl flex items-center space-x-2 transition-all hover:scale-105"
            title="Open GuardAI SOC Assistant"
          >
            <Bot className="w-5 h-5" />
            <span className="text-xs font-mono font-bold pr-1">GuardAI Assistant</span>
          </button>
        </div>

        {/* GuardAI Assistant Drawer */}
        <GuardAIChat isOpen={isChatOpen} onClose={() => setIsChatOpen(false)} />
      </Router>
    </AuthProvider>
  );
};

export default App;
