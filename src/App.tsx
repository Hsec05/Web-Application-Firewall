import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";

import Dashboard      from "./pages/Dashboard";
import AttackLogs     from "./pages/AttackLogs";
import IPIntelligence from "./pages/IPIntelligence";
import Analytics      from "./pages/Analytics";
import Incidents      from "./pages/Incidents";
import Rules          from "./pages/Rules";
import Reports        from "./pages/Reports";
import ThreatMap      from "./pages/ThreatMap";
import NotFound       from "./pages/NotFound";
import Login          from "./pages/Login";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword  from "./pages/ResetPassword";
import AddUser        from "./pages/AddUser";
import AuditLogs      from "./pages/AuditLogs";
import SystemSettings from "./pages/SystemSettings";
import UserManagement from "./pages/UserManagement";

import { AuthProvider, useAuth } from "./context/AuthContext";

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#070b13] flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login"           element={<Login />} />
            <Route path="/forgot-password" element={<ForgotPassword />} />
            <Route path="/reset-password"  element={<ResetPassword />} />

            <Route path="/"           element={<RequireAuth><Dashboard /></RequireAuth>} />
            <Route path="/threat-map" element={<RequireAuth><ThreatMap /></RequireAuth>} />
            <Route path="/logs"       element={<RequireAuth><AttackLogs /></RequireAuth>} />
            <Route path="/ip-intel"   element={<RequireAuth><IPIntelligence /></RequireAuth>} />
            <Route path="/analytics"  element={<RequireAuth><Analytics /></RequireAuth>} />
            <Route path="/incidents"  element={<RequireAuth><Incidents /></RequireAuth>} />
            <Route path="/rules"      element={<RequireAuth><Rules /></RequireAuth>} />
            <Route path="/reports"    element={<RequireAuth><Reports /></RequireAuth>} />
            <Route path="/add-user"        element={<RequireAuth><AddUser /></RequireAuth>} />
            <Route path="/users"           element={<RequireAuth><UserManagement /></RequireAuth>} />
            <Route path="/audit-logs"      element={<RequireAuth><AuditLogs /></RequireAuth>} />
            <Route path="/system-settings" element={<RequireAuth><SystemSettings /></RequireAuth>} />
            <Route path="*"           element={<NotFound />} />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
