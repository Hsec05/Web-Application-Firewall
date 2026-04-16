import { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  Shield, 
  LayoutDashboard, 
  FileText, 
  Globe, 
  Settings2, 
  BarChart3, 
  AlertTriangle, 
  FileDown,
  ChevronLeft,
  ChevronRight,
  Activity,
  Map,
  UserPlus,
  Users,
  ClipboardList,
  Settings,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { getIncidents } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';

interface NavItem {
  title: string;
  href: string;
  icon: React.ElementType;
  badge?: number;
}

export function AppSidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const [activeIncidents, setActiveIncidents] = useState<number>(0);
  const location = useLocation();
  const { user } = useAuth();

  useEffect(() => {
    const fetchIncidentCount = async () => {
      try {
        const result = await getIncidents();
        const active = result.data.filter(
          (i) => i.status === 'open' || i.status === 'investigating'
        ).length;
        setActiveIncidents(active);
      } catch {
        // silently fail — badge just won't show
      }
    };
    fetchIncidentCount();
    const interval = setInterval(fetchIncidentCount, 60000);
    return () => clearInterval(interval);
  }, []);

  const allNavItems: NavItem[] = [
    { title: 'Dashboard',      href: '/',           icon: LayoutDashboard },
    { title: 'Threat Map',     href: '/threat-map', icon: Map },
    { title: 'Attack Logs',    href: '/logs',        icon: FileText },
    { title: 'IP Intelligence',href: '/ip-intel',   icon: Globe },
    { title: 'Analytics',      href: '/analytics',   icon: BarChart3 },
    { title: 'Incidents',      href: '/incidents',   icon: AlertTriangle, badge: activeIncidents || undefined },
    { title: 'Rules',          href: '/rules',       icon: Settings2 },
    { title: 'Reports',        href: '/reports',     icon: FileDown },
    // Admin-only section
    ...(user?.role === 'admin' ? [
      { title: 'Users',          href: '/users',          icon: Users },
      { title: 'Audit Logs',     href: '/audit-logs',     icon: ClipboardList },
      { title: 'System Settings',href: '/system-settings',icon: Settings },
    ] : []),
  ];

  // Viewer role: restricted to dashboard, threat map, attack logs, analytics, reports
  const viewerAllowedHrefs = new Set(['/', '/threat-map', '/logs', '/analytics', '/reports']);
  const navItems = user?.role === 'viewer'
    ? allNavItems.filter(item => viewerAllowedHrefs.has(item.href))
    : allNavItems;

  return (
    <aside 
      className={cn(
        "fixed left-0 top-0 z-40 h-screen bg-sidebar border-r border-sidebar-border transition-all duration-300 flex flex-col",
        collapsed ? "w-16" : "w-64"
      )}
    >
      {/* Logo Header */}
      <div className={cn(
        "flex items-center gap-3 px-4 py-5 border-b border-sidebar-border",
        collapsed && "justify-center"
      )}>
        <div className="relative inline-flex">
          <Shield className="h-8 w-8 text-primary" />
          <Activity className="h-3.5 w-3.5 text-primary absolute -top-1.5 -right-1.5 animate-pulse-glow" />
        </div>
        {!collapsed && (
          <div className="flex flex-col">
            <span className="font-bold text-lg text-foreground tracking-tight">SecureSOC</span>
            <span className="text-xs text-muted-foreground">Threat Detection Platform</span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto soc-scrollbar">
        {navItems.map((item) => {
          const isActive = location.pathname === item.href;
          const Icon = item.icon;
          // Admin section divider before 'Users'
          const showDivider = item.href === '/users' && user?.role === 'admin';

          const linkContent = (
            <Link
              to={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group relative",
                isActive 
                  ? "bg-primary/10 text-primary border border-primary/20" 
                  : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                collapsed && "justify-center px-2"
              )}
            >
              <Icon className={cn(
                "h-5 w-5 flex-shrink-0 transition-colors",
                isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
              )} />
              {!collapsed && (
                <>
                  <span className="font-medium text-sm">{item.title}</span>
                  {item.badge && (
                    <span className="ml-auto bg-severity-critical text-white text-xs font-bold px-2 py-0.5 rounded-full">
                      {item.badge}
                    </span>
                  )}
                </>
              )}
              {collapsed && item.badge && (
                <span className="absolute -top-1 -right-1 bg-severity-critical text-white text-xs font-bold w-5 h-5 flex items-center justify-center rounded-full">
                  {item.badge}
                </span>
              )}
            </Link>
          );

          if (collapsed) {
            return (
              <div key={item.href}>
                {showDivider && <div className="my-2 border-t border-sidebar-border/60" />}
                <Tooltip delayDuration={0}>
                  <TooltipTrigger asChild>
                    {linkContent}
                  </TooltipTrigger>
                  <TooltipContent side="right" className="bg-popover border-border">
                    {item.title}
                  </TooltipContent>
                </Tooltip>
              </div>
            );
          }

          return (
            <div key={item.href}>
              {showDivider && (
                <div className="pt-2 pb-1">
                  <div className="border-t border-sidebar-border/60" />
                  <p className="text-[9px] font-semibold uppercase tracking-widest text-muted-foreground/40 px-3 pt-2">Admin</p>
                </div>
              )}
              {linkContent}
            </div>
          );
        })}
      </nav>

      {/* System Status */}
      {!collapsed && (
        <div className="px-4 py-3 border-t border-sidebar-border">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <div className="w-2 h-2 rounded-full bg-severity-safe animate-pulse" />
            <span>System Online</span>
            <span className="ml-auto font-mono">v2.1.4</span>
          </div>
        </div>
      )}

      {/* Collapse Toggle */}
      <div className="px-3 py-3 border-t border-sidebar-border">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setCollapsed(!collapsed)}
          className={cn(
            "w-full justify-center text-muted-foreground hover:text-foreground",
            collapsed && "px-2"
          )}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          {!collapsed && <span className="ml-2 text-xs">Collapse</span>}
        </Button>
      </div>
    </aside>
  );
}
