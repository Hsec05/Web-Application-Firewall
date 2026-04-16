import { useState } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Calendar } from '@/components/ui/calendar';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Badge } from '@/components/ui/badge';
import { FileText, Download, Calendar as CalendarIcon, FileJson, Table, AlertCircle, Check, FileType } from 'lucide-react';
import { format } from 'date-fns';
import { cn } from '@/lib/utils';
import { generateReport, getReportPreview, type ReportPreview } from '@/lib/api';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000';

interface ReportType { id: string; name: string; description: string; icon: React.ElementType; }

const reportTypes: ReportType[] = [
  { id: 'daily', name: 'Daily Security Summary', description: 'Overview of security events for the selected period', icon: FileText },
  { id: 'threats', name: 'Threat Analysis Report', description: 'Detailed breakdown of detected threats and attack patterns', icon: AlertCircle },
  { id: 'ips', name: 'IP Intelligence Report', description: 'Analysis of suspicious IP addresses and their activities', icon: Table },
  { id: 'trends', name: 'Security Trends Report', description: 'Long-term security trends and pattern analysis', icon: FileJson },
];

const Reports = () => {
  const [selectedReport, setSelectedReport] = useState<string>('daily');
  const [dateRange, setDateRange] = useState<{ from: Date; to: Date }>({
    from: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
    to: new Date(),
  });
  const [format_, setFormat] = useState<'json' | 'csv' | 'pdf'>('pdf');
  const [isGenerating, setIsGenerating] = useState(false);
  const [isDownloadingPDF, setIsDownloadingPDF] = useState(false);
  const [preview, setPreview] = useState<ReportPreview | null>(null);
  const [reportData, setReportData] = useState<any | null>(null);

  const handleGenerate = async () => {
    setIsGenerating(true);
    try {
      const [previewData, report] = await Promise.all([
        getReportPreview({
          type: selectedReport,
          from: dateRange.from.toISOString(),
          to: dateRange.to.toISOString(),
        }),
        format_ !== 'pdf'
          ? generateReport({
              type: selectedReport as any,
              dateRange: { start: dateRange.from.toISOString(), end: dateRange.to.toISOString() },
              format: format_ as 'json' | 'csv',
            })
          : Promise.resolve(null),
      ]);
      setPreview(previewData);
      setReportData(report);

      // Auto-download PDF if PDF format selected
      if (format_ === 'pdf') {
        await handlePDFDownload();
      }
    } catch (err) {
      console.error('Failed to generate report:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handlePDFDownload = async () => {
    setIsDownloadingPDF(true);
    try {
      const response = await fetch(`${API_BASE}/api/reports/generate/pdf`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: selectedReport,
          dateRange: { start: dateRange.from.toISOString(), end: dateRange.to.toISOString() },
        }),
      });

      if (!response.ok) throw new Error(`PDF generation failed: ${response.statusText}`);

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `waf-${selectedReport}-report-${format(dateRange.from, 'yyyy-MM-dd')}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('PDF download failed:', err);
      alert('PDF download failed. Make sure the backend has pdfkit installed (npm install in soc-backend).');
    } finally {
      setIsDownloadingPDF(false);
    }
  };

  const handleDownload = () => {
    if (!reportData) return;
    const content = format_ === 'csv'
      ? (typeof reportData === 'string' ? reportData : JSON.stringify(reportData))
      : JSON.stringify(reportData, null, 2);
    const mime = format_ === 'csv' ? 'text/csv' : 'application/json';
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedReport}-report-${format(dateRange.from, 'yyyy-MM-dd')}.${format_}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const selectedReportData = reportTypes.find(r => r.id === selectedReport);

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold">Reports</h1>
          <p className="text-muted-foreground text-sm mt-1">Generate and export security reports — PDF, JSON, or CSV</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            <div className="soc-panel">
              <div className="soc-panel-header"><h3 className="soc-panel-title">Select Report Type</h3></div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {reportTypes.map((report) => {
                  const Icon = report.icon;
                  return (
                    <div key={report.id} onClick={() => { setSelectedReport(report.id); setPreview(null); setReportData(null); }}
                      className={cn("p-4 rounded-lg border cursor-pointer transition-all",
                        selectedReport === report.id ? "bg-primary/10 border-primary/30" : "bg-muted/30 border-border hover:border-primary/20")}>
                      <div className="flex items-start gap-3">
                        <Icon className={cn("h-5 w-5 mt-0.5", selectedReport === report.id ? "text-primary" : "text-muted-foreground")} />
                        <div>
                          <div className="font-medium text-sm">{report.name}</div>
                          <div className="text-xs text-muted-foreground mt-1">{report.description}</div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="soc-panel">
              <div className="soc-panel-header"><h3 className="soc-panel-title">Report Options</h3></div>
              <div className="space-y-4">
                <div>
                  <label className="text-xs text-muted-foreground uppercase tracking-wide mb-2 block">Date Range</label>
                  <div className="flex items-center gap-2">
                    <Popover>
                      <PopoverTrigger asChild>
                        <Button variant="outline" className="w-[200px] justify-start">
                          <CalendarIcon className="h-4 w-4 mr-2" />{format(dateRange.from, 'MMM dd, yyyy')}
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent className="w-auto p-0 bg-popover border-border" align="start">
                        <Calendar mode="single" selected={dateRange.from} onSelect={(d) => d && setDateRange(prev => ({ ...prev, from: d }))} />
                      </PopoverContent>
                    </Popover>
                    <span className="text-muted-foreground">to</span>
                    <Popover>
                      <PopoverTrigger asChild>
                        <Button variant="outline" className="w-[200px] justify-start">
                          <CalendarIcon className="h-4 w-4 mr-2" />{format(dateRange.to, 'MMM dd, yyyy')}
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent className="w-auto p-0 bg-popover border-border" align="start">
                        <Calendar mode="single" selected={dateRange.to} onSelect={(d) => d && setDateRange(prev => ({ ...prev, to: d }))} />
                      </PopoverContent>
                    </Popover>
                  </div>
                </div>

                <div>
                  <label className="text-xs text-muted-foreground uppercase tracking-wide mb-2 block">Export Format</label>
                  <Select value={format_} onValueChange={(v) => setFormat(v as 'json' | 'csv' | 'pdf')}>
                    <SelectTrigger className="w-[220px]"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="pdf">
                        <div className="flex items-center gap-2"><FileType className="h-4 w-4 text-red-500" />PDF Report (Recommended)</div>
                      </SelectItem>
                      <SelectItem value="json">
                        <div className="flex items-center gap-2"><FileJson className="h-4 w-4" />JSON Data</div>
                      </SelectItem>
                      <SelectItem value="csv">
                        <div className="flex items-center gap-2"><Table className="h-4 w-4" />CSV Spreadsheet</div>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                  {format_ === 'pdf' && (
                    <p className="text-xs text-muted-foreground mt-2">
                      📄 PDF includes executive summary, charts, graphs, event tables, and security recommendations.
                    </p>
                  )}
                </div>
              </div>
            </div>

            <Button size="lg" className="w-full" onClick={handleGenerate} disabled={isGenerating || isDownloadingPDF}>
              {isGenerating || isDownloadingPDF ? (
                <><div className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                  {format_ === 'pdf' ? 'Generating PDF...' : 'Generating Report...'}</>
              ) : reportData || format_ === 'pdf' ? (
                <><Check className="h-4 w-4 mr-2" />Generate &amp; Download</>
              ) : (
                <><FileText className="h-4 w-4 mr-2" />Generate Report</>
              )}
            </Button>
          </div>

          <div className="soc-panel">
            <div className="soc-panel-header"><h3 className="soc-panel-title">Report Preview</h3></div>
            {preview ? (
              <div className="space-y-4">
                <div className="p-4 bg-muted/30 rounded-lg text-center">
                  <FileType className="h-12 w-12 mx-auto text-red-500 mb-3" />
                  <div className="font-semibold">{selectedReportData?.name}</div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {format(dateRange.from, 'MMM dd')} — {format(dateRange.to, 'MMM dd, yyyy')}
                  </div>
                  <Badge variant="secondary" className="mt-2 uppercase">{format_}</Badge>
                </div>

                <div className="space-y-2">
                  {[
                    { label: 'Total Events', value: preview.totalEvents },
                    { label: 'Unique IPs', value: preview.uniqueIPs },
                    { label: 'Blocked Threats', value: preview.blockedThreats, className: 'text-severity-critical' },
                    { label: 'Critical Alerts', value: preview.criticalAlerts, className: 'text-severity-critical' },
                  ].map(({ label, value, className }) => (
                    <div key={label} className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">{label}</span>
                      <span className={cn("font-mono", className)}>{value}</span>
                    </div>
                  ))}
                </div>

                <div className="space-y-2">
                  {format_ === 'pdf' ? (
                    <Button className="w-full bg-red-600 hover:bg-red-700" onClick={handlePDFDownload} disabled={isDownloadingPDF}>
                      {isDownloadingPDF
                        ? <><div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full mr-2" />Generating PDF...</>
                        : <><Download className="h-4 w-4 mr-2" />Download PDF</>}
                    </Button>
                  ) : (
                    <Button variant="outline" className="w-full" onClick={handleDownload} disabled={!reportData}>
                      <Download className="h-4 w-4 mr-2" />Download {format_.toUpperCase()}
                    </Button>
                  )}
                </div>
              </div>
            ) : (
              <div className="h-[300px] flex items-center justify-center text-center text-muted-foreground">
                <div>
                  <FileText className="h-12 w-12 mx-auto mb-4 opacity-30" />
                  <p className="text-sm">Configure and generate a report to see the preview</p>
                  <p className="text-xs mt-2 opacity-60">PDF format includes charts, graphs &amp; recommendations</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Reports;
