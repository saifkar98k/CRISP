import React, { useState } from 'react';
import { useCrisp } from '../context/CrispContext';
import { CsvColumnMapping } from '../types/config';
import { Upload, FileSpreadsheet, Check, AlertCircle, RefreshCw } from 'lucide-react';
import Papa from 'papaparse';

interface CSVMappingModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const CSVMappingModal: React.FC<CSVMappingModalProps> = ({ isOpen, onClose }) => {
  const { importCustomCsv } = useCrisp();
  const [csvContent, setCsvContent] = useState('');
  const [headers, setHeaders] = useState<string[]>([]);
  const [previewRows, setPreviewRows] = useState<Record<string, string>[]>([]);
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  // Mapping configuration state
  const [mapping, setMapping] = useState<CsvColumnMapping>({
    idColumn: '',
    timestampColumn: '',
    sourceIpColumn: '',
    destinationIpColumn: '',
    attackCategoryColumn: '',
    severityColumn: '',
    descriptionColumn: '',
    assetIdColumn: '',
    assetNameColumn: '',
    assetCriticalityColumn: '',
    relatedCveColumn: '',
    detectionRuleColumn: '',
    statusColumn: '',
    defaultSeverity: 'MEDIUM',
    defaultAttackCategory: 'Exploit Public-Facing App',
  });

  if (!isOpen) return null;

  // Auto-detect columns when CSV content changes
  const handleContentParsed = (content: string) => {
    setCsvContent(content);
    setStatusMsg(null);

    Papa.parse(content, {
      header: true,
      preview: 5,
      skipEmptyLines: true,
      complete: (results) => {
        if (results.meta.fields && results.meta.fields.length > 0) {
          const fields = results.meta.fields;
          setHeaders(fields);
          setPreviewRows((results.data as Record<string, string>[]) || []);

          // Auto-match fields intelligently
          const findCol = (terms: string[]) =>
            fields.find((f) => terms.some((t) => f.toLowerCase().includes(t))) || '';

          setMapping((prev) => ({
            ...prev,
            idColumn: findCol(['id', 'event_id', 'alert_id', 'uuid']) || fields[0],
            timestampColumn: findCol(['time', 'date', 'timestamp', 'created']) || fields[1] || '',
            sourceIpColumn: findCol(['src_ip', 'src', 'source_ip', 'attacker_ip', 'client_ip']) || fields[2] || '',
            destinationIpColumn: findCol(['dest_ip', 'dst_ip', 'target_ip', 'server_ip']) || fields[3] || '',
            attackCategoryColumn: findCol(['threat_category', 'attack_type', 'category', 'signature_group', 'class']) || fields[4] || '',
            severityColumn: findCol(['threat_level', 'severity', 'level', 'priority', 'score']) || '',
            descriptionColumn: findCol(['alert_summary', 'description', 'message', 'msg', 'summary', 'detail']) || '',
            assetIdColumn: findCol(['target_asset_id', 'asset_id', 'host_id', 'device_id']) || '',
            assetNameColumn: findCol(['target_hostname', 'hostname', 'host', 'asset_name']) || '',
            assetCriticalityColumn: findCol(['asset_tier', 'criticality', 'tier']) || '',
            relatedCveColumn: findCol(['cve_reference', 'cve', 'cve_id']) || '',
            detectionRuleColumn: findCol(['signature_id', 'rule_id', 'rule', 'signature']) || '',
            statusColumn: findCol(['incident_state', 'status', 'state']) || '',
          }));
        }
      },
    });
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const text = event.target?.result as string;
        handleContentParsed(text);
      };
      reader.readAsText(file);
    }
  };

  const handleImport = async () => {
    if (!mapping.idColumn || !mapping.timestampColumn || !mapping.sourceIpColumn || !mapping.destinationIpColumn || !mapping.descriptionColumn) {
      setStatusMsg({
        type: 'error',
        text: 'Please select mapping columns for ID, Timestamp, Source IP, Destination IP, and Description.',
      });
      return;
    }

    setIsProcessing(true);
    setStatusMsg(null);

    try {
      const res = await importCustomCsv(csvContent, mapping);
      if (res.errors.length > 0) {
        setStatusMsg({
          type: 'error',
          text: `Import finished with warnings: ${res.errors.join('; ')}`,
        });
      } else {
        setStatusMsg({
          type: 'success',
          text: `Successfully normalized and imported ${res.count} cybersecurity events into SQLite!`,
        });
      }
    } catch (err: any) {
      setStatusMsg({
        type: 'error',
        text: err.message || 'Import failed',
      });
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
      <div className="relative w-full max-w-4xl bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <FileSpreadsheet className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">Generic CSV Dataset Importer &amp; Column Mapper</h3>
              <p className="text-xs text-slate-400">
                Maps external cybersecurity datasets (SOC logs, IDS captures, honeypots) to internal SecurityEvent schema.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white px-2 py-1 text-sm rounded bg-slate-800"
          >
            ✕
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Step 1: Upload or Paste */}
          <div className="space-y-2">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              1. Provide External CSV File or Text
            </label>
            <div className="flex gap-4 items-center">
              <label className="flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold cursor-pointer transition-colors shadow">
                <Upload className="w-4 h-4" /> Upload .CSV File
                <input type="file" accept=".csv" onChange={handleFileUpload} className="hidden" />
              </label>
              <button
                type="button"
                onClick={async () => {
                  try {
                    const res = await fetch('/api/datasets/historical');
                    if (res.ok) {
                      const text = await res.text();
                      handleContentParsed(text);
                    }
                  } catch (e) {
                    console.error(e);
                  }
                }}
                className="px-3 py-2 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
              >
                Load Bundled Historical Dataset
              </button>
              {headers.length > 0 && (
                <span className="text-xs text-emerald-400 flex items-center gap-1 font-medium">
                  <Check className="w-3.5 h-3.5" /> {headers.length} columns detected
                </span>
              )}
            </div>
          </div>

          {/* Step 2: Mapping Grid */}
          {headers.length > 0 && (
            <div className="space-y-3">
              <label className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                2. Configure Column Mapping into Internal Schema
              </label>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 p-4 bg-slate-950/70 border border-slate-800 rounded-lg">
                {[
                  { label: 'Event ID (Required)*', key: 'idColumn' },
                  { label: 'Timestamp (Required)*', key: 'timestampColumn' },
                  { label: 'Source IP (Required)*', key: 'sourceIpColumn' },
                  { label: 'Destination IP (Required)*', key: 'destinationIpColumn' },
                  { label: 'Attack Category*', key: 'attackCategoryColumn' },
                  { label: 'Severity Level', key: 'severityColumn' },
                  { label: 'Description / Summary (Required)*', key: 'descriptionColumn' },
                  { label: 'Target Asset ID', key: 'assetIdColumn' },
                  { label: 'Target Hostname', key: 'assetNameColumn' },
                  { label: 'Asset Tier / Criticality', key: 'assetCriticalityColumn' },
                  { label: 'Related CVE ID', key: 'relatedCveColumn' },
                  { label: 'Detection Signature / Rule', key: 'detectionRuleColumn' },
                  { label: 'Incident State / Status', key: 'statusColumn' },
                ].map((item) => (
                  <div key={item.key} className="space-y-1">
                    <label className="text-[11px] font-medium text-slate-400">{item.label}</label>
                    <select
                      value={(mapping as any)[item.key] || ''}
                      onChange={(e) => setMapping({ ...mapping, [item.key]: e.target.value })}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                    >
                      <option value="">-- Select CSV Header --</option>
                      {headers.map((h) => (
                        <option key={h} value={h}>
                          {h}
                        </option>
                      ))}
                    </select>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Preview Table */}
          {previewRows.length > 0 && (
            <div className="space-y-2">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                Source Data Preview (First 3 Rows)
              </span>
              <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-40">
                <table className="w-full text-left text-[11px] font-mono">
                  <thead className="bg-slate-800/80 text-slate-300">
                    <tr>
                      {headers.map((h) => (
                        <th key={h} className="py-1 px-2.5 whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-400">
                    {previewRows.slice(0, 3).map((r, idx) => (
                      <tr key={idx}>
                        {headers.map((h) => (
                          <td key={h} className="py-1 px-2.5 whitespace-nowrap">{r[h]}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Status Message */}
          {statusMsg && (
            <div
              className={`p-3 rounded-lg text-xs flex items-center gap-2 border ${
                statusMsg.type === 'success'
                  ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-800 text-rose-300'
              }`}
            >
              {statusMsg.type === 'success' ? (
                <Check className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              )}
              <span>{statusMsg.text}</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950 flex justify-between items-center">
          <span className="text-xs text-slate-400">
            Internal Target: <code className="text-sky-300 font-mono">CRISP SecurityEvent</code>
          </span>
          <div className="flex gap-2">
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleImport}
              disabled={isProcessing || headers.length === 0}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white shadow transition-colors"
            >
              {isProcessing ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Normalizing &amp; Saving...
                </>
              ) : (
                'Import &amp; Ingest into SQLite'
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
