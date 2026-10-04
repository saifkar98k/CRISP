import React, { useState } from 'react';
import { useCrisp } from '../context/CrispContext';
import { CsvColumnMapping } from '../types/config';
import { DataSourceBadge } from '../components/DataSourceBadge';
import {
  FileSpreadsheet,
  Upload,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Code,
} from 'lucide-react';
import Papa from 'papaparse';
import defaultMappingConfig from '../data/default_csv_mapping.json';

export const DataImporterView: React.FC = () => {
  const { importCustomCsv, setActiveTab } = useCrisp();

  const [csvText, setCsvText] = useState('');
  const [headers, setHeaders] = useState<string[]>([]);
  const [previewRows, setPreviewRows] = useState<Record<string, string>[]>([]);
  const [mapping, setMapping] = useState<CsvColumnMapping>((defaultMappingConfig as any).mapping);
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  const handleParseText = (raw: string) => {
    setCsvText(raw);
    setStatusMessage(null);

    Papa.parse(raw, {
      header: true,
      skipEmptyLines: true,
      preview: 5,
      complete: (res) => {
        if (res.meta.fields && res.meta.fields.length > 0) {
          setHeaders(res.meta.fields);
          setPreviewRows((res.data as Record<string, string>[]) || []);
        }
      },
    });
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        handleParseText(event.target?.result as string);
      };
      reader.readAsText(file);
    }
  };

  const handleRunImport = async () => {
    if (!csvText.trim()) {
      setStatusMessage({ type: 'error', text: 'Please upload or paste CSV text first.' });
      return;
    }

    setIsProcessing(true);
    setStatusMessage(null);

    try {
      const res = await importCustomCsv(csvText, mapping);
      if (res.errors.length > 0) {
        setStatusMessage({
          type: 'error',
          text: `Import completed with warnings: ${res.errors.join('; ')}`,
        });
      } else {
        setStatusMessage({
          type: 'success',
          text: `Success! Successfully normalized and committed ${res.count} events into SQLite database.`,
        });
      }
    } catch (err: any) {
      setStatusMessage({ type: 'error', text: err.message || 'Import error occurred.' });
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900 border border-slate-800">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-xl font-bold text-white tracking-tight">
              Generic CSV Data Provider &amp; Dynamic Column Mapper
            </h2>
            <DataSourceBadge origin="HISTORICAL_DATASET" size="sm" />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Map external cybersecurity datasets into the CRISP internal SecurityEvent schema using configurable column mappings.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={async () => {
              try {
                const res = await fetch('/api/datasets/historical');
                if (res.ok) {
                  const t = await res.text();
                  handleParseText(t);
                }
              } catch (e) {
                console.error(e);
              }
            }}
            className="px-3.5 py-2 rounded-lg bg-sky-700 hover:bg-sky-600 text-white text-xs font-semibold shadow transition-colors"
          >
            Load Pre-Configured Historical Dataset
          </button>
        </div>
      </div>

      {/* Upload & Mapping Card */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Input & Preview */}
        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Upload className="w-4 h-4 text-sky-400" />
              <span>Step 1: Ingest External CSV File or Payload</span>
            </h3>
            <label className="cursor-pointer px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition-colors">
              Choose File
              <input type="file" accept=".csv" onChange={handleFileUpload} className="hidden" />
            </label>
          </div>

          <textarea
            value={csvText}
            onChange={(e) => handleParseText(e.target.value)}
            rows={10}
            placeholder="Paste raw CSV data here with headers in row 1..."
            className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono text-cyan-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
          />

          {headers.length > 0 && (
            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-300">
                Detected Headers ({headers.length}):
              </span>
              <div className="flex flex-wrap gap-1.5">
                {headers.map((h) => (
                  <span
                    key={h}
                    className="font-mono text-[11px] px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-400"
                  >
                    {h}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right: Column Mapping Configuration */}
        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Code className="w-4 h-4 text-amber-400" />
              <span>Step 2: Map Headers into CRISP Internal Schema</span>
            </h3>
            <span className="text-[11px] font-mono text-slate-400">
              Profile: {defaultMappingConfig.profileId}
            </span>
          </div>

          <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
            {[
              { label: 'Event ID (Required)*', key: 'idColumn' },
              { label: 'Timestamp (Required)*', key: 'timestampColumn' },
              { label: 'Source IP Address (Required)*', key: 'sourceIpColumn' },
              { label: 'Destination IP Address (Required)*', key: 'destinationIpColumn' },
              { label: 'Attack Classification Category*', key: 'attackCategoryColumn' },
              { label: 'Severity Level', key: 'severityColumn' },
              { label: 'Alert Summary / Description (Required)*', key: 'descriptionColumn' },
              { label: 'Target Asset ID', key: 'assetIdColumn' },
              { label: 'Target Hostname', key: 'assetNameColumn' },
              { label: 'Asset Tier / Criticality', key: 'assetCriticalityColumn' },
              { label: 'Associated CVE ID', key: 'relatedCveColumn' },
              { label: 'Detection Signature / Rule', key: 'detectionRuleColumn' },
              { label: 'Incident State / Status', key: 'statusColumn' },
            ].map((field) => (
              <div key={field.key} className="flex items-center justify-between gap-3 text-xs">
                <label className="text-slate-300 font-medium">{field.label}:</label>
                <select
                  value={(mapping as any)[field.key] || ''}
                  onChange={(e) => setMapping({ ...mapping, [field.key]: e.target.value })}
                  className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono w-48"
                >
                  <option value="">-- Unmapped --</option>
                  {headers.map((h) => (
                    <option key={h} value={h}>
                      {h}
                    </option>
                  ))}
                </select>
              </div>
            ))}
          </div>

          <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
            <button
              onClick={() => setMapping((defaultMappingConfig as any).mapping)}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              Reset to Default Profile
            </button>

            <button
              onClick={handleRunImport}
              disabled={isProcessing || !csvText.trim()}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white text-xs font-semibold shadow transition-colors"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{isProcessing ? 'Normalizing & Saving...' : 'Run Pipeline & Save to SQLite'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Status banner */}
      {statusMessage && (
        <div
          className={`p-4 rounded-xl text-xs flex items-center gap-3 border ${
            statusMessage.type === 'success'
              ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
              : 'bg-rose-950/40 border-rose-800 text-rose-300'
          }`}
        >
          {statusMessage.type === 'success' ? (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          ) : (
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
          )}
          <span className="font-medium">{statusMessage.text}</span>
        </div>
      )}
    </div>
  );
};
