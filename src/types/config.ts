/**
 * Configuration schema for CSV/JSON Data Provider
 * Allows dynamic mapping of external column names to CRISP internal SecurityEvent fields
 */

export interface CsvColumnMapping {
  // Required internal fields
  idColumn: string;
  timestampColumn: string;
  sourceIpColumn: string;
  destinationIpColumn: string;
  attackCategoryColumn: string;
  severityColumn: string;
  descriptionColumn: string;

  // Optional internal fields
  assetIdColumn?: string;
  assetNameColumn?: string;
  assetCriticalityColumn?: string;
  relatedCveColumn?: string;
  detectionRuleColumn?: string;
  statusColumn?: string;

  // Transformations and defaults
  defaultSeverity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  defaultAttackCategory?: string;
  dateFormat?: string;
  delimiter?: string;
}

export interface CsvDatasetProfile {
  id: string;
  name: string;
  description: string;
  sourceUrlOrName: string;
  isRealCybersecurityData: boolean;
  mapping: CsvColumnMapping;
}
