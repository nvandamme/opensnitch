use std::sync::Arc;

use crate::models::metrics_snapshot::MetricsSnapshot;
use crate::platform::stats::exporter_port::StatsExporterPort;

/// Fan-out adapter: dispatches `export_snapshot` to multiple inner exporters.
pub struct MultiStatsExporter {
    exporters: Vec<Arc<dyn StatsExporterPort>>,
}

impl MultiStatsExporter {
    pub fn new(exporters: Vec<Arc<dyn StatsExporterPort>>) -> Arc<Self> {
        Arc::new(Self { exporters })
    }
}

impl StatsExporterPort for MultiStatsExporter {
    fn export_snapshot(&self, snapshot: &MetricsSnapshot) {
        for exporter in &self.exporters {
            exporter.export_snapshot(snapshot);
        }
    }
}
