"""
Report Generator
Generates HTML and TXT migration reports
"""
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import json

from database.migration_db import MigrationDB
from config import settings


class ReportGenerator:
    """Generates migration reports in HTML and TXT formats"""

    def __init__(self, migration_db: MigrationDB):
        """
        Initialize report generator

        Args:
            migration_db: Migration database instance
        """
        self.migration_db = migration_db

    def generate_html_report(self, run_id: int, output_path: Optional[Path] = None) -> Path:
        """
        Generate HTML report

        Args:
            run_id: Migration run ID
            output_path: Output file path (auto-generated if None)

        Returns:
            Path to generated report
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = settings.REPORTS_DIR / f"migration_report_{run_id}_{timestamp}.html"

        # Get statistics
        stats = self.migration_db.get_statistics(run_id)
        if not stats:
            raise ValueError(f"No statistics found for run_id {run_id}")

        # Generate HTML
        html = self._generate_html_content(stats)

        # Write file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_path

    def generate_text_report(self, run_id: int, output_path: Optional[Path] = None) -> Path:
        """
        Generate text report

        Args:
            run_id: Migration run ID
            output_path: Output file path (auto-generated if None)

        Returns:
            Path to generated report
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = settings.REPORTS_DIR / f"migration_report_{run_id}_{timestamp}.txt"

        # Get statistics
        stats = self.migration_db.get_statistics(run_id)
        if not stats:
            raise ValueError(f"No statistics found for run_id {run_id}")

        # Generate text
        text = self._generate_text_content(stats)

        # Write file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(text)

        return output_path

    def _generate_html_content(self, stats: Dict[str, Any]) -> str:
        """Generate HTML report content"""
        run_date = stats.get('run_date', 'Unknown')
        source_base_dn = stats.get('source_base_dn', 'Unknown')
        dest_base_dn = stats.get('dest_base_dn', 'Unknown')
        status = stats.get('status', 'unknown')
        duration = stats.get('duration_seconds', 0)

        # Summary
        objects_analyzed = stats.get('objects_analyzed', 0)
        objects_created = stats.get('objects_created', 0)
        objects_updated = stats.get('objects_updated', 0)
        objects_skipped = stats.get('objects_skipped', 0)
        objects_conflicted = stats.get('objects_conflicted', 0)
        errors_count = stats.get('errors_count', 0)

        # Status color
        status_color = {
            'completed': '#4CAF50',
            'failed': '#F44336',
            'cancelled': '#FF9800',
            'in_progress': '#2196F3'
        }.get(status, '#9E9E9E')

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Migration Report - Run {stats.get('run_id')}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #2196F3;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 10px;
            margin: 20px 0;
        }}
        .info-label {{
            font-weight: bold;
            color: #666;
        }}
        .status {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            background-color: {status_color};
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-card.success {{ background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%); }}
        .stat-card.warning {{ background: linear-gradient(135deg, #FF9800 0%, #F57C00 100%); }}
        .stat-card.error {{ background: linear-gradient(135deg, #F44336 0%, #E53935 100%); }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }}
        .stat-label {{
            font-size: 14px;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #2196F3;
            color: white;
            font-weight: bold;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #666;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Migration Report</h1>

        <div class="info-grid">
            <div class="info-label">Run ID:</div>
            <div>{stats.get('run_id')}</div>

            <div class="info-label">Date:</div>
            <div>{run_date}</div>

            <div class="info-label">Status:</div>
            <div><span class="status">{status.upper()}</span></div>

            <div class="info-label">Duration:</div>
            <div>{self._format_duration(duration)}</div>

            <div class="info-label">Source Base DN:</div>
            <div>{source_base_dn}</div>

            <div class="info-label">Destination Base DN:</div>
            <div>{dest_base_dn}</div>
        </div>

        <h2>Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Objects Analyzed</div>
                <div class="stat-value">{objects_analyzed}</div>
            </div>
            <div class="stat-card success">
                <div class="stat-label">Objects Created</div>
                <div class="stat-value">{objects_created}</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-label">Objects Skipped</div>
                <div class="stat-value">{objects_skipped}</div>
            </div>
            <div class="stat-card error">
                <div class="stat-label">Conflicts</div>
                <div class="stat-value">{objects_conflicted}</div>
            </div>
        </div>

        <h2>Objects by Type and Status</h2>
        {self._generate_objects_table(stats.get('objects_by_type_status', []))}

        <h2>Deferred References</h2>
        {self._generate_deferred_section(stats.get('deferred_references', {}))}

        <h2>Conflicts</h2>
        {self._generate_conflicts_section(stats.get('conflicts_count', 0))}

        <h2>Errors</h2>
        {self._generate_errors_section(stats.get('errors_by_severity', []))}

        <div class="footer">
            Generated by Directory Objects Migrator v{settings.APP_VERSION}<br>
            {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </div>
    </div>
</body>
</html>"""

        return html

    def _generate_objects_table(self, objects_by_type: list) -> str:
        """Generate objects table HTML"""
        if not objects_by_type:
            return "<p>No objects data available</p>"

        html = "<table><tr><th>Object Type</th><th>Status</th><th>Count</th></tr>"
        for entry in objects_by_type:
            obj_type = entry.get('object_type', 'unknown')
            status = entry.get('status', 'unknown')
            count = entry.get('count', 0)
            html += f"<tr><td>{obj_type}</td><td>{status}</td><td>{count}</td></tr>"
        html += "</table>"

        return html

    def _generate_deferred_section(self, deferred_stats: dict) -> str:
        """Generate deferred references section"""
        total = deferred_stats.get('total', 0)
        resolved = deferred_stats.get('resolved', 0)
        unresolved = total - resolved if total else 0

        return f"""
        <p><b>Total:</b> {total}</p>
        <p><b>Resolved:</b> {resolved}</p>
        <p><b>Unresolved:</b> {unresolved}</p>
        """

    def _generate_conflicts_section(self, conflicts_count: int) -> str:
        """Generate conflicts section"""
        return f"<p><b>Total conflicts:</b> {conflicts_count}</p>"

    def _generate_errors_section(self, errors_by_severity: list) -> str:
        """Generate errors section"""
        if not errors_by_severity:
            return "<p>No errors</p>"

        html = "<table><tr><th>Severity</th><th>Count</th></tr>"
        for entry in errors_by_severity:
            severity = entry.get('severity', 'unknown')
            count = entry.get('count', 0)
            html += f"<tr><td>{severity}</td><td>{count}</td></tr>"
        html += "</table>"

        return html

    def _generate_text_content(self, stats: Dict[str, Any]) -> str:
        """Generate text report content"""
        lines = []
        lines.append("=" * 80)
        lines.append("MIGRATION REPORT")
        lines.append("=" * 80)
        lines.append("")

        # Basic info
        lines.append(f"Run ID: {stats.get('run_id')}")
        lines.append(f"Date: {stats.get('run_date')}")
        lines.append(f"Status: {stats.get('status', 'unknown').upper()}")
        lines.append(f"Duration: {self._format_duration(stats.get('duration_seconds', 0))}")
        lines.append("")
        lines.append(f"Source Base DN: {stats.get('source_base_dn')}")
        lines.append(f"Destination Base DN: {stats.get('dest_base_dn')}")
        lines.append("")

        # Summary
        lines.append("-" * 80)
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Objects Analyzed:   {stats.get('objects_analyzed', 0)}")
        lines.append(f"Objects Created:    {stats.get('objects_created', 0)}")
        lines.append(f"Objects Updated:    {stats.get('objects_updated', 0)}")
        lines.append(f"Objects Skipped:    {stats.get('objects_skipped', 0)}")
        lines.append(f"Objects Conflicted: {stats.get('objects_conflicted', 0)}")
        lines.append(f"Errors:             {stats.get('errors_count', 0)}")
        lines.append("")

        # Objects by type
        lines.append("-" * 80)
        lines.append("OBJECTS BY TYPE AND STATUS")
        lines.append("-" * 80)
        for entry in stats.get('objects_by_type_status', []):
            obj_type = entry.get('object_type', 'unknown')
            status = entry.get('status', 'unknown')
            count = entry.get('count', 0)
            lines.append(f"{obj_type:15} {status:15} {count:5}")
        lines.append("")

        # Deferred references
        deferred_stats = stats.get('deferred_references', {})
        total = deferred_stats.get('total', 0)
        resolved = deferred_stats.get('resolved', 0)

        lines.append("-" * 80)
        lines.append("DEFERRED REFERENCES")
        lines.append("-" * 80)
        lines.append(f"Total:      {total}")
        lines.append(f"Resolved:   {resolved}")
        lines.append(f"Unresolved: {total - resolved if total else 0}")
        lines.append("")

        # Footer
        lines.append("=" * 80)
        lines.append(f"Generated by Directory Objects Migrator v{settings.APP_VERSION}")
        lines.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)

        return "\n".join(lines)

    @staticmethod
    def _format_duration(seconds: int) -> str:
        """Format duration in human-readable form"""
        if seconds < 60:
            return f"{seconds} seconds"
        elif seconds < 3600:
            minutes = seconds // 60
            secs = seconds % 60
            return f"{minutes} minutes {secs} seconds"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours} hours {minutes} minutes"


if __name__ == "__main__":
    print("=== ReportGenerator Test ===")
    print("Generates HTML and TXT migration reports")
