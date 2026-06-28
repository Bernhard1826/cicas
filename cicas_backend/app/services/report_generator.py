"""
Report generator for update results
"""
from typing import Dict, Any, List
from datetime import datetime
from app.core.logging_config import app_logger


class ReportGenerator:
    """Generate reports for update operations"""

    def generate_update_report(self, update_result: Dict[str, Any]) -> str:
        """
        Generate formatted update report

        Args:
            update_result: Update result dictionary

        Returns:
            Formatted report string
        """
        try:
            lines = []

            # Header
            lines.append("=" * 60)
            lines.append("PKI Standards Update Report")
            lines.append("=" * 60)
            lines.append(f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
            lines.append("")

            # Summary
            lines.append("[CHART] Summary:")
            lines.append(f"  [OK] Sources Processed: {len(update_result.get('sources_processed', []))}")
            lines.append(f"  ➕ Rules Added: {update_result.get('total_rules_added', 0)}")
            lines.append(f"  [SYNC] Rules Updated: {update_result.get('total_rules_updated', 0)}")
            lines.append(f"  [WARNING]  Errors: {len(update_result.get('errors', []))}")
            lines.append("")

            # Source details
            if update_result.get('sources_processed'):
                lines.append("📁 Source Details:")
                for source_result in update_result['sources_processed']:
                    source = source_result.get('source', 'Unknown')
                    status = source_result.get('status', 'unknown')
                    status_icon = "[OK]" if status == 'success' else "[X]"

                    lines.append(f"  {status_icon} {source}:")
                    if status == 'success':
                        lines.append(f"    - Added: {source_result.get('rules_added', 0)} rules")
                        lines.append(f"    - Updated: {source_result.get('rules_updated', 0)} rules")
                    else:
                        lines.append(f"    - Error: {source_result.get('error', 'Unknown')}")

                lines.append("")

            # Errors
            if update_result.get('errors'):
                lines.append("[WARNING]  Errors:")
                for error in update_result['errors']:
                    lines.append(f"  - {error}")
                lines.append("")

            # Footer
            lines.append("=" * 60)

            report = "\n".join(lines)
            return report

        except Exception as e:
            app_logger.error(f"Error generating report: {e}")
            return f"Error generating report: {e}"

    def generate_stats_report(self, stats: Dict[str, Any]) -> str:
        """
        Generate statistics report

        Args:
            stats: Statistics dictionary

        Returns:
            Formatted report string
        """
        try:
            lines = []

            lines.append("=" * 60)
            lines.append("PKI Standards Database Statistics")
            lines.append("=" * 60)
            lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
            lines.append("")

            lines.append("[CHART] Overview:")
            lines.append(f"  📚 Total Standards: {stats.get('total_standards', 0)}")
            lines.append(f"  📝 Total Rules: {stats.get('total_rules', 0)}")
            lines.append(f"  [OK] Active Rules: {stats.get('active_rules', 0)}")
            lines.append(f"  [WARNING]  Rules Need Review: {stats.get('rules_need_review', 0)}")
            lines.append("")

            if stats.get('last_update'):
                lines.append(f"🕒 Last Update: {stats['last_update']}")
            else:
                lines.append("🕒 Last Update: Never")

            lines.append("")
            lines.append("=" * 60)

            return "\n".join(lines)

        except Exception as e:
            app_logger.error(f"Error generating stats report: {e}")
            return f"Error generating stats report: {e}"

    def generate_simple_report(self, summary: Dict[str, Any]) -> str:
        """
        Generate simple one-line summary

        Args:
            summary: Summary dictionary

        Returns:
            Simple report string
        """
        return (
            f"[OK] Update completed: "
            f"{summary.get('total_rules_added', 0)} added, "
            f"{summary.get('total_rules_updated', 0)} updated, "
            f"{len(summary.get('errors', []))} errors"
        )
