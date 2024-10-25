import csv
import logging

from converters.models import Finding

logger = logging.getLogger(__name__)

class SvaceParser(object):
    """Parser for SVACE CSV report format."""

    def get_scan_types(self):
        return ["SVACE"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "SVACE report file can be imported in CSV format."

    def get_findings(self, filehandle, test):
        """Parse the CSV file and return findings."""
        items = list()
        reader = csv.DictReader(filehandle)
        for row in reader:
            item = self.get_item(row)
            if item is not None:
                items.append(item)
        return items

    def get_item(self, row):
        """Convert a CSV row to a Finding object."""
        finding = Finding(
            title="",
            description=self.get_description(row),
            vuln_id_from_tool=row["warnClass"], # Категория
            severity=self.get_severity(row["severity"]),
            file_path=row["file"],
            line=int(row["line"]),
            dynamic_finding=False,
            static_finding=True,
            verified=True if row["status"] == "Confirmed" else False,
            false_p=True if row["status"] == "False Positive" else False,
            risk_accepted=True if row["status"] == "Won't fix" else False,
            code=row["function"], # Не всегда будет содержать полезную информацию, но лучше, чем ничего
            rule_description="",
            reason=" ", # Если указать пустую строку, в описании появится title (если не пустой), либо vuln_id_from_tool
            references="",
            nb_occurences=1
        )
        return finding

    def get_description(self, row):
        """Generate a description for the finding."""
        description = f"**ID уязвимости:** {row['id']}\n\n"
        description += f"**Движок анализа:** {row['tool']}\n\n"
        description += f"**Язык разработки:** {row['lang']}\n\n"
        description += f"**Найденный фрагмент:** `{row['function']}`\n\n"
        description += f"**Сообщение анализатора:** {row['msg']}\n\n"
        description += f"**Предлагаемое действие:** {row['action']}\n\n"
        description += f"**Комментарии:**\n\n{self.get_comments(row)}\n"
        return description

    def get_severity(self, severity):
        """Map SVACE severity to a standard severity."""
        severity_mapping = {
            "Minor": "Low",
            "Major": "Medium",
            "Critical": "High"
        }
        return severity_mapping.get(severity, "Low")

    def get_comments(self, row):
        comments = []
        for key, value in row.items():
            if key.startswith("comment_"):
                comments.append(value + "\n\n")
        return " ".join(comments)
