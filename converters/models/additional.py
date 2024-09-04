import hashlib
from dataclasses import dataclass
from html_sanitizer import Sanitizer
import re


@dataclass(kw_only=False, eq=False, order=False)
class AdditionalFields:
    dupe_key: str | None = None
    ruleId: str | None = None
    rule_description: str | None = None
    reason: str | None = None
    secret: str | None = None
    file_key: str | None = None
    sanitizer = Sanitizer()

    def __parse_url(self) -> None:
        if not self.url and "URL:" in self.description:
            urls = re.findall(r'(https?://[^\s]+)', self.description)
            self.url = '\n'.join(x.replace('\n', '') for x in urls)

    def __parse_rule_id(self) -> None:
        # Trying to use title for DAST
        if hasattr(self, "unsaved_endpoints") and isinstance(self.unsaved_endpoints, list):
            self.ruleId = self.title
            return
        if "**Rule Id:**" in self.description:
            self.ruleId = self.description.split("**Rule Id:** ")[1].split("\n")[0]
        elif "Rule Id:" in self.description:
            dirty = self.description.split("Rule Id:")[1].split("\n")[0]
            self.ruleId = self.sanitizer.sanitize(dirty).strip('"`,;{}()%*[]^:/\\@~\'').strip()
        elif self.vuln_id_from_tool:
            if not self.ruleId:
                self.ruleId = self.vuln_id_from_tool
        elif "Reason:" in self.description:
            self.ruleId = self.description.split("**Reason:** ")[1].split("\n")[0]
        elif self.reason:
            self.ruleId = self.reason

    def __parse_reason(self) -> None:
        # Пример: "Hard coded {reason} found in {file_path}"
        #            0    1     !2!      3    4      5
        if not self.reason and self.title:
            self.reason = self.title.split()[2] if len(self.title.split()) > 2 else None

        if not self.reason and self.vuln_id_from_tool:
            self.reason = self.vuln_id_from_tool

    def __parse_secret(self) -> None:
        if not self.code:

            if "**Secret:**" in self.description:
                self.secret = self.description.split("**Secret:** ")[1].split("\n")[0]
            elif "Secret:" in self.description:
                self.secret = self.sanitizer.sanitize(
                    self.description.replace('\\n','\n').split("Secret:")[1].split("\n")[0]).strip()
            elif "Snippet:" in self.description:
                self.secret = self.description.split("**Snippet:**\n")[1]
            elif "String Found:" in self.description:
                self.secret = self.description.split("**String Found:**\n")[1]
            elif "Code:" in self.description:
                try:
                    self.secret = self.description.split("**Code:**\n")[1]
                except IndexError:
                    self.secret = self.description.split("Code:\n")[1]
            elif "Code flow:" in self.description:
                self.secret = self.description.split("**Code flow:**\n")[1]
            if self.secret:
                self.secret = self.secret.strip().replace("```", "")

            elif "\nAt " in self.description:
                self.secret = self.description.split("\nAt ")[-1].split("\n")[0]

            self.code = self.secret

    def __parse_file_key(self) -> None:
        if self.file_path is not None:
            self.file_key = hashlib.md5(
                self.file_path.encode('utf-8')
            ).hexdigest()
        elif self.url is not None:
            self.file_key = hashlib.md5(
                self.url.encode('utf-8')
            ).hexdigest()
        elif self.component_name is not None and self.component_version is not None:
            self.file_key = self.component_name + '@' + self.component_version
        else:
            self.file_key = 'Unknown'

    def __parse_dupe_key(self) -> None:
        try:
            key = self.title
            if self.secret:
                key = key + self.secret
            if self.line:
                key = key + str(self.line)
            self.dupe_key = hashlib.md5((key + self.file_path + self.description).encode("utf-8")).hexdigest()
        except TypeError:
            self.dupe_key = hashlib.md5(
                (
                        self.title +
                        self.description
                 ).encode("utf-8")
            ).hexdigest()

    def __parse_rule_description(self) -> None:
        # Trying to use title for DAST
        if hasattr(self, "unsaved_endpoints") and isinstance(self.unsaved_endpoints, list):
            self.rule_description = self.title + '\n\n' + self.impact + '\n' + self.mitigation
        else:
            self.rule_description = self.reason if self.reason else "Unknown"
            if self.reason and self.references:
                self.rule_description += '\n' + self.references

    def parse_additional_fields(self) -> None:
        self.__parse_url()
        self.__parse_rule_id()
        self.__parse_reason()
        self.__parse_secret()
        self.__parse_file_key()
        self.__parse_dupe_key()
        self.__parse_rule_description()

    def check_additional_fields(self) -> None:
        if not self.ruleId:
            raise ValueError("ruleId not found")
