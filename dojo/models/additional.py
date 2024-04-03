import hashlib
from dataclasses import dataclass


@dataclass(kw_only=False, eq=False, order=False)
class AdditionalFields:
    dupe_key: str | None = None
    ruleId: str | None = None
    rule_description: str | None = None
    reason: str | None = None
    secret: str | None = None
    file_key: str | None = None

    def parse_additional_fields(self):
        if "Rule Id" in self.description:
            self.ruleId = self.description.split("**Rule Id:** ")[1].split("\n")[0]

        # Пример: "Hard coded {reason} found in {file_path}"
        #            0    1     !2!      3    4      5
        if self.title:
            self.reason = self.title.split()[2] if len(self.title.split()) > 2 else None

        if "Secret:" in self.description:
            self.secret = self.description.split("**Secret:** ")[1].split("\n")[0]

        if self.file_path is not None:
            self.file_key = hashlib.md5(
                self.file_path.encode('utf-8')
            ).hexdigest()

        try:
            self.dupe_key = hashlib.md5(
                (self.title + self.secret + str(self.line)).encode("utf-8")
            ).hexdigest()
        except TypeError:
            self.dupe_key = self.title + self.file_path + str(self.line)

        self.rule_description = f'Hard coded {self.reason}'
