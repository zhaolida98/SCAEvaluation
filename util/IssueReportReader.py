import csv
import os


class IssueReportReader:
    """
    read the component report and output is a list of component. Format:
    [
        {
            "publicId": id,
            "componentId": G:A:V
        },
        ...
    ]
    """
    def __init__(self, report_path):
        self.issue_report_path = report_path
        self.report_dict = []
        self.tool_name = os.path.basename(report_path).split('-')[0]

    def get_report_dict(self):
        with open(self.issue_report_path, mode="r", encoding="UTF-8") as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                issue = {}
                raw_library = row["Library"].replace("None", "").strip().lower().strip('-')
                if " " in raw_library:
                    raw_org, raw_lib = raw_library.split(" ")
                    raw_version = row["Library Version"].strip(' ')
                else:
                    raw_lib = raw_library.split(" ")
                    raw_org = raw_lib
                    raw_version = row["Library Version"].strip(' ')
                issue['componentId'] = f"{raw_org}:{raw_lib}:{raw_version}"
                issue['publicId'] = row['Public ID']
                self.report_dict.append(issue)
        return self.report_dict
