import csv


class ComponentReportReader:
    """
    read the component report and output is a list of component. Format:
    [
        {
            "artifactId": A,
            "groupId": G,
            "version": V,
            "hash": G:A:V
        },
        ...
    ]
    """
    def __init__(self, report_path):
        self.component_report_path = report_path
        self.report_dict = []

    def get_report_dict(self):
        with open(self.component_report_path, mode="r", encoding="UTF-8") as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                component = {}
                raw_library = row["Library"].replace("None", "").strip().lower().strip('-')
                if " " in raw_library:
                    if len(raw_library.split(" ")) == 2:
                        raw_lib, raw_org = raw_library.split(" ")
                        component['artifactId'] = raw_lib.strip('-').strip(' ')
                        component['groupId'] = raw_org.strip(' ')
                        component['version'] = row["Version"].strip(' ')
                    else:
                        component['artifactId'] = raw_library.split(" ")
                        component['groupId'] = ''
                        component['version'] = row["Version"].strip(' ')
                else:
                    component['artifactId'] = raw_library.split(" ")
                    component['groupId'] = raw_library.split(" ")
                    component['version'] = row["Version"]
                component['hash'] = f"{component['groupId']}:{component['artifactId']}:{component['version']}"
                self.report_dict.append(component)
        return self.report_dict
