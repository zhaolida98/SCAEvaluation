field_names = [
            "Library",
            "Scope",
            "Library Version",
            "File Path",
            "Vulnerabilities",
            "License",
            "Language",
            "Recommended upgrade",
            "Vulnerability List",
        ]

class ComponentReport:
    def __init__(self, library, version, scope='-'):
        if ' ' in library:
            tmp_library = library.split(' ')
            library = f"{tmp_library[1]}:{tmp_library[0]}"
        self.info = {
            "Library": library,
            "Scope": scope,
            "Library Version": version,
            "File Path": "",
            "Vulnerabilities": "",
            "License": "",
            "Language": "",
            "Recommended upgrade": "",
            "Vulnerability List": [],
        }

    def set_field(self, key, value):
        if self.info.__contains__(key):
            self.info[key] = value
            return 0
        else:
            return 1

    def get_vul_list(self):
        return self.info["Vulnerability List"]

    def get_hash(self):
        return self.info['Library'] + ":" + self.info['Library Version']