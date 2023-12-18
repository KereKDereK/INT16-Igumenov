from datetime import datetime
from re import split
from json import dumps, loads
from types import SimpleNamespace


# region Task_2
class Vulnerability:
    def __init__(self, name: str, count: int):
        self.name = name
        self.count = count


class Report:
    def __init__(self, vulnerabilities: list[Vulnerability] = None):
        self.vulnerabilities = vulnerabilities

    def to_json(self, name: str = "NoNameGiven") -> None:
        """
        Function that converts objects data to string and then writes it in new json-file.
        :param name: desired json-file name
        :return: None
        """
        vulnerabilities_dump = dumps(self, default=lambda o: o.__dict__, indent=4)
        with open(f'./formatted_reports/{name}.json', 'w') as report:
            report.write(vulnerabilities_dump)


def format_json(path: str) -> None:
    """
    Created for formatting OWASP ZAP report json-file to our standardized json file format.
    :param path: path to OWASP ZAP report json-file.
    :return: None
    """
    with open(path, "r") as file:
        report = loads(file.read(), object_hook=lambda d: SimpleNamespace(**d))

    for site in report.site:
        vulnerabilities = [Vulnerability(alert.name, alert.count) for alert in site.alerts]
        name_str = f'{getattr(site, "@host")}-{datetime.now().strftime("%Y%m%d")}'
        formatted_report = Report(vulnerabilities)
        formatted_report.to_json(name_str)
# endregion


# region Task_1
def title(input_str: str = '') -> str:
    """
    Simple alternative to str.title()
    :param input_str: string that need capitalization
    :return: capitalized string
    """
    titled_str = '' if len(input_str) == 0 else ''.join([x[0].upper() + x[1:] for x in split(r'(\s+)', input_str)
                                                         if len(x) > 0])
    print(titled_str)
    return titled_str
# endregion


if __name__ == '__main__':
    title("smthm    m  k jbohoi h oh ihi hiI HO O O oiH OI \t  test TetSTET +_-2340661DSF)SD)f42   \n  ff\n   ADFA ")
    format_json('./reports/2023-12-17-ZAP-Report-.json')
