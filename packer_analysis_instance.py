import os
import requests

from mass_client import FileAnalysisClient, temporary_sample_file
from common_analysis_yara import CommonAnalysisYara

YARA_RULES_URL = 'https://raw.githubusercontent.com/Yara-Rules/rules/master/packer.yar'
PACKER_FAMILIES = [
    'armadillo',
    'acprotect',
    'aspack',
    'asprotect',
    'codecrypt',
    'enigmaprotector',
    'exestealth',
    'expressor',
    'fsg',
    'kkrunchy',
    'mew',
    'mpress_2',
    'nspack',
    'obsidium',
    'pecompact',
    'pecrypt',
    'pelock',
    'peprotect',
    'peshield',
    'pespin',
    'petite',
    'rlpack',
    'telock',
    'themida',
    'upack',
    'upx',
    'vbox',
    'vmprotect',
    'yodasprotector'
]


def _get_packer_families(matched_rule_string):
    matched_rule_string = matched_rule_string.lower()
    result = []
    for family in PACKER_FAMILIES:
        if family in matched_rule_string:
            result.append('packerfamily:' + family)
    return result


class PackerAnalysisInstance(FileAnalysisClient):
    def __init__(self, config_object):
        super(PackerAnalysisInstance, self).__init__(config_object)
        result = requests.get(YARA_RULES_URL)
        self.yara = CommonAnalysisYara(yara_rules_string=result.text)

    def do_analysis(self, analysis_request):
        with temporary_sample_file(self.sample_dict) as file:
            yara_report = self.yara.analyze_file(file)
            tags = []
            for match in yara_report['yara_result']:
                tags.append('packer:' + match.rule)
                packer_families = _get_packer_families(match.rule)
                tags.extend(packer_families)
            self.submit_report(analysis_request['url'], tags=tags, additional_metadata={'yara_result': str(yara_report['yara_result'])})
