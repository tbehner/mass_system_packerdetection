import os
import requests

import mass_api_client
from mass_api_client import resources as mass
from common_analysis_yara import CommonAnalysisYara
from mass_api_client.utils import *
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('Packerdetection')
logger.setLevel(logging.INFO)

YARA_RULES_URL = 'https://raw.githubusercontent.com/Yara-Rules/rules/master/Packers/packer.yar'
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


class PackerAnalysisInstance():
    def __init__(self):
        try:
            result = requests.get(YARA_RULES_URL)
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout):
            yara_file = './packer.yar'
            result = open(yara_file, 'r').read()
            logger.info('Could not go online for fresh yara rules. Using {}'.format(yara_file))
        self.yara = CommonAnalysisYara(yara_rules_string=result.text)

    def do_analysis(self, scheduled_analysis):
        logging.info('Processing {}'.format(scheduled_analysis))
        sample = scheduled_analysis.get_sample()
        with sample.temporary_file() as sample_file:
            yara_report = self.yara.analyze_file(sample_file.name)
            tags = []
            for match in yara_report['yara_result']:
                tags.append('packer:' + match.rule)
                packer_families = _get_packer_families(match.rule)
                tags.extend(packer_families)
            logging.info('Submitting report. Adding tags {}'.format(tags))
            scheduled_analysis.create_report(tags=tags, additional_metadata={'yara_result': str(yara_report['yara_result'])})

if __name__ == "__main__"   :
    api_key = os.getenv('MASS_API_KEY', '')
    logger.info('Got API KEY {}'.format(api_key))
    server_addr = os.getenv('MASS_SERVER', 'http://localhost:8000/api/')
    logger.info('Connecting to {}'.format(server_addr))
    timeout = int(os.getenv('MASS_TIMEOUT', '60'))
    mass_api_client.ConnectionManager().register_connection('default', api_key, server_addr, timeout=timeout)

    analysis_system_instance = get_or_create_analysis_system_instance(identifier='packerdetection',
                                                                      verbose_name= 'PackerDetection',
                                                                      tag_filter_exp='sample-type:executablebinarysample',
                                                                      )
    packer_detection = PackerAnalysisInstance()
    process_analyses(analysis_system_instance, packer_detection.do_analysis, sleep_time=7)
