import click
import logging
import os

from quark.core.quark import Quark;
from quark.core.rule import QuarkRule


def get_rules_from_directory(dir_path):

    for file in os.listdir(dir_path):
        rule_file = os.path.join(dir_path, file)

        if not os.path.isfile(rule_file) or not rule_file.endswith('.json'):
            continue

        yield rule_file


@click.command()
@click.option('-a', '--apk', help='Apk File',
              type=click.Path(file_okay=True, dir_okay=False, readable=True, exists=True))
@click.option('-r', '--rule', help='Json Rule',
              type=click.Path(file_okay=False, dir_okay=True, readable=True, exists=True))
def main(apk, rule):
    logging.basicConfig(level=logging.DEBUG, )
    logging.info(f'Apk File: {apk}')
    logging.info(f'Rule Directory: {rule}', )

    quark = Quark(apk)

    for rule_file in get_rules_from_directory(rule):
        rule = QuarkRule(rule_file)

        quark.analysis(rule)
        logging.info(
            f'{rule.crime:<80} {quark.analysis_report.get_rule_passed(rule):>2}')


if __name__ == '__main__':
    main()
