import click
import logging
import os

from quark.core.quark import Quark
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
@click.option('-t', '--thershold', help='Filter for displaying crimes', type=click.IntRange(0, 100), required=False)
def main(apk, rule, thershold):
    logging.basicConfig(level=logging.WARN )
    print(f'Apk File: {apk}')
    print(f'Rule Directory: {rule}', )

    if thershold:
        print(f'Thershold:{thershold}%')

    counter = 0
    displayed = 0

    quark = Quark(apk)

    for rule_file in get_rules_from_directory(rule):
        rule = QuarkRule(rule_file)
        #logging.info(f'Analysing {rule.crime}')
        quark.analysis_rule(rule)
        counter = counter + 1

        max_stage = max([behavior.reached_stage for behavior in quark.report.passed_behaviors[rule]])
        if thershold and max_stage*20 < thershold:
            continue

        print(f'Crime @ {rule.crime:<80} {max_stage*20:>3}%')
        displayed = displayed + 1
        
    print(f'Total: {displayed}/{counter}')
                

if __name__ == '__main__':
    main()
