import json
import logging
import os

import click
import tqdm

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
              type=click.Path(file_okay=True, dir_okay=False, readable=True, exists=True), required=True)
@click.option('-r', '--rule', help='Json Rule',
              type=click.Path(file_okay=False, dir_okay=True, readable=True, exists=True), required=False)
@click.option('-t', '--thershold', help='Filter for displaying crimes', type=click.IntRange(0, 100), required=False)
@click.option('-o', '--output', help="Report as a json file", type=click.File('w', lazy=True), required=False)
@click.option('-s', '--summary', help="Summary report", is_flag=True)
def main(apk, rule, thershold, output, summary):
    logging.basicConfig(level=logging.WARN)
    print(f'Apk File: {apk}')
    print(f'Rule Directory: {rule}', )

    if output:
        print(f'Generate Json File: {output.name}')

    if thershold:
        print(f'Thershold:{thershold}%')

    counter = 0
    displayed = 0

    quark = Quark(apk)

    # Analyzing
    for rule_file in tqdm.tqdm(get_rules_from_directory(rule)):
        rule = QuarkRule(rule_file)
        quark.analysis_rule(rule)
        counter = counter + 1

    # Summarizing
    if summary:
        for rule, behavior_list in quark.report.passed_behaviors.items():
            max_stage = max(
                [behavior.reached_stage for behavior in behavior_list])

            if thershold and max_stage*20 < thershold:
                continue

            print(f'Crime @ {rule.crime:<80} {max_stage*20:>3}%')
            displayed = displayed + 1

        print(f'Total: {displayed}/{counter}')
    else:
        print(f'Total: {counter}')

    # Generate json file
    if output:
        json.dump(quark.report.get_json_report(), output, indent=4)


if __name__ == '__main__':
    main()
