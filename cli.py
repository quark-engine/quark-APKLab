from quark.core.quark import Quark

import click
import os

from quark.core.rule import QuarkRule


@click.command()
@click.option('-a', '--apk', help='Apk File',
              type=click.Path(file_okay=True, dir_okay=False, readable=True, exists=True))
@click.option('-r', '--rule', help='Json Rule',
              type=click.Path(file_okay=False, dir_okay=True, readable=True, exists=True))
def main(apk, rule):
    q = Quark(apk)

    for file in os.listdir(rule):
        rulepath = os.path.join(rule, file)
        if os.path.isfile(rulepath) and file.endswith('.json'):
            result = q.analysis(QuarkRule(rulepath))

            print(f'Rule:{file} -> {result}')


if __name__ == '__main__':
    main()
