from setuptools import setup, find_packages

with open('Readme.md') as f:
    readme = f.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

# with open('LICENSE') as f:
#     license = f.read()

setup(
    name='smartsolar',
    version='0.1.0',
    description='Query Victron Energy SmartSolar Devices',
    long_description=readme,
    author='Jonas Höchst',
    author_email='hello@jonashoechst.de',
    url='https://github.com/trackit-system/smartsolar',
    install_requires=requirements,
    # license=license,
    packages=find_packages(exclude=('tests', 'docs')),
)
