from setuptools import find_packages, setup


def descriptions():
    with open('README.md') as fh:
        ret = fh.read()
        first = ret.split('\n', 1)[0].replace('#', '')
        return first, ret


def version():
    with open('octodns_powerdns/__init__.py') as fh:
        for line in fh:
            if line.startswith('__VERSION__'):
                return line.split("'")[1]


description, long_description = descriptions()

tests_require = (
    'pytest',
    'pytest-cov',
    'pytest-network',
    'requests_mock'
)

setup(
    author='Ross McFaland',
    author_email='rwmcfa1@gmail.com',
    description=description,
    extras_require={
        'dev': tests_require + (
            'build>=0.7.0',
            'pycodestyle>=2.6.0',
            'pyflakes>=2.2.0',
            'readme_renderer[md]>=26.0',
            'twine>=3.4.2',
        ),
    },
    install_requires=(
        'octodns>=0.9.16',
        'requests>=2.26.0',
    ),
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    name='octodns-powerdns',
    packages=find_packages(),
    python_requires='>=3.6',
    tests_require=tests_require,
    url='https://github.com/octodns/octodns-powerdns',
    version=version(),
)
