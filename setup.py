import os
from setuptools import setup


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as f:
        return f.read()


def get_version():
    with open("mobiledetect/version.py") as f:
        line = f.readline()
        version = line.split("=")[1].strip().strip('"')
        return version


setup(
    name="MobileDetectPy",
    version=get_version(),
    author="Loop11",
    author_email="tzemanovic@loop11.com",
    description="Detect mobile and tablet browsers",
    license="AGPL",
    keywords="mobile tabled detect browser",
    url="https://github.com/Loop11/pymobiledetect",
    packages=['mobiledetect', 'mobiledetect.test'],
    package_data={
        'mobiledetect': ['Mobile_Detect.json'],
        'mobiledetect.test': ['test_user_agents.json']
    },
    test_suite='nose.collector',
    long_description=read('README.md'),
    install_requires=[
        'six',
    ],
    tests_require=['six', 'nose'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",  # NOQA
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware",
        "Topic :: Software Development :: Libraries",
    ], )
