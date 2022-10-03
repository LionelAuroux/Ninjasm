#!/usr/bin/env python3
import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ninjasm",
    version="0.0.1",
    include_package_data=True,
    install_requires=['wheel', 'keystone-engine'],
    package_dir={"": "."},
    packages=setuptools.find_packages(where="."),
    entry_points = {
        'console_scripts': ['ninjasm = ninjasm:main'],
        }
)
