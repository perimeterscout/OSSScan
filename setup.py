"""Setup configuration for OSS Risk Scanner."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="oss-risk-scanner",
    version="1.0.0",
    author="OSS Risk Scanner Team",
    description="A tool for analyzing open-source software security and maintenance risks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/perimeterscout/OSSScan",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.25.0",
    ],
    entry_points={
        "console_scripts": [
            "oss-scan=oss_scanner.cli:main",
        ],
    },
)
