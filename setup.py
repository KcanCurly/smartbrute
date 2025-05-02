from setuptools import setup, find_packages

setup(
    name="smartbrute",
    version="1.0.0",
    author="KcanCurly",
    description="A script to brute ldap without blocking account.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/KcanCurly/smartbrute",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "ldap3",
        "toml",
        "pytz",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.12",
    entry_points={
        "console_scripts": [
            "smartbrute=smartbrute.main:main",  
        ],
    },
)