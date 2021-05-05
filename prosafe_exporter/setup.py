import pathlib
from setuptools import find_packages, setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

README = (HERE / "README.md").read_text()
INSTALL_REQUIRED = (HERE / "requirements.txt").read_text()
SETUP_REQUIRED = (HERE / "setup_requirements.txt").read_text()
TEST_REQUIRED = (HERE / "test_requirements.txt").read_text()

setup(
    name='prosafe_exporter',
    packages=['prosafe_exporter'],
    version=open("prosafe_exporter/_version.py").readlines()[-1].split()[-1].strip("\"'"),
    description='Prometheus metrics exporter for NETGEAR switches of the Smart Managed Plus series.',
    long_description=README,
    long_description_content_type="text/markdown",
    author='Till Steinbach',
    keywords='prometheus, netgear, metrics-exporter, prosafe, prosafe-exporter',
    url='https://github.com/tillsteinbach/prosafe_exporter_python',
    license='MIT',
    install_requires=INSTALL_REQUIRED,
    entry_points={
        'console_scripts': [
            'prosafe_exporter = prosafe_exporter.prosafe_exporter:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: System Administrators',
        'Programming Language :: Python :: 3.6',
        'Topic :: System :: Networking :: Monitoring ',
      ],
    python_requires='>=3.6',
    setup_requires=SETUP_REQUIRED,
    tests_require=TEST_REQUIRED,
)
