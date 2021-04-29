from setuptools import find_packages, setup
setup(
    name='prosafe_exporter',
    packages=find_packages(include=['prosafe_exporter']),
    version='0.1.0',
    description='Prometheus metrics exporter for NETGEAR switches of the Smart Managed Plus series.',
    author='Till Steinbach',
    install_requires=['Flask==1.1.2', 'lxml==4.5.0', 'requests==2.23.0', 'PyYAML==3.13'],
    entry_points={
        'console_scripts': [
            'prosafe_exporter = prosafe_exporter.prosafe_exporter:main',
        ],
    },
    python_requires='>=3.6',
)