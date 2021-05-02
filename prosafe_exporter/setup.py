from setuptools import find_packages, setup

with open('requirements.txt') as f:
    install_required = f.read().splitlines()

with open('setup_requirements.txt') as f:
    setup_required = f.read().splitlines()

with open('test_requirements.txt') as f:
    test_required = f.read().splitlines()

setup(
    name='prosafe_exporter',
    packages=['prosafe_exporter'],
    version='0.1.0',
    description='Prometheus metrics exporter for NETGEAR switches of the Smart Managed Plus series.',
    author='Till Steinbach',
    keywords='prometheus, netgear, metrics-exporter, prosafe, prosafe-exporter',
    url='https://github.com/tillsteinbach/prosafe_exporter_python',
    license='MIT',
    install_requires=install_required,
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
    setup_requires=setup_required,
    tests_require=test_required,
)
