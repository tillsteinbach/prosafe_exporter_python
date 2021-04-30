from setuptools import find_packages, setup

setup(
    name='prosafe_exporter',
    packages=['prosafe_exporter'],
    version='0.1.0',
    description='Prometheus metrics exporter for NETGEAR switches of the Smart Managed Plus series.',
    author='Till Steinbach',
    keywords='prometheus, netgear, metrics-exporter, prosafe, prosafe-exporter',
    url='https://github.com/tillsteinbach/prosafe_exporter_python',
    license='MIT',
    install_requires=['Flask>=1.1.2', 'lxml>=4.6.3',
                      'requests>=2.23.0', 'PyYAML>=4.6.3'],
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
    setup_requires=['pytest-runner', 'flake8'],
    tests_require=['pytest', 'pytest-httpserver'],
)
