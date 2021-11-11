# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased] (Available through Edge Tag)
- no unreleased changes so far
- 
## [0.4.6] - 2021-11-11
### Fixed
- fix socket timeout error

## [0.4.5] - 2021-10-12
### Fixed
- fix retry on corrupted answer when retrieving switch_info
- fix on curropted switch info

## [0.4.4] - 2021-06-30
### Fixed
- Logging of flask now uses logging level from verbose option

## [0.4.3] - 2021-06-29
### Fixed
- Prevent sending outdated data when retrieval process is stuck

## [0.4.2] - 2021-05-07
### Changed
- Fixed issues colected in static analysis

## [0.4.1] - 2021-05-05
### Added
- "--version" command
## [0.4.0] - 2021-05-05
### Changed
- Will login only once and reuse session if possible

### Added
- Cookies storing session id can be persisted in file
- Now code has almost 100% test coverage

## [0.3.0] - 2021-04-30
### Added
- Support for older firmware versions
- More plausability checking of the results coming from the switch

### Changed
- Now accepts any url to fetch results, not only /probe and /metrics

## [0.2.0] - 2021-04-22
### Added
- Support for Firmware V2.06.14EN

## [0.1.0] - 2021-04-22
Initial release to enable "latest" tag on dockerhub

[unreleased]: https://github.com/tillsteinbach/prosafe_exporter_python/compare/v0.4.6...HEAD
[0.4.6]: https://github.com/tillsteinbach/prosafe_exporter_python/releases/tag/v0.4.6
[0.4.5]: https://github.com/tillsteinbach/prosafe_exporter_python/releases/tag/v0.4.5
[0.4.4]: https://github.com/tillsteinbach/prosafe_exporter_python/releases/tag/v0.4.4
[0.4.3]: https://github.com/tillsteinbach/prosafe_exporter_python/releases/tag/v0.4.3
[0.4.2]: https://github.com/tillsteinbach/prosafe_exporter_python/releases/tag/v0.4.2
[0.4.1]: https://github.com/tillsteinbach/prosafe_exporter_python/releases/tag/v0.4.1
[0.4.0]: https://github.com/tillsteinbach/prosafe_exporter_python/releases/tag/v0.4.0
[0.3.0]: https://github.com/tillsteinbach/prosafe_exporter_python/releases/tag/v0.3.0
[0.2.0]: https://github.com/tillsteinbach/prosafe_exporter_python/releases/tag/v0.2.0
[0.1.0]: https://github.com/tillsteinbach/prosafe_exporter_python/releases/tag/v0.1.0
