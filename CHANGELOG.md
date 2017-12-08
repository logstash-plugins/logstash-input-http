## 3.0.8
  - In the event that all webserver threads are busy this plugin will now return a 429, busy, error.

## 3.0.7
  - Update gemspec summary

## 3.0.6
  - Fix some documentation issues

## 3.0.4
  - Improve error logging to log more details, including stack trace, for true bugs.
    This makes debugging broken codecs much easier.
## 3.0.3
  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99
## 3.0.2
  - Use a new class as redefined Puma::Server class as we need to mock one method and only need it for this plugin, but not for all parts using puma in logstash.Fixes https://github.com/logstash-plugins/logstash-input-http/issues/51.
## 3.0.1
  - Republish all the gems under jruby.
## 3.0.0
  - Update the plugin to the version 2.0 of the plugin api, this change is required for Logstash 5.0 compatibility. See https://github.com/elastic/logstash/issues/5141
# 2.2.2
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash
# 2.2.1
  - New dependency requirements for logstash-core for the 5.0 release
## 2.2.0
 - Bump puma dependency to 2.16.0

## 2.1.1
 - Support for custom response headers

## 2.1.0
 - Support compressed and gziped requests (thanks dwapstra)

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0

## 1.0.3 (September 2, 2015)
* Include remote host address to events (#25)

## 1.0.2 (July 28, 2015)
* Fix for missing base64 require which was crashing Logstash (#17)

## 1.0.0 (July 1, 2015)

* First version: New input to receive HTTP requests
* Added basic authentication and SSL support
