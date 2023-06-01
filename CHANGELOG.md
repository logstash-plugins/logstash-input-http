## 3.7.1
  - bump netty to 4.1.93 [#166](https://github.com/logstash-plugins/logstash-input-http/pull/166)

## 3.7.0
 - Reviewed and deprecated SSL settings to comply with Logstash's naming convention [#165](https://github.com/logstash-plugins/logstash-input-http/pull/165)
   - Deprecated `ssl` in favor of `ssl_enabled`
   - Deprecated `ssl_verify_mode` in favor of `ssl_client_authentication`
   - Deprecated `keystore` in favor of `ssl_keystore_path`
   - Deprecated `keystore_password` in favor of `ssl_keystore_password`

## 3.6.1
 - Update Netty dependency to 4.1.87 [#162](https://github.com/logstash-plugins/logstash-input-http/pull/162)

## 3.6.0
 - Feat: review and deprecate ssl protocol/cipher related settings [#151](https://github.com/logstash-plugins/logstash-input-http/pull/151)

## 3.5.1
 - Fix: codecs provided with `additional_codecs` now correctly run in the pipeline's context, which means that they respect the `pipeline.ecs_compatibility` setting [#152](https://github.com/logstash-plugins/logstash-input-http/pull/152)

## 3.5.0
 - Feat: TLSv1.3 support [#146](https://github.com/logstash-plugins/logstash-input-http/pull/146)

## 3.4.5
 - Build: do not package log4j-api dependency [#149](https://github.com/logstash-plugins/logstash-input-http/pull/149).
   Logstash provides the log4j framework and the dependency is not needed except testing and compiling.

## 3.4.4
 - Update log4j dependency to 2.17.0

## 3.4.3
 - Update log4j dependency to 2.15.0
 - Fix: update to Gradle 7 [#145](https://github.com/logstash-plugins/logstash-input-http/pull/145)

## 3.4.2
 - Docs: added `v8` as an acceptable value for `ecs_compatibility` [#142](https://github.com/logstash-plugins/logstash-input-http/pull/142)

## 3.4.1
 - Changed jar dependencies to reflect newer versions [#140](https://github.com/logstash-plugins/logstash-input-http/pull/140)

## 3.4.0
 - Add ECS support, mapping Http header to ECS compatible fields [#137](https://github.com/logstash-plugins/logstash-input-http/pull/137)

## 3.3.7
 - Feat: improved error handling/logging/unwraping [#133](https://github.com/logstash-plugins/logstash-input-http/pull/133)
 
## 3.3.6
 - Fixes a regression introduced in 3.1.0's migration to the Netty back-end that broke some users'
   browser-based workflows. When an instance of this plugin that is configured to require Basic
   authentication receives a request that does not include authentication, it now appropriately
   includes an `WWW-Authenticate` header in its `401 Unauthorized` response, allowing the browser
   to collect credentials before retrying the request.

## 3.3.5
 - Updated jackson databind and Netty dependencies. Additionally, this release removes the dependency on `tcnative` +
   `boringssl`, using JVM supplied ciphers instead. This may result in fewer ciphers being available if the JCE
   unlimited strength jurisdiction policy is not installed. (This policy is installed by default on versions of the
   JDK from u161 onwards)[#126](https://github.com/logstash-plugins/logstash-input-http/pull/126)

## 3.3.4
 - Refactor: scope (and avoid unused) java imports [#124](https://github.com/logstash-plugins/logstash-input-http/pull/124)

## 3.3.3
 - Revert updates to netty and tcnative since CBC ciphers are still used in many contexts
 - More about the reasoning can be found [here](https://github.com/elastic/logstash/issues/11499#issuecomment-580333510)

## 3.3.2
 - Update netty and tcnative dependency [#118](https://github.com/logstash-plugins/logstash-input-http/issues/118)

## 3.3.1
 - Added 201 to valid response codes [#114](https://github.com/logstash-plugins/logstash-input-http/issues/114)
 - Documented response\_code option

## 3.3.0
 - Added configurable response code option [#103](https://github.com/logstash-plugins/logstash-input-http/pull/103)
 - Added explanation about operation order of codec and additional_codecs [#104](https://github.com/logstash-plugins/logstash-input-http/pull/104)

## 3.2.4
 - Loosen jar-dependencies manager gem dependency to allow plugin to work with JRubies that include a later version.

## 3.2.3
  - Changed jar dependencies to reflect newer versions

## 3.2.2
  - Fix some edge cases of the verify\_mode+ssl\_verify\_mode options

## 3.2.1
  - Fix expensive SslContext creation per connection #93

## 3.2.0
  - Add `request_headers_target_field` and `remote_host_target_field` configuration options with default to `host` and `headers` respectively #68
  - Sanitize content-type header with getMimeType #87
  - Move most message handling code to java #85
  - Fix: respond with correct http protocol version #84

## 3.1.0
  - Replace Puma web server with Netty
  - Support crt/key certificates
  - Deprecates jks support

## 3.0.10
  - Docs: Set the default_codec doc attribute.

## 3.0.9
  - Make sure default codec is also cloned for thread safety. https://github.com/logstash-plugins/logstash-input-http/pull/80
  - Always flush codec after each request and codec decoding. https://github.com/logstash-plugins/logstash-input-http/pull/81

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
