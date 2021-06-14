# Fork of Loki Logstash Http input Plugin
Added features:
- encode data which comes from promtails

Eg. promtail configuration:
```yaml 
server:
  http_listen_port: 9080
  grpc_listen_port: 0
  log_level: debug
positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://localhost:5043
    tenant_id: chcialembycpiekarzem

scrape_configs:
- job_name: system
  static_configs:
  - targets:
      - localhost
    labels:
      job: varlogs
      tenant: chcialembycpiekarzem
      __path__: /var/log/*log
```

Eg. Logstash configuration:
```yaml 
input {
    http {
        id => "logstash-promtail-http-input"
        port => "5043"  
        host => "0.0.0.0"
    }
}
output {
  stdout { codec => rubydebug }
}
```

## Building and pushing gem
1. `gem build logstash-promtail-http-input.gemspec`
2. Push desired build version `logstash-promtail-http-input-{VERSION}.gem`
    - In case of massage 'Repushing of gem versions is not allowed.' Raise the plugin version in logstash-promtail-http-input.gemspec
    - Rebuild the plugin
    - Push proper version


## Documentation

Logstash provides infrastructure to automatically generate documentation for this plugin. We use the asciidoc format to write documentation so any comments in the source code will be first converted into asciidoc and then into html. All plugin documentation are placed under one [central location](http://www.elastic.co/guide/en/logstash/current/).

- For formatting code or config example, you can use the asciidoc `[source,ruby]` directive
- For more asciidoc formatting tips, see the excellent reference here https://github.com/elastic/docs#asciidoc-guide

## Need Help?

Need help? Try #logstash on freenode IRC or the https://discuss.elastic.co/c/logstash discussion forum.

## Developing

### 1. Plugin Developement and Testing

#### Code
- To get started, you'll need JRuby with the Bundler gem installed.

- Create a new plugin or clone and existing from the GitHub [logstash-plugins](https://github.com/logstash-plugins) organization. We also provide [example plugins](https://github.com/logstash-plugins?query=example).

- Install dependencies
```sh
bundle install
```

#### Test

- Update your dependencies

```sh
bundle install
```

- Run tests

```sh
bundle exec rspec
```

### 2. Running your unpublished Plugin in Logstash

#### 2.1 Run in a local Logstash clone

- Edit Logstash `Gemfile` and add the local plugin path, for example:
```ruby
gem "logstash-filter-awesome", :path => "/your/local/logstash-filter-awesome"
```
- Install plugin
```sh
# Logstash 2.3 and higher
bin/logstash-plugin install --no-verify

# Prior to Logstash 2.3
bin/plugin install --no-verify

```
- Run Logstash with your plugin
```sh
bin/logstash -e 'filter {awesome {}}'
```
At this point any modifications to the plugin code will be applied to this local Logstash setup. After modifying the plugin, simply rerun Logstash.

#### 2.2 Run in an installed Logstash

You can use the same **2.1** method to run your plugin in an installed Logstash by editing its `Gemfile` and pointing the `:path` to your local plugin development directory or you can build the gem and install it using:

- Build your plugin gem
```sh
jruby -S gem build logstash-promtail-http-input.gemspec

```
- Install the plugin from the Logstash home
```sh
# Logstash 2.3 and higher
bin/logstash-plugin install --no-verify

# or locally 

bin/logstash-plugin install --no-verify --local  /path_to_gem/logstash-filter-java_drain_filter-0.1.1.gem

```
- Start Logstash and proceed to test the plugin

## Contributing

All contributions are welcome: ideas, patches, documentation, bug reports, complaints, and even something you drew up on a napkin.

Programming is not a required skill. Whatever you've seen about open source and maintainers or community members  saying "send patches or die" - you will not see that here.

It is more important to the community that you are able to contribute.

For more information about contributing, see the [CONTRIBUTING](https://github.com/elastic/logstash/blob/master/CONTRIBUTING.md) file.