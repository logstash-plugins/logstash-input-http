FROM jruby:9.2.17.0-jdk8 as build

COPY . .
RUN gem install bundler:1.17.3
RUN ruby -S bundle install
RUN ruby -S bundle exec rake vendor
RUN gem build logstash-input-http.gemspec

FROM grafana/logstash-output-loki
COPY --from=build logstash-input-http-3.3.7-java.gem .
RUN /usr/share/logstash/bin/logstash-plugin install --no-verify --local logstash-input-http-3.3.7-java.gem
