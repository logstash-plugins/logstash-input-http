./gradlew build
./gradlew assemble
./gradlew generateGemJarRequiresFile
./gradlew vendor
./gradlew test


jruby -S bundle exec rspec ./spec/inputs/http_spec.rb:158

# in case of the error with bundler
## jruby -S  gem install bundler -v "$(grep -A 1 "BUNDLED WITH" Gemfile.lock | tail -n 1)"