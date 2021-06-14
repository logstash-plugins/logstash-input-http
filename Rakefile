require 'logstash/devutils/rake'
require 'bundler/gem_tasks'

task :install_jars do
  sh('./gradlew clean vendor')
end

task :vendor => :install_jars

task :test do
  require 'rspec'
  require 'rspec/core/runner'
  Rake::Task[:install_jars].invoke
  sh './gradlew test'
  exit(RSpec::Core::Runner.run(Rake::FileList['spec/**/*_spec.rb']))
end
