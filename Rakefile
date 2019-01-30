@files=[]

task :default do
  system("rake -T")
end

require 'logstash/devutils/rake'
require 'jars/installer'

task :install_jars do
  system('./gradlew vendor')
end

task :vendor => :install_jars

task :test do
  require 'rspec/core/runner'
  require 'rspec'
  system './gradlew clean test'
  Rake::Task[:install_jars].invoke
  exit(RSpec::Core::Runner.run(Rake::FileList['spec/**/*_spec.rb']))
end
