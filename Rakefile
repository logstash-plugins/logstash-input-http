require 'logstash/devutils/rake'

task :install_jars do
  sh('./gradlew clean vendor')
end

task :vendor => :install_jars

Rake::Task["test"].clear
task :test do
  require 'rspec'
  require 'rspec/core/runner'
  Rake::Task[:install_jars].invoke
  sh(%{./gradlew test}) { |ok,res| exit(res) unless ok }
  exit(RSpec::Core::Runner.run(%w(--format documentation).concat(Rake::FileList['spec/**/*_spec.rb'])))
end
