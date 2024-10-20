require 'nginx_test_helper'
module NginxConfiguration
  def self.default_configuration
    {
      disable_start_stop_server: false,
      master_process: 'off',
      daemon: 'off',

      restrict_access_address: nil,
      allow_hosts: [],
      deny_hosts: [],
    }
  end


  def self.template_configuration
  %(
pid               <%= pid_file %>;
error_log         <%= error_log %> debug;

worker_processes  <%= nginx_workers %>;

events {
  worker_connections  1024;
  use                 <%= (RUBY_PLATFORM =~ /darwin/) ? 'kqueue' : 'epoll' %>;
}

http {
  access_log      <%= access_log %>;

  server {
    listen        <%= nginx_port %>;
    server_name   <%= nginx_host %>;

    root <%= nginx_tests_tmp_dir %>;

    <%= write_directive("restrict_access_address", restrict_access_address) %>

    location /denys_first {
    <% deny_hosts.each do |deny_host| %>
      deny_host <%= deny_host %>;
    <% end %>
    <% allow_hosts.each do |allow_host| %>
      allow_host <%= allow_host %>;
    <% end %>
    }

    location /allows_first {
    <% allow_hosts.each do |allow_host| %>
      allow_host <%= allow_host %>;
    <% end %>
    <% deny_hosts.each do |deny_host| %>
      deny_host <%= deny_host %>;
    <% end %>
    }
  }
}
  )
  end
end
