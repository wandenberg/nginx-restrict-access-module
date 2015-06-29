Nginx Restrict Access Module
============================

A module to restrict access to a server / location using the hostname of remote host, based on Nginx access module.

_This module is not distributed with the Nginx source. See [the installation instructions](#installation)._


Configuration
-------------

An example:

    pid         logs/nginx.pid;
    error_log   logs/nginx-main_error.log debug;

    # Development Mode
    # master_process      off;
    # daemon              off;
    worker_processes    1;
    worker_rlimit_core  500M;
    working_directory /tmp;
    debug_points abort;

    events {
        worker_connections  1024;
        #use                 kqueue; # MacOS
        use                 epoll; # Linux
    }

    http {
        default_type    application/octet-stream;

        log_format main  '[$time_local] $host "$request" $request_time s '
                         '$status $body_bytes_sent "$http_referer" '
                         '"$http_user_agent" Remote: "$remote_addr" '
                         'remote_hostname: "$restrict_access_remote_hostname"';

        access_log      logs/nginx-http_access.log main;
        error_log       logs/nginx-http_error.log;

        restrict_access_address "$http_x_origin_ip";

        server {
            listen          8080;
            server_name     localhost;

            location / {
                allow_host "localhost" no_reverse_dns;
                allow_host "^p[0-9A-F]*\.dip0.t-ipconnect.de$";
                allow_host "^crawl-[0-9\-]*\.googlebot\.com$";
                allow_host "^.*\.ptr\.globo\.com$" no_reverse_dns;
                deny_host "all";
            }
        }
    }


Variables
---------

* **$restrict_access_remote_hostname** - just list the hostname of remote host accessing the location


Directives
----------

* **allow_host** - name or a regular expression to match against the remote hostname, if it matches, the access is allowed. It accepts "all" as a special value and a "no_rever_dns" as second parameter to skip the reverse DNS check step.
* **deny_host** - name or a regular expression to match against the remote hostname, if it matches, the access is denied. It accepts "all" as a special value and a "no_rever_dns" as second parameter to skip the reverse DNS check step.
* **restrict_access_address** - could indicate a header or a variable with the IP to be checked as the origin. If it results in an empty value the client IP is used.

<a id="installation"></a>Installation instructions
--------------------------------------------------

[Download Nginx Stable](http://nginx.org/en/download.html) source and uncompress it (ex.: to ../nginx). You must then run ./configure with --add-module pointing to this project as usual. Something in the lines of:

    $ ./configure \
        --add-module=../nginx-restrict-access-module \
        --prefix=/home/user/dev-workspace/nginx
    $ make
    $ make install


Running tests
-------------

This project uses [nginx_test_helper](https://github.com/wandenberg/nginx_test_helper) on the test suite. So, after you've installed the module, you can just download the necessary gems:

    $ cd test
    $ bundle install

And run rspec pointing to where your Nginx binary is (default: /usr/local/nginx/sbin/nginx):

    $ NGINX_EXEC=../path/to/my/nginx rspec .


Changelog
---------

This is still a work in progress. Be the change. And take a look on the Changelog file.
