require File.expand_path('spec_helper', File.dirname(__FILE__))

describe "check restrict access module" do
  it "should check reverse DNS" do
    nginx_run_server({allow_hosts: ["^crawl-[0-9\-]*\.googlebot\.com$"], deny_hosts: ["all"], restrict_access_address: "$http_x_origin_ip"}, timeout: 10) do
      EventMachine.run do
        sub = EventMachine::HttpRequest.new("#{nginx_address}/allows_first").get(head: {"x-origin-ip" => "66.249.64.10"})
        sub.callback do
          expect(sub).to be_http_status(404)

          sub = EventMachine::HttpRequest.new("#{nginx_address}/allows_first").get(head: {"x-origin-ip" => "186.192.87.75"})
          sub.callback do
            expect(sub).to be_http_status(403)
            EventMachine.stop
          end
        end
      end
    end
  end

  it "should be possible ignore reverse DNS" do
    nginx_run_server({allow_hosts: ['"^.*\.ptr\.globo\.com$" no_reverse_dns'], deny_hosts: ["all"], restrict_access_address: "$http_x_origin_ip"}, timeout: 10) do
      EventMachine.run do
        sub = EventMachine::HttpRequest.new("#{nginx_address}/allows_first").get(head: {"x-origin-ip" => "66.249.64.10"})
        sub.callback do
          expect(sub).to be_http_status(403)

          sub = EventMachine::HttpRequest.new("#{nginx_address}/allows_first").get(head: {"x-origin-ip" => "186.192.87.75"})
          sub.callback do
            expect(sub).to be_http_status(404)
            EventMachine.stop
          end
        end
      end
    end
  end

  it "should block access for ip without a hostname" do
    nginx_run_server({allow_hosts: ['all'], restrict_access_address: "$http_x_origin_ip"}, timeout: 10) do
      EventMachine.run do
        sub = EventMachine::HttpRequest.new("#{nginx_address}/allows_first").get(head: {"x-origin-ip" => "72.14.224.154"})
        sub.callback do
          expect(sub).to be_http_status(403)

          EventMachine.stop
        end
      end
    end
  end

  it "should be possible block a host" do
    nginx_run_server({allow_hosts: ["all"], deny_hosts: ['"^.*\.ptr\.globo\.com$" no_reverse_dns'], restrict_access_address: "$http_x_origin_ip"}, timeout: 10) do
      EventMachine.run do
        sub = EventMachine::HttpRequest.new("#{nginx_address}/denys_first").get(head: {"x-origin-ip" => "66.249.64.10"})
        sub.callback do
          expect(sub).to be_http_status(404)

          sub = EventMachine::HttpRequest.new("#{nginx_address}/denys_first").get(head: {"x-origin-ip" => "186.192.87.75"})
          sub.callback do
            expect(sub).to be_http_status(403)
            EventMachine.stop
          end
        end
      end
    end
  end

  it "should be possible block a specific host" do
    nginx_run_server({allow_hosts: ["^crawl-[0-9\-]*\.googlebot\.com$"], deny_hosts: ["crawl-66-249-64-11.googlebot.com"], restrict_access_address: "$http_x_origin_ip"}, timeout: 10) do
      EventMachine.run do
        sub = EventMachine::HttpRequest.new("#{nginx_address}/denys_first").get(head: {"x-origin-ip" => "66.249.64.11"})
        sub.callback do
          expect(sub).to be_http_status(403)

          sub = EventMachine::HttpRequest.new("#{nginx_address}/denys_first").get(head: {"x-origin-ip" => "66.249.64.10"})
          sub.callback do
            expect(sub).to be_http_status(404)
            EventMachine.stop
          end
        end
      end
    end
  end

  it "should be possible allow a specific host" do
    nginx_run_server({allow_hosts: ["crawl-66-249-64-11.googlebot.com"], deny_hosts: ["^crawl-[0-9\-]*\.googlebot\.com$"], restrict_access_address: "$http_x_origin_ip"}, timeout: 10) do
      EventMachine.run do
        sub = EventMachine::HttpRequest.new("#{nginx_address}/allows_first").get(head: {"x-origin-ip" => "66.249.64.11"})
        sub.callback do
          expect(sub).to be_http_status(404)

          sub = EventMachine::HttpRequest.new("#{nginx_address}/allows_first").get(head: {"x-origin-ip" => "66.249.64.10"})
          sub.callback do
            expect(sub).to be_http_status(403)
            EventMachine.stop
          end
        end
      end
    end
  end
end
