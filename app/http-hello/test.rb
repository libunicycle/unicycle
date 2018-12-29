#!/usr/bin/ruby
# SPDX-License-Identifier: MIT

require "net/http"
require "test/unit"
require "typhoeus"
require_relative "../common/integration"

DEBUG = ENV["DEBUG"]
ROOT = File.join(File.dirname(__FILE__), "../../../")

class TestHttpService < Test::Unit::TestCase
  def setup
    # TODO: in the future when we have correct app build encapsulation
    # we will need to run config / build for our application.
    # config.generate
    # shog.build
    @qemu = fork do
      exec "qemu-system-x86_64 -cpu max -smp 4 -kernel #{ROOT}/out/app.elf -device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:80 -serial file:application.log --no-reboot -display none"
    end
    sleep(1)
  end

  def teardown
    Process.kill("HUP", @qemu)
    # unicycle.check_no_leaks
  end

  def test_service
    hydra = Typhoeus::Hydra.new(max_concurrency: 80)
    100.times do
      request = Typhoeus::Request.new("localhost:5555", followlocation: true)
      request.on_complete do |response|
        assert response.success?
        assert_equal "<html><body><h1>Hello, World!</h1></body></html>", response.body
      end
      hydra.queue(request)
    end
    hydra.run
  end
end
