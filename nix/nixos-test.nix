# Copyright (C) 2026 Stephan Naumann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

{ testers, pkgs }:

testers.nixosTest {
  name = "tssh-sample";

  nodes.device =
    { ... }:
    {
      security.tpm2.enable = true;
      security.tpm2.pkcs11.enable = true;
      security.tpm2.tctiEnvironment.enable = true;
      virtualisation.tpm.enable = true;

    };

  nodes.ssh_host =
    { ... }:
    {
      services.openssh.enable = true;
      services.openssh.settings.PermitRootLogin = "yes";
    };

  testScript = # python
    ''
      start_all()

      #setup the host
      ssh_host.succeed("mkdir -p /root/.ssh")
      ssh_host.succeed("touch /root/.ssh/authorized_keys")
      ssh_host.succeed("touch /root/.ssh/config")
      ssh_host.succeed("chmod 700 -R /root/.ssh")


      #setup the client
      device.succeed("mkdir -p /root/.ssh")
      device.succeed("touch /root/.ssh/config")
      device.succeed("chmod 700 -R /root/.ssh")
      device.succeed("${pkgs.tssh}/bin/tssh include --raw > /root/.ssh/config")

      #wait until everything is ready
      ssh_host.wait_for_unit("sshd.service")
      ssh_host.wait_for_open_port(22)

      #Test cases


      ssh_command="RUST_LOG=trace ssh -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o StrictHostKeyChecking=no root@ssh_host 'pwd'" 

      #the following tests cases are supported by the backing swtpm. However one could find out with tssh check to. ...
      test_cases= ["nistp256", "nistp384", "nistp521", "rsa1024", "rsa2048", "rsa3072"]

      for case in test_cases:
          device.succeed(f"${pkgs.tssh}/bin/tssh add root@ssh_host --kind {case}")
          pub_key=device.succeed("${pkgs.tssh}/bin/tssh get --raw root@ssh_host")
          ssh_host.succeed(f"echo '{pub_key}' > /root/.ssh/authorized_keys")
          device.succeed(ssh_command)
          device.succeed("${pkgs.tssh}/bin/tssh delete root@ssh_host")


      ssh_host.shutdown()
      device.shutdown()

    '';
}
