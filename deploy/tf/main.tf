locals {
  instances = [
    {
      name   = "app-server-1"
      region = "eu-north-1a"
    }
  ]
}

resource "aws_lightsail_key_pair" "keenan-terraform" {
  name = "keenan-terraform"
  public_key = file("~/.ssh/id_terraform.pub")
}

resource "aws_lightsail_instance" "app" {
  for_each = { for idx, instance in local.instances : idx => instance }
  name     = each.value.name
  availability_zone = each.value.region
  blueprint_id = "ubuntu_22_04"
  bundle_id    = "micro_3_0"
  ip_address_type = "dualstack"

  key_pair_name = aws_lightsail_key_pair.keenan-terraform.name

  connection {
    host        = element(self.ipv6_addresses, 0)
    type        = "ssh"
    user        = "ubuntu"
    private_key = file(var.pvt_key)
    timeout     = "2m"
  }

}

# Add firewall rules to allow HTTP and HTTPS traffic
resource "aws_lightsail_instance_public_ports" "app_http_https" {
  for_each = aws_lightsail_instance.app

  instance_name = each.value.name

  port_info {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
  }

  port_info {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
  }

  port_info {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
  }
}

resource "aws_key_pair" "keenan-terraform" {
  key_name   = "keenan-terraform"
  public_key = file(var.public_key)
}

resource "local_file" "hosts_cfg" {
  content = templatefile("${path.module}/templates/hosts.tpl",
    {
      instances = aws_lightsail_instance.app
    }
  )
  filename = "../ansible/hosts.cfg"
}