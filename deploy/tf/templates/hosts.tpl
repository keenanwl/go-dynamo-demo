[webservers]
%{ for index, instance in instances ~}
dynamo-demo-${index + 1} ansible_host=${instance.public_ip_address}
%{ endfor ~}

[all:vars]
ansible_python_interpreter=/usr/bin/python3