from copy import copy

from envs.monkey_zoo.blackbox.config_templates.base_template import BaseTemplate
from envs.monkey_zoo.blackbox.config_templates.config_template import ConfigTemplate


class Elastic(ConfigTemplate):

    config_values = copy(BaseTemplate.config_values)

    config_values.update(
        {
            "basic.exploiters.exploiter_classes": ["ElasticGroovyExploiter"],
            "internal.classes.finger_classes": ["PingScanner", "HTTPFinger", "ElasticFinger"],
            "basic_network.scope.subnet_scan_list": ["10.2.2.4", "10.2.2.5"],
            "basic_network.scope.depth": 1,
            "internal.network.tcp_scanner.HTTP_PORTS": [9200],
            "internal.network.tcp_scanner.tcp_target_ports": [],
        }
    )
