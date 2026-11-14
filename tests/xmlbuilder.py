"""Fabrique des rapports XML au format de Nmap 7.94 (adresses réservées à la documentation)."""

from html import escape


def port(number, service, product="", version="", extrainfo="", tunnel="", state="open", proto="tcp"):
    attrs = f'name="{service}"'
    for key, value in (("product", product), ("version", version), ("extrainfo", extrainfo), ("tunnel", tunnel)):
        if value:
            attrs += f' {key}="{escape(value)}"'
    return (
        f'<port protocol="{proto}" portid="{number}"><state state="{state}" reason="syn-ack" reason_ttl="64"/>'
        f'<service {attrs} method="probed" conf="10"></service></port>'
    )


def host(ip, ports=(), mac="", vendor="", hostname="", state="up", addrtype="ipv4"):
    lines = [
        f'<host><status state="{state}" reason="arp-response" reason_ttl="0"/>',
        f'<address addr="{ip}" addrtype="{addrtype}"/>',
    ]
    if mac:
        extra = f' vendor="{vendor}"' if vendor else ""
        lines.append(f'<address addr="{mac}" addrtype="mac"{extra}/>')
    lines.append("<hostnames>")
    if hostname:
        lines.append(f'<hostname name="{hostname}" type="PTR"/>')
    lines.append("</hostnames>")
    if state == "up":
        lines += [
            '<ports><extraports state="closed" count="990">',
            '<extrareasons reason="reset" count="990" proto="tcp" ports="1-1000"/>',
            "</extraports>",
            *ports,
            "</ports>",
        ]
    lines.append("</host>")
    return "\n".join(lines)


def document(hosts, start=1794532996, args="nmap -T4 -sV -oX - 192.0.2.0/24"):
    """Un <hosthint> est inclus, comme dans la vraie sortie : le lecteur doit l'ignorer."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
        f'<nmaprun scanner="nmap" args="{args}" start="{start}" version="7.94SVN" xmloutputversion="1.05">\n'
        '<hosthint><status state="up" reason="arp-response" reason_ttl="0"/>'
        '<address addr="192.0.2.99" addrtype="ipv4"/><hostnames></hostnames></hosthint>\n'
        + "\n".join(hosts)
        + "\n</nmaprun>\n"
    )
