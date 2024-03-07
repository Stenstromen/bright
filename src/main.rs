use std::net::SocketAddr;
use trust_dns_resolver::config::{ NameServerConfig, Protocol, ResolverConfig, ResolverOpts };
use trust_dns_resolver::Resolver;

fn check_dns_records(domain: &str) {
    let custom_resolver_ip: SocketAddr = "8.8.8.8:53".parse().expect("Invalid IP address format");

    let name_server: NameServerConfig = NameServerConfig {
        socket_addr: custom_resolver_ip,
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_nx_responses: true,
    };

    let resolver_config: ResolverConfig = ResolverConfig::from_parts(
        None,
        vec![],
        vec![name_server]
    );
    let resolver_opts: ResolverOpts = ResolverOpts::default();
    let resolver: Resolver = Resolver::new(resolver_config, resolver_opts).expect(
        "Failed to create resolver"
    );

    let response = resolver.lookup_ip(domain);
    
    match response {
        Ok(ip_addresses) => {
            println!("{:?}", ip_addresses);
            for ip in ip_addresses.iter() {
                println!("A record: {}", ip);
            }
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}

fn main() {
    let domain: &str = "stenstromen.se";
    check_dns_records(domain);
}
