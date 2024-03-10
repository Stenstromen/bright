use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use hickory_resolver::config::*;

fn dnslookup(domain: &str) {
    let record_types = vec![
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::PTR,
        RecordType::SOA,
        RecordType::SRV,
        RecordType::TXT,
        RecordType::CAA,
        RecordType::DNSKEY,
    ];

    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

    for record_type in record_types {
        let result: Result<
            hickory_resolver::lookup::Lookup,
            hickory_resolver::error::ResolveError
        > = resolver.lookup(domain, record_type);

        match result {
            Ok(lookup) => {
                for record in lookup.record_iter() {
                    println!("{}", record);
                }
            }
            Err(_e) => {
                //println!("Error: {:?}", e);
                println!("{} NODATA", record_type.to_string());
            }
        }
    }
}

fn main() {
    let domain: &str = "stenstromen.se";
    //look_up(domain);
    dnslookup(domain);
}
