use types::*;

#[test]
fn domain_to_string() {
    assert_eq!(String::from("1"), String::from(Domain(1)));
}

#[test]
fn new_domain() {
    assert_eq!(Domain(1), Domain::new(1).unwrap());
}

#[test]
fn domain_domainparam() {
    let orig_domain = Domain(1);
    let domain_param = DomainParam::from(orig_domain);
    let new_domain: Vec<Domain> = domain_param.into();
    assert_eq!(new_domain.len(), 1);
    assert_eq!(orig_domain, new_domain[0]);
}

#[test]
fn domains_to_domainparam() {
    let orig_domains = vec![Domain(1), Domain(3)];
    let domain_param = DomainParam::from(orig_domains.clone());
    let new_domains: Vec<Domain> = domain_param.into();
    assert_eq!(new_domains.len(), 2);
    assert_eq!(orig_domains, new_domains);
}
