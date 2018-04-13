// Copyright 2018 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use types::*;

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
    let domain_param = DomainParam::from(&orig_domains.clone());
    let new_domains: Vec<Domain> = domain_param.into();
    assert_eq!(new_domains.len(), 2);
    assert_eq!(orig_domains, new_domains);
}
