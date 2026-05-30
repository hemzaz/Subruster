#[cfg(test)]
mod test_dns_operations {
    #[tokio::test]
    async fn test_lookup() {
        let ns: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let host: String = "example.com".to_string();

        // Assert the lookup resolves successfully rather than checking a specific
        // IP: public DNS records change over time, and a hardcoded address made
        // this test brittle (it broke when the target's IP changed).
        let result = subruster::dns_operations::lookup(Some(&[ns]), host.clone()).await;
        assert!(result.is_ok(), "expected {} to resolve, got {:?}", host, result);
    }
}
