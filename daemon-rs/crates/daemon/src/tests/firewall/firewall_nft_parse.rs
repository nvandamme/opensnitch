use crate::platform::firewall::netlink::parse::tokenize_nft_expression;

#[test]
fn tokenize_expression_keeps_quoted_and_splits_complex_fragments() {
    let tokens =
        tokenize_nft_expression("log prefix \"opensnitch test\" tcp flags & (fin|syn|rst|ack)");
    assert_eq!(
        tokens,
        vec![
            "log",
            "prefix",
            "\"opensnitch test\"",
            "tcp",
            "flags",
            "&",
            "(fin|syn|rst|ack)"
        ]
    );
}
