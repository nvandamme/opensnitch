use crate::utils::sort_key::sort_by_string_key;

#[derive(Debug, PartialEq, Eq)]
struct Item {
    id: String,
    value: u8,
}

#[test]
fn sorts_by_string_key() {
    let mut items = vec![
        Item {
            id: "c".to_string(),
            value: 3,
        },
        Item {
            id: "a".to_string(),
            value: 1,
        },
        Item {
            id: "b".to_string(),
            value: 2,
        },
    ];

    sort_by_string_key(&mut items, |item| item.id.as_str());

    assert_eq!(items[0].value, 1);
    assert_eq!(items[1].value, 2);
    assert_eq!(items[2].value, 3);
}
