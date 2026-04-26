use super::NetfilterTransactionBuilder;
use super::exprs::{NftRule, counter::collect_counter_object_specs};

impl NetfilterTransactionBuilder {
    pub(super) fn add_system_rule(&mut self, family: &str, rule: &NftRule) -> bool {
        if rule.expressions.is_empty() {
            return false;
        }

        for (name, (packets, bytes)) in collect_counter_object_specs(std::slice::from_ref(rule)) {
            self.ensure_counter_object(family, rule.table().name(), &name, packets, bytes);
        }

        self.add_parsed_rule(family, rule);

        true
    }

    fn add_parsed_rule(&mut self, family: &str, parsed: &NftRule) {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        let mut request = self.inner.request().set_create().op_newrule_do(&h);
        let mut encoded = request
            .encode()
            .push_table_bytes(parsed.table().name().as_bytes())
            .push_chain_bytes(parsed.chain().as_bytes())
            .push_userdata(parsed.encoded_userdata());

        if let Some(position) = parsed.position() {
            encoded = encoded.push_position(position);
        }

        if let Some(id) = parsed.id() {
            encoded = encoded.push_id(id);
        }

        let mut exprs = encoded.nested_expressions();

        for expression in &parsed.expressions {
            exprs = expression.encode(exprs);
        }

        let _ = exprs.end_nested();

        self.has_operation = true;
    }

    fn ensure_counter_object(
        &mut self,
        family: &str,
        table: &str,
        name: &str,
        packets: bool,
        bytes: bool,
    ) {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);

        let mut request = self.inner.request().set_create().op_newobj_do(&h);
        let mut counter_obj = request
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_name_bytes(name.as_bytes())
            .nested_data_counter();

        if bytes {
            counter_obj = counter_obj.push_bytes(1);
        }

        if packets {
            counter_obj = counter_obj.push_packets(1);
        }

        let _ = counter_obj.end_nested();
        self.has_operation = true;
    }
}
