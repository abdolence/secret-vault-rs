use crate::SecretValue;
use prost::bytes::{Buf, BufMut};
use prost::encoding::{skip_field, DecodeContext, WireType};
use prost::DecodeError;

impl prost::Message for SecretValue {
    fn encode_raw(&self, buf: &mut impl BufMut)
    where
        Self: Sized,
    {
        if self.ref_sensitive_value().is_empty() {
            prost::encoding::bytes::encode(1, self.ref_sensitive_value(), buf)
        }
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: WireType,
        buf: &mut impl Buf,
        ctx: DecodeContext,
    ) -> Result<(), DecodeError>
    where
        Self: Sized,
    {
        if tag == 1 {
            prost::encoding::bytes::merge(wire_type, self.ref_sensitive_value_mut(), buf, ctx)
        } else {
            skip_field(wire_type, tag, buf, ctx)
        }
    }

    fn encoded_len(&self) -> usize {
        if !self.ref_sensitive_value().is_empty() {
            prost::encoding::bytes::encoded_len(1, self.ref_sensitive_value())
        } else {
            0
        }
    }

    fn clear(&mut self) {
        self.ref_sensitive_value_mut().clear()
    }
}
