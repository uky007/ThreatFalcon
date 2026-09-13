//! Bounded native ETW decoder. No payload pointer or metadata pointer escapes
//! the callback. Unsupported layouts remain explicit, inspectable raw evidence.
use std::collections::HashMap;
use std::mem::{offset_of, size_of};
use std::sync::Arc;
use windows::core::PWSTR;
use windows::Win32::System::Diagnostics::Etw::*;

use super::etw_normalize;
use crate::events::{AgentInfo, EventProvenance, ThreatEvent};

const MAX_METADATA: usize = 1_048_576;
const MAX_PROPERTIES: usize = 128;
const MAX_FIELD: usize = 65_536;
const MAX_CACHE: usize = 128;

#[derive(Default)]
pub struct Decoder {
    // Full descriptor and pointer-width flags, not just a provider prefix or ID.
    schemas: HashMap<String, Arc<Vec<u64>>>,
}

impl Decoder {
    /// Safety: record and all ETW-owned buffers must remain valid for this call.
    pub unsafe fn decode(&mut self, record: &EVENT_RECORD, agent: &AgentInfo) -> ThreatEvent {
        let h = &record.EventHeader;
        let d = h.EventDescriptor;
        let guid = format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            h.ProviderId.data1,
            h.ProviderId.data2,
            h.ProviderId.data3,
            h.ProviderId.data4[0],
            h.ProviderId.data4[1],
            h.ProviderId.data4[2],
            h.ProviderId.data4[3],
            h.ProviderId.data4[4],
            h.ProviderId.data4[5],
            h.ProviderId.data4[6],
            h.ProviderId.data4[7]
        );
        let mut p = EventProvenance {
            provider_guid: guid.clone(),
            event_id: d.Id,
            version: d.Version,
            opcode: d.Opcode,
            ..Default::default()
        };
        let mut provider_name = guid.clone();
        for (name, value) in [
            ("@header_pid", h.ProcessId.to_string()),
            ("@thread_id", h.ThreadId.to_string()),
            ("@task", d.Task.to_string()),
            ("@keyword", d.Keyword.to_string()),
            ("@channel", d.Channel.to_string()),
            ("@level", d.Level.to_string()),
            ("@activity_id", format!("{:?}", h.ActivityId)),
        ] {
            p.fields.insert(name.into(), value);
        }
        let key = format!(
            "{guid}:{}:{}:{}:{}:{}:{}:{}:{}",
            d.Id, d.Version, d.Opcode, d.Task, d.Channel, d.Level, d.Keyword, h.Flags
        );
        match unsafe { self.schema(record, &key) } {
            Ok(schema) => {
                let info = unsafe { &*(schema.as_ptr() as *const TRACE_EVENT_INFO) };
                if let Some(name) = wide_at(&schema, info.ProviderNameOffset) {
                    provider_name = name;
                }
                for (name, offset) in [
                    ("@task_name", info.TaskNameOffset),
                    ("@opcode_name", info.OpcodeNameOffset),
                    ("@event_name", unsafe { info.Anonymous1.EventNameOffset }),
                ] {
                    if let Some(value) = wide_at(&schema, offset) {
                        p.fields.insert(name.into(), value);
                    }
                }
                let count = info.TopLevelPropertyCount as usize;
                let end = offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray)
                    .checked_add(count.saturating_mul(size_of::<EVENT_PROPERTY_INFO>()));
                if count > MAX_PROPERTIES
                    || count > info.PropertyCount as usize
                    || end.is_none_or(|end| end > schema.len() * 8)
                {
                    p.issues.push("tdh_invalid_property_table".into());
                } else {
                    for i in 0..count {
                        let property = unsafe { &*info.EventPropertyInfoArray.as_ptr().add(i) };
                        let Some(name) = wide_at(&schema, property.NameOffset) else {
                            p.issues.push("tdh_invalid_property_name".into());
                            continue;
                        };
                        match unsafe { read_property(record, info, property, &name) } {
                            Ok(value) => {
                                p.fields.insert(name, value);
                            }
                            Err(error) => p.issues.push(format!("{error}:{name}")),
                        }
                    }
                }
            }
            Err(error) => p.issues.push(error),
        }
        // Preserve the native bytes only if normalization fails, including
        // complex fields we do not yet decode. ETW's payload length is u16.
        let payload = if record.UserData.is_null() || record.UserDataLength == 0 {
            None
        } else {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    record.UserData as *const u8,
                    record.UserDataLength as usize,
                )
            };
            Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
        };
        etw_normalize::normalize(
            agent,
            provider_name,
            h.ProcessId,
            h.TimeStamp as u64,
            p,
            payload,
        )
    }

    unsafe fn schema(&mut self, record: &EVENT_RECORD, key: &str) -> Result<Arc<Vec<u64>>, String> {
        if let Some(info) = self.schemas.get(key) {
            return Ok(info.clone());
        }
        let mut size = 0u32;
        let status = unsafe { TdhGetEventInformation(record, None, None, &mut size) };
        if status != 122 {
            return Err(format!("tdh_schema_error:{status}"));
        }
        if (size as usize) < size_of::<TRACE_EVENT_INFO>() || size as usize > MAX_METADATA {
            return Err("tdh_schema_size_limit".into());
        }
        // u64 storage provides sufficient alignment for all TRACE_EVENT_INFO fields.
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let ptr = buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO;
        let status = unsafe { TdhGetEventInformation(record, None, Some(ptr), &mut size) };
        if status != 0 {
            return Err(format!("tdh_schema_error:{status}"));
        }
        // TraceLogging metadata may vary despite identical event descriptors.
        // Cache only manifest schemas (DecodingSourceXMLFile == 0).
        let cache = unsafe { (*ptr).DecodingSource.0 == 0 };
        let buffer = Arc::new(buffer);
        if cache && self.schemas.len() < MAX_CACHE {
            self.schemas.insert(key.to_string(), buffer.clone());
        }
        Ok(buffer)
    }
}

fn wide_at(buffer: &[u64], offset: u32) -> Option<String> {
    let offset = offset as usize;
    if offset == 0 || offset % 2 != 0 || offset >= buffer.len() * 8 {
        return None;
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u8, buffer.len() * 8) };
    let mut units = Vec::new();
    for pair in bytes[offset..].chunks_exact(2).take(MAX_FIELD / 2) {
        let value = u16::from_le_bytes([pair[0], pair[1]]);
        if value == 0 {
            return String::from_utf16(&units).ok();
        }
        units.push(value);
    }
    None
}

unsafe fn read_property(
    record: &EVENT_RECORD,
    info: &TRACE_EVENT_INFO,
    property: &EVENT_PROPERTY_INFO,
    name: &str,
) -> Result<String, String> {
    // Struct, custom schema, parameterized count, and multi-element arrays are
    // deliberately not interpreted as scalars. Full payload remains available.
    let flags = property.Flags.0;
    if flags & (PropertyStruct.0 | PropertyParamCount.0 | PropertyHasCustomSchema.0) != 0
        || unsafe { property.Anonymous2.count } > 1
    {
        return Err("tdh_complex_property".into());
    }
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let desc = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name.as_ptr() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut size = 0;
    let status = unsafe { TdhGetPropertySize(record, None, &[desc], &mut size) };
    if status != 0 {
        return Err(format!("tdh_property_size_error:{status}"));
    }
    if size as usize > MAX_FIELD {
        return Err("tdh_property_size_limit".into());
    }
    let mut raw = vec![0u8; size as usize];
    let status = unsafe { TdhGetProperty(record, None, &[desc], &mut raw) };
    if status != 0 {
        return Err(format!("tdh_property_error:{status}"));
    }
    let ty = unsafe { property.Anonymous1.nonStructType };
    // Retain FILETIME as exact ticks (localized display strings are unsuitable
    // for identity). All other types use TDH, including network byte order.
    if ty.InType == TDH_INTYPE_FILETIME.0 as u16 && raw.len() == 8 {
        return Ok(u64::from_le_bytes(raw[..8].try_into().unwrap()).to_string());
    }
    if raw.is_empty() {
        return Ok(String::new());
    }
    let pointer_size = if record.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER as u16 != 0 {
        4
    } else {
        8
    };
    let mut size = 0;
    let mut consumed = 0;
    let length = if flags & PropertyParamLength.0 != 0 {
        u16::try_from(raw.len()).map_err(|_| "tdh_property_size_limit")?
    } else {
        unsafe { property.Anonymous3.length }
    };
    let length = if ty.OutType == TDH_OUTTYPE_IPV6.0 as u16 && length == 0 {
        16
    } else {
        length
    };
    let status = unsafe {
        TdhFormatProperty(
            info,
            None,
            pointer_size,
            ty.InType,
            ty.OutType,
            length,
            &raw,
            &mut size,
            PWSTR::null(),
            &mut consumed,
        )
    };
    if status != 122 || size == 0 || size as usize > MAX_FIELD || size % 2 != 0 {
        return Err(format!("tdh_format_size_error:{status}"));
    }
    let mut output = vec![0u16; size as usize / 2];
    let status = unsafe {
        TdhFormatProperty(
            info,
            None,
            pointer_size,
            ty.InType,
            ty.OutType,
            length,
            &raw,
            &mut size,
            PWSTR(output.as_mut_ptr()),
            &mut consumed,
        )
    };
    if status != 0 || consumed as usize != raw.len() {
        return Err(format!("tdh_format_error:{status}"));
    }
    let end = output
        .iter()
        .position(|v| *v == 0)
        .ok_or("tdh_unterminated_string")?;
    String::from_utf16(&output[..end]).map_err(|_| "tdh_invalid_utf16".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_alignment_and_bounds() {
        assert!(std::mem::align_of::<TRACE_EVENT_INFO>() <= std::mem::align_of::<u64>());
        assert!(wide_at(&[0], 9).is_none());
        assert!(wide_at(&[0], 1).is_none());
        assert!(wide_at(&[0], 0).is_none());
    }
}
