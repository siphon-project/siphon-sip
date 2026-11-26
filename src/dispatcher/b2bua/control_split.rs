//! The control plane's door to a leg's split-bridge flag.

use crate::dispatcher::*;

/// Record (or clear) a **split bridge** on a control-plane channel's media
/// session.  The twin of [`b2bua_media_set_ws_bridge_attached`]: a bridge plan
/// reads it to take the split off before a leg is renegotiated.
pub fn b2bua_media_set_ws_split_attached(sip_call_id: &str, attached: bool) {
    if let Some(control) = B2BUA_CONTROL.get() {
        if let Some(sessions) = control.state.rtpengine_sessions.as_ref() {
            sessions.set_ws_split_attached(sip_call_id, attached);
        }
    }
}
