//! One WebSocket tee fed by several calls (siphon-rtp 0.21.0
//! `additional_sources`): a recording session's streams, streamed live as one.

use super::*;

impl SiphonRtpClient {
    /// Attach one WebSocket tee fed by several calls, one channel each in
    /// order: `sources[0]` is the call the tee is attached to and reported on.
    /// Needs an engine listing `ws_tee_multi_source`.
    pub async fn attach_ws_tee_sources(
        &self,
        sources: &[crate::rtpengine::events::MediaSource],
        ws_uri: &str,
        direction: WsTeeDirection,
        channels: Option<u8>,
        sample_rate: Option<u32>,
    ) -> Result<(), RtpEngineError> {
        let Some((first, rest)) = sources.split_first() else {
            return Err(RtpEngineError::Protocol(
                "a multi-source tee needs at least one source".to_string(),
            ));
        };
        recording::require_features(
            self.request_in(None, Command::NodeInfo).await?,
            &["ws_tee_multi_source"],
            "a multi-source tee",
        )?;
        expect_ok(
            self.request(Command::AttachWsTee {
                call_id: first.call_id.clone(),
                from_tag: first.from_tag.clone(),
                ws_uri: ws_uri.to_string(),
                direction: proto_ws_tee_direction(direction),
                channels,
                sample_rate,
                additional_sources: rest
                    .iter()
                    .map(|source| siphon_rtp_proto::RecordingSource {
                        call_id: source.call_id.clone(),
                        from_tag: source.from_tag.clone(),
                    })
                    .collect(),
            })
            .await?,
        )
    }
}

impl SiphonRtpClientSet {
    /// [`SiphonRtpClient::attach_ws_tee_sources`] on the instance owning the
    /// first source.
    pub async fn attach_ws_tee_sources(
        &self,
        sources: &[crate::rtpengine::events::MediaSource],
        ws_uri: &str,
        direction: WsTeeDirection,
        channels: Option<u8>,
        sample_rate: Option<u32>,
    ) -> Result<(), RtpEngineError> {
        let call_id = sources
            .first()
            .map(|source| source.call_id.as_str())
            .unwrap_or_default();
        self.select(call_id)
            .attach_ws_tee_sources(sources, ws_uri, direction, channels, sample_rate)
            .await
    }
}
