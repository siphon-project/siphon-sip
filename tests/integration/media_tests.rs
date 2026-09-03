//! Integration tests for the SDP parser and codec filtering module.
//!
//! Tests cover parsing audio-only and audio+video SDP bodies, codec filtering
//! and removal, parse-serialize-reparse roundtrips, edge cases (empty SDP, no
//! media lines), and session-level attribute preservation.

use siphon::media::sdp::{rewrite_sdp_body, SdpBody};

// ---------------------------------------------------------------------------
// Sample SDP bodies
// ---------------------------------------------------------------------------

const AUDIO_ONLY_SDP: &str = concat!(
    "v=0\r\n",
    "o=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n",
    "s=-\r\n",
    "c=IN IP4 10.0.0.1\r\n",
    "t=0 0\r\n",
    "m=audio 49170 RTP/AVP 0 8 97 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:8 PCMA/8000\r\n",
    "a=rtpmap:97 opus/48000/2\r\n",
    "a=fmtp:97 minptime=10;useinbandfec=1\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=fmtp:101 0-16\r\n",
);

const AUDIO_VIDEO_SDP: &str = concat!(
    "v=0\r\n",
    "o=bob 1234567890 1234567890 IN IP4 192.168.1.1\r\n",
    "s=Session\r\n",
    "c=IN IP4 192.168.1.1\r\n",
    "t=0 0\r\n",
    "m=audio 5004 RTP/AVP 0 8\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:8 PCMA/8000\r\n",
    "m=video 5006 RTP/AVP 96 97\r\n",
    "a=rtpmap:96 H264/90000\r\n",
    "a=fmtp:96 profile-level-id=42e01e\r\n",
    "a=rtpmap:97 VP8/90000\r\n",
);

// ---------------------------------------------------------------------------
// Parse audio-only SDP
// ---------------------------------------------------------------------------

#[test]
fn parse_audio_only_sdp() {
    let sdp = SdpBody::parse(AUDIO_ONLY_SDP);

    // Session-level lines: v=, o=, s=, c=, t=
    assert_eq!(sdp.session_lines.len(), 5);
    assert!(sdp.session_lines[0].starts_with("v=0"));
    assert!(sdp.session_lines[1].starts_with("o=alice"));

    // Single audio media section.
    assert_eq!(sdp.media_sections.len(), 1);
    let media = &sdp.media_sections[0];
    assert_eq!(media.media_type, "audio");
    assert_eq!(media.port, 49170);
    assert_eq!(media.protocol, "RTP/AVP");
    assert_eq!(media.formats, vec![0, 8, 97, 101]);
    assert_eq!(media.rtpmap.len(), 4);
    assert_eq!(media.fmtp.len(), 2);
}

// ---------------------------------------------------------------------------
// Parse audio+video SDP
// ---------------------------------------------------------------------------

#[test]
fn parse_audio_and_video_sdp() {
    let sdp = SdpBody::parse(AUDIO_VIDEO_SDP);

    assert_eq!(sdp.media_sections.len(), 2);

    let audio = &sdp.media_sections[0];
    assert_eq!(audio.media_type, "audio");
    assert_eq!(audio.port, 5004);
    assert_eq!(audio.formats, vec![0, 8]);
    assert_eq!(audio.rtpmap.len(), 2);

    let video = &sdp.media_sections[1];
    assert_eq!(video.media_type, "video");
    assert_eq!(video.port, 5006);
    assert_eq!(video.formats, vec![96, 97]);
    assert_eq!(video.rtpmap.len(), 2);
    assert_eq!(video.fmtp.len(), 1);
    assert_eq!(video.fmtp[0].0, 96);
    assert!(video.fmtp[0].1.contains("profile-level-id"));
}

// ---------------------------------------------------------------------------
// filter_codecs: keep only PCMU
// ---------------------------------------------------------------------------

#[test]
fn filter_codecs_keep_pcmu_only() {
    let mut sdp = SdpBody::parse(AUDIO_ONLY_SDP);
    sdp.filter_codecs(&["PCMU"]);

    let media = &sdp.media_sections[0];
    assert_eq!(media.formats, vec![0]);
    assert_eq!(media.rtpmap.len(), 1);
    assert_eq!(media.rtpmap[0].1, "PCMU/8000");
    assert!(
        media.fmtp.is_empty(),
        "opus and telephone-event fmtp should be removed"
    );
}

#[test]
fn filter_codecs_is_case_insensitive() {
    let mut sdp = SdpBody::parse(AUDIO_ONLY_SDP);
    sdp.filter_codecs(&["pcmu", "Opus"]);

    let media = &sdp.media_sections[0];
    assert_eq!(media.formats, vec![0, 97]);
}

#[test]
fn filter_codecs_keep_pcmu_and_pcma() {
    let mut sdp = SdpBody::parse(AUDIO_ONLY_SDP);
    sdp.filter_codecs(&["PCMU", "PCMA"]);

    let media = &sdp.media_sections[0];
    assert_eq!(media.formats, vec![0, 8]);
    assert_eq!(media.rtpmap.len(), 2);
    assert!(media.fmtp.is_empty());
}

// ---------------------------------------------------------------------------
// remove_codecs: remove telephone-event
// ---------------------------------------------------------------------------

#[test]
fn remove_codecs_telephone_event() {
    let mut sdp = SdpBody::parse(AUDIO_ONLY_SDP);
    sdp.remove_codecs(&["telephone-event"]);

    let media = &sdp.media_sections[0];
    assert_eq!(media.formats, vec![0, 8, 97]);
    assert!(!media
        .rtpmap
        .iter()
        .any(|(_, codec)| codec.contains("telephone-event")));
    assert!(!media.fmtp.iter().any(|(pt, _)| *pt == 101));
}

#[test]
fn remove_codecs_opus_removes_fmtp() {
    let mut sdp = SdpBody::parse(AUDIO_ONLY_SDP);
    sdp.remove_codecs(&["opus"]);

    let media = &sdp.media_sections[0];
    assert_eq!(media.formats, vec![0, 8, 101]);
    assert!(!media.rtpmap.iter().any(|(_, codec)| codec.contains("opus")));
    assert!(!media.fmtp.iter().any(|(pt, _)| *pt == 97));
}

// ---------------------------------------------------------------------------
// Parse-serialize-reparse roundtrip
// ---------------------------------------------------------------------------

#[test]
fn parse_serialize_reparse_roundtrip_audio_only() {
    let original = SdpBody::parse(AUDIO_ONLY_SDP);
    let serialized = original.to_string();
    let reparsed = SdpBody::parse(&serialized);

    assert_eq!(reparsed.session_lines.len(), original.session_lines.len());
    assert_eq!(reparsed.media_sections.len(), original.media_sections.len());

    let original_media = &original.media_sections[0];
    let reparsed_media = &reparsed.media_sections[0];
    assert_eq!(reparsed_media.media_type, original_media.media_type);
    assert_eq!(reparsed_media.port, original_media.port);
    assert_eq!(reparsed_media.protocol, original_media.protocol);
    assert_eq!(reparsed_media.formats, original_media.formats);
    assert_eq!(reparsed_media.rtpmap, original_media.rtpmap);
    assert_eq!(reparsed_media.fmtp, original_media.fmtp);
}

#[test]
fn parse_serialize_reparse_roundtrip_audio_video() {
    let original = SdpBody::parse(AUDIO_VIDEO_SDP);
    let serialized = original.to_string();
    let reparsed = SdpBody::parse(&serialized);

    assert_eq!(reparsed.session_lines.len(), original.session_lines.len());
    assert_eq!(reparsed.media_sections.len(), 2);

    for index in 0..2 {
        assert_eq!(
            reparsed.media_sections[index].formats,
            original.media_sections[index].formats
        );
        assert_eq!(
            reparsed.media_sections[index].rtpmap,
            original.media_sections[index].rtpmap
        );
    }
}

#[test]
fn filter_then_roundtrip() {
    let mut sdp = SdpBody::parse(AUDIO_ONLY_SDP);
    sdp.filter_codecs(&["PCMU", "PCMA"]);

    let serialized = sdp.to_string();
    let reparsed = SdpBody::parse(&serialized);

    let media = &reparsed.media_sections[0];
    assert_eq!(media.formats, vec![0, 8]);
    assert_eq!(media.rtpmap.len(), 2);
    assert!(media.fmtp.is_empty());
}

// ---------------------------------------------------------------------------
// Edge case: SDP with no media lines
// ---------------------------------------------------------------------------

#[test]
fn parse_sdp_with_no_media_lines() {
    let sdp_str = concat!(
        "v=0\r\n",
        "o=- 0 0 IN IP4 0.0.0.0\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
    );

    let sdp = SdpBody::parse(sdp_str);
    assert_eq!(sdp.session_lines.len(), 4);
    assert!(sdp.media_sections.is_empty());

    // Serialization should work fine with no media sections.
    let output = sdp.to_string();
    assert!(output.contains("v=0"));
    assert!(!output.contains("m="));
}

#[test]
fn parse_empty_sdp() {
    let sdp = SdpBody::parse("");
    assert!(sdp.session_lines.is_empty());
    assert!(sdp.media_sections.is_empty());
}

// ---------------------------------------------------------------------------
// Session-level attribute preservation
// ---------------------------------------------------------------------------

#[test]
fn session_level_attributes_survive_codec_filtering() {
    let sdp_str = concat!(
        "v=0\r\n",
        "o=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n",
        "s=SIPhon Call\r\n",
        "c=IN IP4 10.0.0.1\r\n",
        "t=0 0\r\n",
        "m=audio 49170 RTP/AVP 0 8 97\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
        "a=rtpmap:97 opus/48000/2\r\n",
    );

    let mut sdp = SdpBody::parse(sdp_str);

    // Verify session-level lines.
    assert_eq!(sdp.session_lines.len(), 5);
    assert!(sdp.session_lines[2].contains("SIPhon Call"));

    // Filter codecs.
    sdp.filter_codecs(&["PCMU"]);

    // Session-level lines should be unchanged.
    assert_eq!(sdp.session_lines.len(), 5);
    assert!(sdp.session_lines[2].contains("SIPhon Call"));

    // Verify in serialized output.
    let output = sdp.to_string();
    assert!(output.contains("s=SIPhon Call"));
    assert!(output.contains("c=IN IP4 10.0.0.1"));
    assert!(output.contains("t=0 0"));
}

// ---------------------------------------------------------------------------
// Media-level other_attrs preservation
// ---------------------------------------------------------------------------

#[test]
fn media_level_other_attrs_preserved_after_filtering() {
    let sdp_str = concat!(
        "v=0\r\n",
        "o=- 0 0 IN IP4 0.0.0.0\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
        "m=audio 5004 RTP/AVP 0 8\r\n",
        "c=IN IP4 192.168.1.1\r\n",
        "a=sendrecv\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
    );

    let mut sdp = SdpBody::parse(sdp_str);

    // The c= and a=sendrecv lines should be in other_attrs.
    let media = &sdp.media_sections[0];
    assert!(media
        .other_attrs
        .iter()
        .any(|attr| attr.contains("sendrecv")));
    assert!(media
        .other_attrs
        .iter()
        .any(|attr| attr.contains("c=IN IP4")));

    // Filter to PCMU only.
    sdp.filter_codecs(&["PCMU"]);

    // other_attrs should still be there.
    let media = &sdp.media_sections[0];
    assert!(media
        .other_attrs
        .iter()
        .any(|attr| attr.contains("sendrecv")));

    // Verify in serialized output.
    let output = sdp.to_string();
    assert!(output.contains("a=sendrecv"));
    assert!(output.contains("c=IN IP4 192.168.1.1"));
}

// ---------------------------------------------------------------------------
// Static codec filtering without explicit rtpmap
// ---------------------------------------------------------------------------

#[test]
fn filter_static_codecs_without_rtpmap() {
    let sdp_str = concat!(
        "v=0\r\n",
        "o=- 0 0 IN IP4 0.0.0.0\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
        "m=audio 5004 RTP/AVP 0 8\r\n",
    );

    let mut sdp = SdpBody::parse(sdp_str);
    sdp.filter_codecs(&["PCMU"]);

    assert_eq!(sdp.media_sections[0].formats, vec![0]);
}

// ---------------------------------------------------------------------------
// rewrite_sdp_body convenience function
// ---------------------------------------------------------------------------

#[test]
fn rewrite_sdp_body_returns_filtered_body_and_length() {
    let (new_body, length) = rewrite_sdp_body(AUDIO_ONLY_SDP, &["PCMU"]);

    assert!(new_body.contains("PCMU"));
    assert!(!new_body.contains("PCMA"));
    assert!(!new_body.contains("opus"));
    assert!(!new_body.contains("telephone-event"));
    assert_eq!(length, new_body.len());
}

// ---------------------------------------------------------------------------
// Multi-media section filtering
// ---------------------------------------------------------------------------

#[test]
fn filter_codecs_applies_to_each_media_section() {
    let mut sdp = SdpBody::parse(AUDIO_VIDEO_SDP);

    // Keep only PCMU in audio and H264 in video.
    sdp.filter_codecs(&["PCMU", "H264"]);

    let audio = &sdp.media_sections[0];
    assert_eq!(audio.formats, vec![0]);

    let video = &sdp.media_sections[1];
    assert_eq!(video.formats, vec![96]);
    assert_eq!(video.rtpmap.len(), 1);
    assert!(video.rtpmap[0].1.contains("H264"));
}
