//! Known-answer tests from profile XML written to the TS 29.228 Annex E
//! schema: shared iFC sets (Annex B.2, `tServiceProfileExtension`), session
//! case 4 (`tDirectionOfRequest` ORIGINATING_CDIV) and SessionDescription
//! trigger points (Annex F).

use super::*;
use crate::config::SharedIfcSetConfig;

const AOR: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";

/// An `<InitialFilterCriteria>` triggered on INVITE, at `priority`, to `server`.
fn invite_ifc(priority: i32, server: &str) -> String {
    format!(
        "<InitialFilterCriteria><Priority>{priority}</Priority>\
         <TriggerPoint><ConditionTypeCNF>0</ConditionTypeCNF>\
         <SPT><ConditionNegated>0</ConditionNegated><Group>0</Group><Method>INVITE</Method></SPT>\
         </TriggerPoint>\
         <ApplicationServer><ServerName>{server}</ServerName><DefaultHandling>0</DefaultHandling>\
         </ApplicationServer></InitialFilterCriteria>"
    )
}

/// A user profile in the Annex E form: its own iFCs, then the
/// SharedIFCSetIDs its Extension names.
fn user_profile(ifcs: &str, shared_ids: &[u32]) -> String {
    let ids: String = shared_ids
        .iter()
        .map(|id| format!("<SharedIFCSetID>{id}</SharedIFCSetID>"))
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <IMSSubscription><PrivateID>001010000000001@ims.mnc001.mcc001.3gppnetwork.org</PrivateID>\
         <ServiceProfile><PublicIdentity><Identity>{AOR}</Identity></PublicIdentity>\
         {ifcs}<Extension>{ids}</Extension></ServiceProfile></IMSSubscription>"
    )
}

fn shared_sets() -> HashMap<u32, Vec<InitialFilterCriteria>> {
    HashMap::from([
        (
            1,
            parse_service_profile(&invite_ifc(20, "sip:as-b.example.com")).expect("set 1 parses"),
        ),
        (
            7,
            parse_service_profile(&invite_ifc(10, "sip:as-a.example.com")).expect("set 7 parses"),
        ),
    ])
}

fn servers(matched: &[MatchedApplicationServer]) -> Vec<&str> {
    matched
        .iter()
        .map(|server| server.server_name.as_str())
        .collect()
}

fn invite(store: &IfcStore, body: Option<&str>) -> Vec<MatchedApplicationServer> {
    store.evaluate(
        AOR,
        "INVITE",
        "sip:bob@example.com",
        &[],
        SessionCase::Originating,
        None,
        body,
    )
}

#[test]
fn shared_ifc_set_ids_are_read_from_the_service_profile_extension() {
    let profile = parse_user_profile(&user_profile("", &[1, 7, 1])).expect("parses");
    assert!(profile.ifcs.is_empty());
    assert_eq!(profile.shared_ifc_set_ids, [1, 7], "duplicates removed");
}

/// A profile made only of SharedIFCSetIDs evaluates to the configured sets,
/// in priority order, and `store_profile` counts their iFCs.
#[test]
fn a_profile_of_only_shared_sets_evaluates_to_the_sets_in_priority_order() {
    let store = IfcStore::new(Vec::new());
    store.set_shared_sets(shared_sets());
    let count = store
        .store_profile_xml(AOR, &user_profile("", &[1, 7]))
        .expect("stores");
    assert_eq!(count, 2, "the iFCs of both sets, not 0");
    assert_eq!(
        servers(&invite(&store, None)),
        ["sip:as-a.example.com", "sip:as-b.example.com"]
    );
    assert_eq!(store.shared_set_ids(AOR), [1, 7]);
}

/// The profile's own iFCs and the shared ones are merged by Priority, and a
/// resumed evaluation (`start_after_priority`) sees the shared ones too.
#[test]
fn own_and_shared_ifcs_merge_by_priority() {
    let store = IfcStore::new(Vec::new());
    store.set_shared_sets(shared_sets());
    store
        .store_profile_xml(
            AOR,
            &user_profile(&invite_ifc(15, "sip:own.example.com"), &[1, 7]),
        )
        .expect("stores");
    assert_eq!(
        servers(&invite(&store, None)),
        [
            "sip:as-a.example.com",
            "sip:own.example.com",
            "sip:as-b.example.com"
        ]
    );
    let resumed = store.evaluate(
        AOR,
        "INVITE",
        "sip:bob@example.com",
        &[],
        SessionCase::Originating,
        Some(15),
        None,
    );
    assert_eq!(servers(&resumed), ["sip:as-b.example.com"]);
}

/// An id with no local set contributes nothing (and is warned about); the
/// rest of the profile still applies.
#[test]
fn an_unknown_shared_set_id_applies_nothing_and_the_rest_still_applies() {
    let store = IfcStore::new(Vec::new());
    store.set_shared_sets(shared_sets());
    let count = store
        .store_profile_xml(AOR, &user_profile("", &[7, 99]))
        .expect("stores");
    assert_eq!(count, 1);
    assert_eq!(servers(&invite(&store, None)), ["sip:as-a.example.com"]);
    assert_eq!(store.shared_set_ids(AOR), [7, 99]);
}

#[test]
fn removing_the_profile_forgets_its_shared_set_ids() {
    let store = IfcStore::new(Vec::new());
    store.set_shared_sets(shared_sets());
    store
        .store_profile_xml(AOR, &user_profile("", &[1]))
        .expect("stores");
    assert!(store.remove_profile(AOR));
    assert!(store.shared_set_ids(AOR).is_empty());
}

#[test]
fn a_shared_set_id_that_is_not_a_non_negative_integer_is_refused() {
    assert!(parse_user_profile(&user_profile("", &[]).replace(
        "<Extension></Extension>",
        "<Extension><SharedIFCSetID>-1</SharedIFCSetID></Extension>"
    ))
    .is_err());
}

/// Shared sets load from a file or inline, and a reload keeps a set whose
/// file no longer parses.
#[test]
fn shared_sets_load_from_files_and_a_bad_reload_keeps_the_old_set() {
    let directory = std::env::temp_dir().join(format!("siphon-sifc-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a scratch directory");
    let file = directory.join("1.xml");
    std::fs::write(
        &file,
        format!(
            "<SharedIFCs>{}</SharedIFCs>",
            invite_ifc(5, "sip:file.example.com")
        ),
    )
    .expect("the set is written");
    let configured = vec![
        SharedIfcSetConfig {
            id: 1,
            file: Some(file.display().to_string()),
            xml: None,
        },
        SharedIfcSetConfig {
            id: 2,
            file: None,
            xml: Some(invite_ifc(6, "sip:inline.example.com")),
        },
    ];
    let store = IfcStore::new(Vec::new());
    store.set_shared_sets(load_shared_ifc_sets(&configured));
    assert!(store.has_shared_sets());
    store
        .store_profile_xml(AOR, &user_profile("", &[1, 2]))
        .expect("stores");
    assert_eq!(
        servers(&invite(&store, None)),
        ["sip:file.example.com", "sip:inline.example.com"]
    );

    std::fs::write(&file, "<InitialFilterCriteria><Priority>").expect("a broken edit");
    store.reload_shared_sets(&configured);
    assert_eq!(
        servers(&invite(&store, None)),
        ["sip:file.example.com", "sip:inline.example.com"],
        "the set that no longer parses keeps what it had"
    );

    std::fs::write(&file, invite_ifc(5, "sip:edited.example.com")).expect("a good edit");
    store.reload_shared_sets(&configured);
    assert_eq!(
        servers(&invite(&store, None)),
        ["sip:edited.example.com", "sip:inline.example.com"]
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// One iFC per session case code, 0 to 4 (Annex E `tDirectionOfRequest`).
fn session_case_profile() -> String {
    let ifc = |priority: u32, code: u32| {
        format!(
            "<InitialFilterCriteria><Priority>{priority}</Priority>\
             <TriggerPoint><ConditionTypeCNF>0</ConditionTypeCNF>\
             <SPT><ConditionNegated>0</ConditionNegated><Group>0</Group><SessionCase>{code}</SessionCase></SPT>\
             </TriggerPoint>\
             <ApplicationServer><ServerName>sip:case-{code}.example.com</ServerName></ApplicationServer>\
             </InitialFilterCriteria>"
        )
    };
    user_profile(
        &(0..=4).map(|code| ifc(code + 1, code)).collect::<String>(),
        &[],
    )
}

/// An iFC with `<SessionCase>4</SessionCase>` matches `originating_cdiv` and
/// nothing else; each other code matches its own case only.
#[test]
fn session_case_four_matches_originating_cdiv_and_nothing_else() {
    let store = IfcStore::new(Vec::new());
    store
        .store_profile_xml(AOR, &session_case_profile())
        .expect("stores");
    for (case, expected) in [
        (SessionCase::Originating, "sip:case-0.example.com"),
        (SessionCase::Terminating, "sip:case-1.example.com"),
        (
            SessionCase::TerminatingUnregistered,
            "sip:case-2.example.com",
        ),
        (
            SessionCase::OriginatingUnregistered,
            "sip:case-3.example.com",
        ),
        (SessionCase::OriginatingCdiv, "sip:case-4.example.com"),
    ] {
        let matched = store.evaluate(AOR, "INVITE", "sip:bob@example.com", &[], case, None, None);
        assert_eq!(servers(&matched), [expected], "{case}");
    }
    assert_eq!(SessionCase::OriginatingCdiv.to_string(), "OriginatingCdiv");
}

/// A session case outside 0 to 4 fails the profile rather than becoming an
/// SPT that never matches.
#[test]
fn a_session_case_outside_the_schema_fails_the_profile() {
    for bad in ["5", "originating", ""] {
        let xml = session_case_profile().replace(
            "<SessionCase>4</SessionCase>",
            &format!("<SessionCase>{bad}</SessionCase>"),
        );
        assert!(
            matches!(parse_user_profile(&xml), Err(IfcError::InvalidFormat(_))),
            "{bad:?}"
        );
    }
}

/// An iFC routing video calls: `<SessionDescription><Line>m</Line>
/// <Content>video</Content>` (Annex F), plain or negated.
fn video_profile(negated: bool) -> String {
    user_profile(
        &format!(
            "<InitialFilterCriteria><Priority>1</Priority>\
             <TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF>\
             <SPT><ConditionNegated>0</ConditionNegated><Group>0</Group><Method>INVITE</Method></SPT>\
             <SPT><ConditionNegated>{}</ConditionNegated><Group>1</Group>\
             <SessionDescription><Line>m</Line><Content>video</Content></SessionDescription></SPT>\
             </TriggerPoint>\
             <ApplicationServer><ServerName>sip:video-as.example.com</ServerName></ApplicationServer>\
             </InitialFilterCriteria>",
            u8::from(negated)
        ),
        &[],
    )
}

const AUDIO_VIDEO_OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 49170 RTP/AVP 96\r\n",
    "a=rtpmap:96 AMR-WB/16000\r\n",
    "m=video 49172 RTP/AVP 97\r\n",
    "a=rtpmap:97 H264/90000\r\n",
);

const AUDIO_ONLY_OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 49170 RTP/AVP 96\r\n",
    "a=rtpmap:96 AMR-WB/16000\r\n",
);

/// An `m` / `video` SPT matches an audio+video offer and not an audio-only
/// one; its negation the reverse. A request with no SDP has no field to
/// match, so the plain SPT does not match and the negated one does.
#[test]
fn a_session_description_trigger_matches_the_sdp_of_the_request() {
    let store = IfcStore::new(Vec::new());
    store
        .store_profile_xml(AOR, &video_profile(false))
        .expect("stores");
    assert_eq!(
        servers(&invite(&store, Some(AUDIO_VIDEO_OFFER))),
        ["sip:video-as.example.com"]
    );
    assert!(invite(&store, Some(AUDIO_ONLY_OFFER)).is_empty());
    assert!(invite(&store, None).is_empty());

    store
        .store_profile_xml(AOR, &video_profile(true))
        .expect("stores");
    assert!(invite(&store, Some(AUDIO_VIDEO_OFFER)).is_empty());
    assert_eq!(
        servers(&invite(&store, Some(AUDIO_ONLY_OFFER))),
        ["sip:video-as.example.com"]
    );
    assert_eq!(servers(&invite(&store, None)), ["sip:video-as.example.com"]);
}

/// `Line` is a regular expression on the field type and `Content` on its
/// value: a codec trigger on `a` / `rtpmap:[0-9]+ H264`.
#[test]
fn line_and_content_are_regular_expressions() {
    let profile = video_profile(false)
        .replace("<Line>m</Line>", "<Line>^a$</Line>")
        .replace(
            "<Content>video</Content>",
            "<Content>^rtpmap:[0-9]+ H264/</Content>",
        );
    let store = IfcStore::new(Vec::new());
    store.store_profile_xml(AOR, &profile).expect("stores");
    assert_eq!(servers(&invite(&store, Some(AUDIO_VIDEO_OFFER))).len(), 1);
    assert!(invite(&store, Some(AUDIO_ONLY_OFFER)).is_empty());
}

/// A SessionDescription with no Content matches any field of the type.
#[test]
fn a_line_with_no_content_matches_any_field_of_that_type() {
    let profile = video_profile(false).replace("<Content>video</Content>", "");
    let store = IfcStore::new(Vec::new());
    store.store_profile_xml(AOR, &profile).expect("stores");
    assert_eq!(servers(&invite(&store, Some(AUDIO_ONLY_OFFER))).len(), 1);
}

/// Lines of a multipart body that are not `<type>=<value>` fields, such as
/// another part's XML, are not read as SDP.
#[test]
fn lines_that_are_not_sdp_fields_are_skipped() {
    let profile = video_profile(false)
        .replace("<Line>m</Line>", "<Line>.</Line>")
        .replace("<Content>video</Content>", "<Content>urn</Content>");
    let store = IfcStore::new(Vec::new());
    store.store_profile_xml(AOR, &profile).expect("stores");
    let body = "<presence entity=\"urn:example\">\r\nm=audio 9 RTP/AVP 0\r\n";
    assert!(invite(&store, Some(body)).is_empty());
}

/// Profiles written to the older `<SDPLine>` element still parse.
#[test]
fn the_older_sdp_line_element_is_still_read() {
    let profile = video_profile(false)
        .replace("<SessionDescription>", "<SDPLine>")
        .replace("</SessionDescription>", "</SDPLine>");
    let store = IfcStore::new(Vec::new());
    store.store_profile_xml(AOR, &profile).expect("stores");
    assert_eq!(servers(&invite(&store, Some(AUDIO_VIDEO_OFFER))).len(), 1);
}
