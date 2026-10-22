//! AVP codes, for encoding. The definitions these belong to (vendor, name and
//! type) are in the table of the parent module.

// Base Diameter
pub const USER_NAME: u32 = 1;
pub const HOST_IP_ADDRESS: u32 = 257;
pub const AUTH_APPLICATION_ID: u32 = 258;
pub const VENDOR_SPECIFIC_APPLICATION_ID: u32 = 260;
pub const SESSION_ID: u32 = 263;
pub const ORIGIN_HOST: u32 = 264;
pub const SUPPORTED_VENDOR_ID: u32 = 265;
pub const VENDOR_ID: u32 = 266;
pub const FIRMWARE_REVISION: u32 = 267;
pub const RESULT_CODE: u32 = 268;
pub const PRODUCT_NAME: u32 = 269;
pub const DISCONNECT_CAUSE: u32 = 273;
pub const AUTH_SESSION_STATE: u32 = 277;
pub const ORIGIN_STATE_ID: u32 = 278;
pub const ERROR_MESSAGE: u32 = 281;
pub const ROUTE_RECORD: u32 = 282;
pub const DESTINATION_REALM: u32 = 283;
pub const DESTINATION_HOST: u32 = 293;
pub const TERMINATION_CAUSE: u32 = 295;
pub const ORIGIN_REALM: u32 = 296;
pub const EXPERIMENTAL_RESULT: u32 = 297;
pub const EXPERIMENTAL_RESULT_CODE: u32 = 298;
pub const FAILED_AVP: u32 = 279;

// RFC 6733 §8.21 Event-Timestamp / §8.19 Acct-Interim-Interval
pub const EVENT_TIMESTAMP: u32 = 55;
pub const ACCT_INTERIM_INTERVAL: u32 = 85;

// Base RADIUS/Diameter
pub const FRAMED_IP_ADDRESS: u32 = 8;
pub const FRAMED_IPV6_PREFIX: u32 = 97;
pub const ACCT_APPLICATION_ID: u32 = 259;

// Accounting (RFC 6733)
pub const ACCOUNTING_RECORD_TYPE: u32 = 480;
pub const ACCOUNTING_RECORD_NUMBER: u32 = 485;

// RFC 8506 (obsoletes RFC 4006) Credit-Control / Gy — vendor 0.
// Codes per the IANA aaa-parameters registry; see the AVP_TABLE note.
pub const FILTER_ID: u32 = 11;
pub const CC_INPUT_OCTETS: u32 = 412;
pub const CC_MONEY: u32 = 413;
pub const CC_OUTPUT_OCTETS: u32 = 414;
pub const CC_REQUEST_NUMBER: u32 = 415;
pub const CC_REQUEST_TYPE: u32 = 416;
pub const CC_SERVICE_SPECIFIC_UNITS: u32 = 417;
pub const CC_SESSION_FAILOVER: u32 = 418;
pub const CC_SUB_SESSION_ID: u32 = 419;
pub const CC_TIME: u32 = 420;
pub const CC_TOTAL_OCTETS: u32 = 421;
pub const CREDIT_CONTROL_FAILURE_HANDLING: u32 = 427;
pub const FINAL_UNIT_INDICATION: u32 = 430;
pub const GRANTED_SERVICE_UNIT: u32 = 431;
pub const RATING_GROUP: u32 = 432;
pub const REDIRECT_ADDRESS_TYPE: u32 = 433;
pub const REDIRECT_SERVER: u32 = 434;
pub const REDIRECT_SERVER_ADDRESS: u32 = 435;
pub const REQUESTED_ACTION: u32 = 436;
pub const REQUESTED_SERVICE_UNIT: u32 = 437;
pub const RESTRICTION_FILTER_RULE: u32 = 438;
pub const SERVICE_IDENTIFIER: u32 = 439;
pub const SUBSCRIPTION_ID: u32 = 443;
pub const SUBSCRIPTION_ID_DATA: u32 = 444;
pub const USED_SERVICE_UNIT: u32 = 446;
pub const VALIDITY_TIME: u32 = 448;
pub const FINAL_UNIT_ACTION: u32 = 449;
pub const TARIFF_TIME_CHANGE: u32 = 451;
pub const SUBSCRIPTION_ID_TYPE: u32 = 450;
pub const G_S_U_POOL_IDENTIFIER: u32 = 453;
pub const MULTIPLE_SERVICES_INDICATOR: u32 = 455;
pub const MULTIPLE_SERVICES_CREDIT_CONTROL: u32 = 456;
pub const G_S_U_POOL_REFERENCE: u32 = 457;
pub const USER_EQUIPMENT_INFO: u32 = 458;
pub const USER_EQUIPMENT_INFO_TYPE: u32 = 459;
pub const USER_EQUIPMENT_INFO_VALUE: u32 = 460;
pub const SERVICE_CONTEXT_ID: u32 = 461;

// 3GPP Cx (TS 29.228)
pub const VISITED_NETWORK_IDENTIFIER: u32 = 600;
pub const PUBLIC_IDENTITY: u32 = 601;
pub const SERVER_NAME: u32 = 602;
pub const SERVER_CAPABILITIES: u32 = 603;
pub const MANDATORY_CAPABILITY: u32 = 604;
pub const OPTIONAL_CAPABILITY: u32 = 605;
pub const USER_DATA_CX: u32 = 606;
pub const SIP_NUMBER_AUTH_ITEMS: u32 = 607;
pub const SIP_AUTHENTICATION_SCHEME: u32 = 608;
pub const SIP_AUTHENTICATE: u32 = 609;
pub const SIP_AUTHORIZATION: u32 = 610;
pub const SIP_AUTH_DATA_ITEM: u32 = 612;
pub const SERVER_ASSIGNMENT_TYPE: u32 = 614;
pub const DEREGISTRATION_REASON: u32 = 615;
pub const REASON_CODE: u32 = 616;
pub const REASON_INFO: u32 = 617;
pub const CHARGING_INFORMATION: u32 = 618;
pub const USER_AUTHORIZATION_TYPE: u32 = 623;
pub const USER_DATA_ALREADY_AVAILABLE: u32 = 624;
pub const CONFIDENTIALITY_KEY: u32 = 625;
pub const INTEGRITY_KEY: u32 = 626;
pub const SUPPORTED_FEATURES: u32 = 628;
pub const FEATURE_LIST_ID: u32 = 629;
pub const FEATURE_LIST: u32 = 630;
pub const SIP_DIGEST_AUTHENTICATE: u32 = 635;
// IMS restoration (TS 29.229 table 6.3.1)
pub const SCSCF_RESTORATION_INFO: u32 = 639;
pub const PATH: u32 = 640;
pub const CONTACT: u32 = 641;
pub const SUBSCRIPTION_INFO: u32 = 642;
pub const CALL_ID_SIP_HEADER: u32 = 643;
pub const FROM_SIP_HEADER: u32 = 644;
pub const TO_SIP_HEADER: u32 = 645;
pub const RECORD_ROUTE: u32 = 646;
pub const ASSOCIATED_REGISTERED_IDENTITIES: u32 = 647;
pub const MULTIPLE_REGISTRATION_INDICATION: u32 = 648;
pub const RESTORATION_INFO: u32 = 649;
pub const INITIAL_CSEQ_SEQUENCE_NUMBER: u32 = 654;
pub const SAR_FLAGS: u32 = 655;
pub const PCSCF_SUBSCRIPTION_INFO: u32 = 660;
pub const REGISTRATION_TIME_OUT: u32 = 661;
pub const FAILED_PCSCF: u32 = 664;
pub const PCSCF_FQDN: u32 = 665;
pub const PCSCF_IP_ADDRESS: u32 = 666;
pub const ALTERNATE_DIGEST_ALGORITHM: u32 = 662;
pub const ALTERNATE_DIGEST_HA1: u32 = 663;
// RFC 5090 digest attributes, no vendor (TS 29.229 table 6.3.0.1)
pub const DIGEST_REALM: u32 = 104;
pub const DIGEST_QOP: u32 = 110;
pub const DIGEST_ALGORITHM: u32 = 111;
pub const DIGEST_HA1: u32 = 121;

// 3GPP GBA, Zh and Zn (TS 29.109 Table 6.1)
pub const GBA_USER_SEC_SETTINGS: u32 = 400;
pub const TRANSACTION_IDENTIFIER: u32 = 401;
pub const NAF_ID: u32 = 402;
pub const GAA_SERVICE_IDENTIFIER: u32 = 403;
pub const KEY_EXPIRY_TIME: u32 = 404;
pub const ME_KEY_MATERIAL: u32 = 405;
pub const UICC_KEY_MATERIAL: u32 = 406;
pub const GBA_U_AWARENESS_INDICATOR: u32 = 407;
pub const BOOTSTRAP_INFO_CREATION_TIME: u32 = 408;
pub const GUSS_TIMESTAMP: u32 = 409;
pub const GBA_TYPE: u32 = 410;

// 3GPP Sh (TS 29.329)
pub const MSISDN: u32 = 701;
pub const USER_IDENTITY: u32 = 700;
pub const USER_DATA_SH: u32 = 702;
pub const DATA_REFERENCE: u32 = 703;
pub const SERVICE_INDICATION: u32 = 704;
pub const SUBS_REQ_TYPE: u32 = 705;

// 3GPP Gx (TS 29.212)
pub const CHARGING_RULE_INSTALL: u32 = 1001;
pub const CHARGING_RULE_REMOVE: u32 = 1002;
pub const CHARGING_RULE_DEFINITION: u32 = 1003;
pub const CHARGING_RULE_BASE_NAME: u32 = 1004;
pub const CHARGING_RULE_NAME: u32 = 1005;
pub const EVENT_TRIGGER: u32 = 1006;
pub const METERING_METHOD: u32 = 1007;
pub const OFFLINE: u32 = 1008;
pub const ONLINE: u32 = 1009;
pub const PRECEDENCE: u32 = 1010;
pub const QOS_INFORMATION: u32 = 1016;
pub const BEARER_IDENTIFIER: u32 = 1020;
pub const GUARANTEED_BITRATE_DL: u32 = 1025;
pub const GUARANTEED_BITRATE_UL: u32 = 1026;
pub const IP_CAN_TYPE: u32 = 1027;
pub const QOS_CLASS_IDENTIFIER: u32 = 1028;
pub const ALLOCATION_RETENTION_PRIORITY: u32 = 1034;
pub const FLOW_INFORMATION: u32 = 1058;
pub const FLOW_DIRECTION: u32 = 1080;
pub const APN_AGGREGATE_MAX_BITRATE_DL: u32 = 1040;
pub const APN_AGGREGATE_MAX_BITRATE_UL: u32 = 1041;
pub const PRIORITY_LEVEL: u32 = 1046;
pub const PRE_EMPTION_CAPABILITY: u32 = 1047;
pub const PRE_EMPTION_VULNERABILITY: u32 = 1048;
pub const DEFAULT_EPS_BEARER_QOS: u32 = 1049;
pub const AN_GW_ADDRESS: u32 = 1050;
pub const REVALIDATION_TIME: u32 = 1042;
pub const THREE_GPP_PS_DATA_OFF_STATUS: u32 = 2847;

// 3GPP Rx (TS 29.214)
pub const ABORT_CAUSE: u32 = 500;
pub const ACCESS_NETWORK_CHARGING_ADDRESS: u32 = 501;
pub const ACCESS_NETWORK_CHARGING_IDENTIFIER: u32 = 502;
pub const AF_APPLICATION_IDENTIFIER: u32 = 504;
pub const AF_CHARGING_IDENTIFIER: u32 = 505;
pub const FLOW_DESCRIPTION: u32 = 507;
pub const FLOW_NUMBER: u32 = 509;
pub const FLOWS: u32 = 510;
pub const FLOW_STATUS: u32 = 511;
pub const FLOW_USAGE: u32 = 512;
pub const SPECIFIC_ACTION: u32 = 513;
pub const MAX_REQUESTED_BANDWIDTH_DL: u32 = 515;
pub const MAX_REQUESTED_BANDWIDTH_UL: u32 = 516;
pub const MEDIA_COMPONENT_DESCRIPTION: u32 = 517;
pub const MEDIA_COMPONENT_NUMBER: u32 = 518;
pub const MEDIA_SUB_COMPONENT: u32 = 519;
pub const MEDIA_TYPE: u32 = 520;
pub const RR_BANDWIDTH: u32 = 521;
pub const RS_BANDWIDTH: u32 = 522;
pub const SIP_FORKING_INDICATION: u32 = 523;
pub const CODEC_DATA: u32 = 524;
pub const SERVICE_URN: u32 = 525;
pub const ACCEPTABLE_SERVICE_INFO: u32 = 526;
pub const SERVICE_INFO_STATUS: u32 = 527;
pub const RX_REQUEST_TYPE: u32 = 533;
pub const MIN_REQUESTED_BANDWIDTH_DL: u32 = 534;
pub const MIN_REQUESTED_BANDWIDTH_UL: u32 = 535;

// 3GPP Ro/Rf Charging (TS 32.299)
pub const EVENT_TYPE: u32 = 823;
pub const SIP_METHOD_CHARGING: u32 = 824;
pub const EVENT: u32 = 825;
pub const ROLE_OF_NODE: u32 = 829;
pub const USER_SESSION_ID: u32 = 830;
pub const CALLING_PARTY_ADDRESS: u32 = 831;
pub const CALLED_PARTY_ADDRESS: u32 = 832;
pub const TIME_STAMPS: u32 = 833;
pub const SIP_REQUEST_TIMESTAMP: u32 = 834;
pub const SIP_RESPONSE_TIMESTAMP: u32 = 835;
pub const APPLICATION_SERVER: u32 = 836;
pub const APPLICATION_PROVIDED_CALLED_PARTY_ADDRESS: u32 = 837;
pub const INTER_OPERATOR_IDENTIFIER: u32 = 838;
pub const ORIGINATING_IOI: u32 = 839;
pub const TERMINATING_IOI: u32 = 840;
pub const IMS_CHARGING_IDENTIFIER: u32 = 841;
pub const SERVED_PARTY_IP_ADDRESS: u32 = 848;
pub const APPLICATION_SERVER_INFORMATION: u32 = 850;
pub const TRUNK_GROUP_ID: u32 = 851;
pub const INCOMING_TRUNK_GROUP_ID: u32 = 852;
pub const OUTGOING_TRUNK_GROUP_ID: u32 = 853;
pub const CAUSE_CODE: u32 = 861;
pub const NODE_FUNCTIONALITY: u32 = 862;
/// Time-Quota-Threshold (TS 32.299 §7.2.229): seconds of the granted time
/// left at which the CTF re-authorises, so the next grant arrives before the
/// current one runs out.
pub const TIME_QUOTA_THRESHOLD: u32 = 868;
pub const SERVICE_INFORMATION: u32 = 873;
pub const IMS_INFORMATION: u32 = 876;
pub const ACCESS_NETWORK_INFORMATION: u32 = 1263;
pub const IMS_VISITED_NETWORK_IDENTIFIER: u32 = 2713;

// 3GPP S6c served-node identifiers
pub const SGSN_NUMBER: u32 = 1489;
pub const MME_NUMBER_FOR_MT_SMS: u32 = 1645;
// Serving-Node (TS 29.272 §7.3.109) and its children — where an S6c SRA actually names
// the node serving the subscriber.
pub const SERVING_NODE: u32 = 2401;
pub const MME_NAME: u32 = 2402;
pub const MSC_NUMBER: u32 = 2403;
pub const MME_REALM: u32 = 2408;
pub const SGSN_NAME: u32 = 2409;
pub const SGSN_REALM: u32 = 2410;

// 3GPP S6c (TS 29.336) and SGd (TS 29.338) — SMS over Diameter
pub const USER_IDENTIFIER: u32 = 3102;
pub const SC_ADDRESS: u32 = 3300;
pub const SM_RP_UI: u32 = 3301;
pub const SM_RP_MTI: u32 = 3308;
pub const SM_DELIVERY_OUTCOME: u32 = 3316;
pub const MME_SM_DELIVERY_OUTCOME: u32 = 3317;
pub const MSC_SM_DELIVERY_OUTCOME: u32 = 3318;
pub const SGSN_SM_DELIVERY_OUTCOME: u32 = 3319;
pub const IP_SM_GW_SM_DELIVERY_OUTCOME: u32 = 3320;
pub const SM_DELIVERY_CAUSE: u32 = 3321;
pub const ABSENT_USER_DIAGNOSTIC_SM: u32 = 3322;
pub const SMSMI_CORRELATION_ID: u32 = 3324;
pub const SMS_GMSC_ADDRESS: u32 = 3332;

// 3GPP SMS-Information (TS 32.299 §7.2.79) — IMS SMS offline charging
pub const ORIGINATOR_ADDRESS: u32 = 886;
pub const ADDRESS_DATA: u32 = 897;
pub const ADDRESS_TYPE: u32 = 899;
pub const RECIPIENT_ADDRESS: u32 = 1201;
pub const SMS_INFORMATION: u32 = 2000;
pub const DATA_CODING_SCHEME: u32 = 2001;
pub const SM_MESSAGE_TYPE: u32 = 2007;
pub const ORIGINATOR_SCCP_ADDRESS: u32 = 2008;
pub const ORIGINATOR_INTERFACE: u32 = 2009;
pub const RECIPIENT_SCCP_ADDRESS: u32 = 2010;
pub const REPLY_PATH_REQUESTED: u32 = 2011;
pub const SM_DISCHARGE_TIME: u32 = 2012;
pub const SM_PROTOCOL_ID: u32 = 2013;
pub const SM_STATUS: u32 = 2014;
pub const SM_USER_DATA_HEADER: u32 = 2015;
pub const SMS_NODE: u32 = 2016;
pub const SMSC_ADDRESS: u32 = 2017;
pub const CLIENT_ADDRESS: u32 = 2018;
pub const NUMBER_OF_MESSAGES_SENT: u32 = 2019;
pub const RECIPIENT_INFO: u32 = 2026;
pub const ORIGINATOR_RECEIVED_ADDRESS: u32 = 2027;
pub const RECIPIENT_RECEIVED_ADDRESS: u32 = 2028;
pub const SM_SERVICE_TYPE: u32 = 2029;
pub const APPLICATION_PORT_IDENTIFIER: u32 = 3010;
pub const EXTERNAL_IDENTIFIER: u32 = 3111;
pub const SM_DEVICE_TRIGGER_INFORMATION: u32 = 3405;
pub const MTC_IWF_ADDRESS: u32 = 3406;
pub const SM_DEVICE_TRIGGER_INDICATOR: u32 = 3407;
pub const SMS_RESULT: u32 = 3409;

// ── S6a / S6d (TS 29.272) ────────────────────────────────────────────
pub const RAT_TYPE: u32 = 1032;
pub const SUBSCRIPTION_DATA: u32 = 1400;
pub const TERMINAL_INFORMATION: u32 = 1401;
pub const IMEI: u32 = 1402;
pub const SOFTWARE_VERSION: u32 = 1403;
pub const ULR_FLAGS: u32 = 1405;
pub const ULA_FLAGS: u32 = 1406;
pub const VISITED_PLMN_ID: u32 = 1407;
pub const REQUESTED_EUTRAN_AUTHENTICATION_INFO: u32 = 1408;
pub const NUMBER_OF_REQUESTED_VECTORS: u32 = 1410;
pub const RE_SYNCHRONIZATION_INFO: u32 = 1411;
pub const IMMEDIATE_RESPONSE_PREFERRED: u32 = 1412;
pub const AUTHENTICATION_INFO: u32 = 1413;
pub const E_UTRAN_VECTOR: u32 = 1414;
pub const CANCELLATION_TYPE: u32 = 1420;
pub const EQUIPMENT_STATUS: u32 = 1445;
pub const RAND: u32 = 1447;
pub const XRES: u32 = 1448;
pub const AUTN: u32 = 1449;
pub const KASME: u32 = 1450;
pub const MEID_3GPP2: u32 = 1471;
pub const PUR_FLAGS: u32 = 1635;

// TS 32.299 VCS-Information (TS 32.276 voice call charging), vendor 10415.
pub const BEARER_SERVICE: u32 = 854;
pub const PS_FREE_FORMAT_DATA: u32 = 866;
pub const START_TIME: u32 = 2041;
pub const STOP_TIME: u32 = 2042;
pub const VCS_INFORMATION: u32 = 3410;
pub const BASIC_SERVICE_CODE: u32 = 3411;
pub const BEARER_CAPABILITY: u32 = 3412;
pub const TELESERVICE: u32 = 3413;
pub const ISUP_LOCATION_NUMBER: u32 = 3414;
pub const FORWARDING_PENDING: u32 = 3415;
pub const ISUP_CAUSE: u32 = 3416;
pub const MSC_ADDRESS: u32 = 3417;
pub const NETWORK_CALL_REFERENCE_NUMBER: u32 = 3418;
pub const START_OF_CHARGING: u32 = 3419;
pub const VLR_NUMBER: u32 = 3420;
pub const ISUP_CAUSE_DIAGNOSTICS: u32 = 3422;
pub const ISUP_CAUSE_LOCATION: u32 = 3423;
pub const ISUP_CAUSE_VALUE: u32 = 3424;
