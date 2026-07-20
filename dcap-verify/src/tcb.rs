use crate::TcbStanding;
use crate::error::{ErrorCategory, VerifyError};
use crate::pki::PckPlatformTcb;
use crate::types::qe_identity::QeIdentity;
use crate::types::report::SgxReportBody;
use crate::types::tcb_info::{TcbInfo, TcbLevel};

pub(crate) fn platform_standing(
    info: &TcbInfo,
    pck: &PckPlatformTcb,
) -> Result<TcbStanding, VerifyError> {
    let fmspc = decode_hex_field("TCB info fmspc", &info.fmspc)?;
    if fmspc != pck.fmspc {
        return Err(VerifyError::new(
            ErrorCategory::TcbLevelUnsupported,
            format!(
                "TCB info describes platform family {}, the quote's PCK certificate belongs to {}",
                info.fmspc,
                hex::encode(pck.fmspc)
            ),
        ));
    }
    let pce_id = decode_hex_field("TCB info pceId", &info.pce_id)?;
    if pce_id != pck.pce_id {
        return Err(VerifyError::new(
            ErrorCategory::TcbLevelUnsupported,
            format!(
                "TCB info describes PCE {}, the quote's PCK certificate belongs to PCE {}",
                info.pce_id,
                hex::encode(pck.pce_id)
            ),
        ));
    }

    // Match Intel's QVL exactly — iterate tcbLevels in document
    // order and take the FIRST level the platform satisfies. Intel emits the array
    // most-recent-first; the first satisfied entry is that level. Do NOT reorder or
    // pick a derived maximum: levels are not always totally ordered, and any
    // reordering can diverge from Intel.
    let selected = info
        .tcb_levels
        .iter()
        .find(|level| level_satisfied(level, pck));

    let Some(selected) = selected else {
        return Err(VerifyError::new(
            ErrorCategory::TcbLevelUnsupported,
            format!(
                "platform TCB (components {:?}, pcesvn {}) meets none of the {} levels in the TCB info",
                pck.comp_svns,
                pck.pcesvn,
                info.tcb_levels.len()
            ),
        ));
    };

    match selected.tcb_status.as_str() {
        "UpToDate" => Ok(TcbStanding::UpToDate),
        "SWHardeningNeeded" => Ok(TcbStanding::SWHardeningNeeded {
            advisory_ids: selected.advisory_ids.clone(),
        }),
        // Accepted, but surfaced as its own distinct status (not collapsed into
        // SWHardeningNeeded) so a caller can choose to reject/alert on it.
        "ConfigurationAndSWHardeningNeeded" => Ok(TcbStanding::ConfigurationAndSWHardeningNeeded {
            advisory_ids: selected.advisory_ids.clone(),
        }),
        other => Err(VerifyError::new(
            ErrorCategory::TcbLevelUnsupported,
            format!("the platform's TCB level carries status '{other}', which is not accepted"),
        )),
    }
}

fn level_satisfied(level: &TcbLevel, pck: &PckPlatformTcb) -> bool {
    level.tcb.sgxtcbcomponents.len() == 16
        && level
            .tcb
            .sgxtcbcomponents
            .iter()
            .zip(pck.comp_svns.iter())
            .all(|(component, platform)| *platform >= component.svn)
        && pck.pcesvn >= level.tcb.pcesvn
}

pub(crate) fn check_qe_identity(
    identity: &QeIdentity,
    qe_report: &SgxReportBody,
) -> Result<(), VerifyError> {
    if identity.id != "QE" {
        return Err(VerifyError::new(
            ErrorCategory::QeIdentityMismatch,
            format!(
                "identity document describes enclave '{}', expected the SGX QE",
                identity.id
            ),
        ));
    }

    let mrsigner = decode_hex_field("QE identity mrsigner", &identity.mrsigner)?;
    if mrsigner != qe_report.mrsigner {
        return Err(VerifyError::new(
            ErrorCategory::QeIdentityMismatch,
            format!(
                "QE report is signed by {}, identity requires {}",
                hex::encode(qe_report.mrsigner),
                identity.mrsigner
            ),
        ));
    }

    if identity.isvprodid != qe_report.isv_prod_id {
        return Err(VerifyError::new(
            ErrorCategory::QeIdentityMismatch,
            format!(
                "QE report carries product id {}, identity requires {}",
                qe_report.isv_prod_id, identity.isvprodid
            ),
        ));
    }

    let miscselect: [u8; 4] = decode_hex_field("QE identity miscselect", &identity.miscselect)?;
    let miscselect_mask: [u8; 4] =
        decode_hex_field("QE identity miscselectMask", &identity.miscselect_mask)?;
    if !masked_eq(&qe_report.misc_select, &miscselect, &miscselect_mask) {
        return Err(VerifyError::new(
            ErrorCategory::QeIdentityMismatch,
            format!(
                "QE report miscselect {} does not match identity value {} under mask {}",
                hex::encode(qe_report.misc_select),
                identity.miscselect,
                identity.miscselect_mask
            ),
        ));
    }

    let attributes: [u8; 16] = decode_hex_field("QE identity attributes", &identity.attributes)?;
    let attributes_mask: [u8; 16] =
        decode_hex_field("QE identity attributesMask", &identity.attributes_mask)?;
    if !masked_eq(&qe_report.attributes, &attributes, &attributes_mask) {
        return Err(VerifyError::new(
            ErrorCategory::QeIdentityMismatch,
            format!(
                "QE report attributes {} do not match identity value {} under mask {}",
                hex::encode(qe_report.attributes),
                identity.attributes,
                identity.attributes_mask
            ),
        ));
    }

    let level = identity
        .tcb_levels
        .iter()
        .filter(|l| l.tcb.isvsvn <= qe_report.isv_svn)
        .max_by_key(|l| l.tcb.isvsvn);
    match level {
        Some(l) if l.tcb_status == "UpToDate" => Ok(()),
        Some(l) => Err(VerifyError::new(
            ErrorCategory::QeIdentityMismatch,
            format!(
                "QE at isvsvn {} sits at TCB status '{}' (level isvsvn {}), which is not current",
                qe_report.isv_svn, l.tcb_status, l.tcb.isvsvn
            ),
        )),
        None => Err(VerifyError::new(
            ErrorCategory::QeIdentityMismatch,
            format!(
                "QE isvsvn {} is below every TCB level in the identity document",
                qe_report.isv_svn
            ),
        )),
    }
}

fn masked_eq<const N: usize>(actual: &[u8; N], expected: &[u8; N], mask: &[u8; N]) -> bool {
    actual
        .iter()
        .zip(expected)
        .zip(mask)
        .all(|((a, e), m)| a & m == e & m)
}

fn decode_hex_field<const N: usize>(what: &str, value: &str) -> Result<[u8; N], VerifyError> {
    let bytes = hex::decode(value).map_err(|e| {
        VerifyError::new(
            ErrorCategory::CollateralParse,
            format!("{what} is not valid hex ('{value}'): {e}"),
        )
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        VerifyError::new(
            ErrorCategory::CollateralParse,
            format!(
                "{what} must be {N} bytes, got {} ('{value}')",
                value.len() / 2
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::qe_identity::{QeTcb, QeTcbLevel};
    use crate::types::tcb_info::{TcbComponent, TcbPlatform};
    use chrono::{DateTime, Utc};

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
    }

    // Three platform-TCB profiles forming a strict chain, both componentwise and
    // lexicographically: LO < MID < HI.
    const LO: [u32; 16] = [1; 16];
    const MID: [u32; 16] = [5; 16];
    const HI: [u32; 16] = [10; 16];

    fn level(comps: [u32; 16], pcesvn: u32, status: &str, advisories: &[&str]) -> TcbLevel {
        TcbLevel {
            tcb: TcbPlatform {
                sgxtcbcomponents: comps.iter().map(|&svn| TcbComponent { svn }).collect(),
                pcesvn,
            },
            tcb_date: ts(0),
            tcb_status: status.to_string(),
            advisory_ids: advisories.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn info(levels: Vec<TcbLevel>) -> TcbInfo {
        TcbInfo {
            id: "SGX".to_string(),
            version: 3,
            issue_date: ts(0),
            next_update: ts(1),
            fmspc: "00a067110000".to_string(),
            pce_id: "0000".to_string(),
            tcb_type: 0,
            tcb_evaluation_data_number: 1,
            tcb_levels: levels,
        }
    }

    fn platform(comp_svns: [u32; 16], pcesvn: u32) -> PckPlatformTcb {
        PckPlatformTcb {
            fmspc: [0x00, 0xa0, 0x67, 0x11, 0x00, 0x00],
            pce_id: [0x00, 0x00],
            comp_svns,
            pcesvn,
        }
    }

    fn sw(ids: &[&str]) -> TcbStanding {
        TcbStanding::SWHardeningNeeded {
            advisory_ids: ids.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn config_sw(ids: &[&str]) -> TcbStanding {
        TcbStanding::ConfigurationAndSWHardeningNeeded {
            advisory_ids: ids.iter().map(|s| s.to_string()).collect(),
        }
    }

    // Matching Intel's QVL: iterate in DOCUMENT ORDER and take the first
    // satisfied level. This is the anti-"maximum" test — the array is deliberately
    // NOT descending, and the platform satisfies BOTH a rejected level listed first
    // and an accepted level listed later. Document-order-first must pick the first
    // (→ reject); a max/most-recent picker would wrongly pick the accepted one.
    #[test]
    fn selection_is_document_order_first_not_maximum() {
        let plat = platform([20; 16], 20); // satisfies every level below
        let reject_first = info(vec![
            level(LO, 1, "OutOfDate", &["SA-LO"]),
            level(HI, 10, "UpToDate", &[]),
        ]);
        let err = platform_standing(&reject_first, &plat).unwrap_err();
        assert_eq!(
            err.category,
            ErrorCategory::TcbLevelUnsupported,
            "first satisfied level in document order is OutOfDate → must reject"
        );

        // Same two levels, accepted one listed first → accept. Confirms the outcome
        // is driven by position, not by which status is "better".
        let accept_first = info(vec![
            level(HI, 10, "UpToDate", &[]),
            level(LO, 1, "OutOfDate", &["SA-LO"]),
        ]);
        assert_eq!(
            platform_standing(&accept_first, &plat).unwrap(),
            TcbStanding::UpToDate
        );
    }

    // The first satisfied level in document order governs, and its own status and
    // advisory IDs are surfaced — not a neighbor's. Here the platform does not clear
    // the first-listed level, so the second (satisfied) one is selected.
    #[test]
    fn first_satisfied_level_supplies_status_and_advisories() {
        let plat = platform([7; 16], 7); // >= MID and LO, below HI
        let tcb = info(vec![
            level(HI, 10, "UpToDate", &["SA-HI"]),
            level(MID, 5, "SWHardeningNeeded", &["SA-MID-1", "SA-MID-2"]),
            level(LO, 1, "OutOfDate", &["SA-LO"]),
        ]);
        assert_eq!(
            platform_standing(&tcb, &plat).unwrap(),
            sw(&["SA-MID-1", "SA-MID-2"])
        );
    }

    // pcesvn gates satisfaction independently of the components: a platform below a
    // level's pcesvn does not satisfy it and falls through to the next.
    #[test]
    fn pcesvn_gates_level_satisfaction() {
        let comps = [5; 16];
        let tcb = info(vec![
            level(comps, 8, "UpToDate", &[]),
            level(comps, 5, "SWHardeningNeeded", &["SA-LOWPCE"]),
        ]);
        assert_eq!(
            platform_standing(&tcb, &platform(comps, 8)).unwrap(),
            TcbStanding::UpToDate
        );
        assert_eq!(
            platform_standing(&tcb, &platform(comps, 7)).unwrap(),
            sw(&["SA-LOWPCE"])
        );
    }

    // A platform below every level is rejected as an unsupported TCB.
    #[test]
    fn platform_below_every_level_is_unsupported() {
        let tcb = info(vec![
            level(LO, 1, "UpToDate", &[]),
            level(MID, 5, "UpToDate", &[]),
        ]);
        let err = platform_standing(&tcb, &platform([0; 16], 0)).unwrap_err();
        assert_eq!(err.category, ErrorCategory::TcbLevelUnsupported);
    }

    // The first satisfied level's status governs: an unaccepted status rejects even
    // though a later (also satisfied) level is UpToDate.
    #[test]
    fn first_satisfied_unaccepted_status_rejects_despite_later_uptodate() {
        let tcb = info(vec![
            level(MID, 5, "OutOfDate", &["SA-MID"]),
            level(LO, 1, "UpToDate", &[]),
        ]);
        let err = platform_standing(&tcb, &platform([5; 16], 5)).unwrap_err();
        assert_eq!(err.category, ErrorCategory::TcbLevelUnsupported);
    }

    // ConfigurationAndSWHardeningNeeded is accepted, kept as its own distinct status
    // (not collapsed into SWHardeningNeeded), with advisory IDs surfaced.
    #[test]
    fn config_and_sw_hardening_is_accepted_with_distinct_status() {
        let tcb = info(vec![level(
            MID,
            5,
            "ConfigurationAndSWHardeningNeeded",
            &["SA-1", "SA-2"],
        )]);
        let standing = platform_standing(&tcb, &platform([5; 16], 5)).unwrap();
        assert_eq!(standing, config_sw(&["SA-1", "SA-2"]));
        // Explicitly distinct from SWHardeningNeeded with the same advisories.
        assert_ne!(standing, sw(&["SA-1", "SA-2"]));
    }

    // ConfigurationNeeded (config only, no SW hardening) is NOT an accepted status.
    #[test]
    fn configuration_needed_is_rejected() {
        let tcb = info(vec![level(MID, 5, "ConfigurationNeeded", &["SA-CFG"])]);
        let err = platform_standing(&tcb, &platform([5; 16], 5)).unwrap_err();
        assert_eq!(err.category, ErrorCategory::TcbLevelUnsupported);
    }

    // A TCB info describing a different platform family than the PCK certificate is rejected.
    #[test]
    fn fmspc_mismatch_is_rejected() {
        let plat = PckPlatformTcb {
            fmspc: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            pce_id: [0x00, 0x00],
            comp_svns: [5; 16],
            pcesvn: 5,
        };
        let tcb = info(vec![level(MID, 5, "UpToDate", &[])]);
        let err = platform_standing(&tcb, &plat).unwrap_err();
        assert_eq!(err.category, ErrorCategory::TcbLevelUnsupported);
    }

    // A TCB info for the right family but a different PCE is rejected.
    #[test]
    fn pceid_mismatch_is_rejected() {
        let mut plat = platform(MID, 5);
        plat.pce_id = [0x01, 0x00];
        let tcb = info(vec![level(MID, 5, "UpToDate", &[])]);
        let err = platform_standing(&tcb, &plat).unwrap_err();
        assert_eq!(err.category, ErrorCategory::TcbLevelUnsupported);
        assert!(err.detail.contains("PCE"), "{}", err.detail);
    }

    // A report body whose non-isvsvn fields all match a minimal QE identity, so QE tests
    // exercise only the isvsvn level selection.
    fn qe_report(isv_svn: u16) -> SgxReportBody {
        SgxReportBody {
            cpu_svn: [0; 16],
            misc_select: [0; 4],
            isv_ext_prod_id: [0; 16],
            attributes: [0; 16],
            mrenclave: [0; 32],
            mrsigner: [0x11; 32],
            config_id: [0; 64],
            isv_prod_id: 1,
            isv_svn,
            config_svn: 0,
            isv_family_id: [0; 16],
            sgx_report_data_bytes: [0; 64],
        }
    }

    fn qe_level(isvsvn: u16, status: &str) -> QeTcbLevel {
        QeTcbLevel {
            tcb: QeTcb { isvsvn },
            tcb_date: ts(0),
            tcb_status: status.to_string(),
            advisory_ids: vec![],
        }
    }

    fn qe_identity(levels: Vec<QeTcbLevel>) -> QeIdentity {
        QeIdentity {
            id: "QE".to_string(),
            version: 2,
            issue_date: ts(0),
            next_update: ts(1),
            tcb_evaluation_data_number: 1,
            miscselect: "00000000".to_string(),
            // Zero masks make the miscselect/attributes comparisons vacuously pass so the
            // tests isolate the isvsvn level selection.
            miscselect_mask: "00000000".to_string(),
            attributes: "00000000000000000000000000000000".to_string(),
            attributes_mask: "00000000000000000000000000000000".to_string(),
            mrsigner: "11".repeat(32),
            isvprodid: 1,
            tcb_levels: levels,
        }
    }

    // QE identity isvsvn selection picks the highest level with isvsvn <= the report's,
    // independent of array order; an UpToDate top level accepts.
    #[test]
    fn qe_identity_selects_highest_satisfied_isvsvn_level() {
        let identity = qe_identity(vec![
            qe_level(6, "OutOfDate"),
            qe_level(8, "UpToDate"),
            qe_level(2, "OutOfDate"),
        ]);
        assert!(check_qe_identity(&identity, &qe_report(8)).is_ok());
        assert!(check_qe_identity(&identity, &qe_report(10)).is_ok());
    }

    // A report between levels lands on the highest one it clears (isvsvn 6, OutOfDate) and
    // is rejected — not silently promoted to the neighbouring UpToDate level 8.
    #[test]
    fn qe_identity_middle_isvsvn_lands_on_its_level_and_rejects() {
        let identity = qe_identity(vec![
            qe_level(8, "UpToDate"),
            qe_level(6, "OutOfDate"),
            qe_level(2, "OutOfDate"),
        ]);
        let err = check_qe_identity(&identity, &qe_report(7)).unwrap_err();
        assert_eq!(err.category, ErrorCategory::QeIdentityMismatch);
    }

    // A report below every QE level is rejected.
    #[test]
    fn qe_identity_isvsvn_below_all_levels_rejects() {
        let identity = qe_identity(vec![qe_level(2, "UpToDate"), qe_level(8, "UpToDate")]);
        let err = check_qe_identity(&identity, &qe_report(1)).unwrap_err();
        assert_eq!(err.category, ErrorCategory::QeIdentityMismatch);
    }

    #[test]
    fn qe_identity_mrsigner_mismatch_rejects() {
        let mut identity = qe_identity(vec![qe_level(1, "UpToDate")]);
        identity.mrsigner = "22".repeat(32);
        let err = check_qe_identity(&identity, &qe_report(1)).unwrap_err();
        assert_eq!(err.category, ErrorCategory::QeIdentityMismatch);
        assert!(err.detail.contains("signed by"), "{}", err.detail);
    }

    #[test]
    fn qe_identity_isvprodid_mismatch_rejects() {
        let mut identity = qe_identity(vec![qe_level(1, "UpToDate")]);
        identity.isvprodid = 2;
        let err = check_qe_identity(&identity, &qe_report(1)).unwrap_err();
        assert_eq!(err.category, ErrorCategory::QeIdentityMismatch);
        assert!(err.detail.contains("product id"), "{}", err.detail);
    }

    // The miscselect/attributes comparisons are masked, and the qe_identity() helper's
    // zero masks make them vacuous — so these tests set a real mask, and each reject
    // arm has a twin proving the same difference outside the mask is ignored.
    #[test]
    fn qe_identity_miscselect_mismatch_inside_mask_rejects() {
        let mut identity = qe_identity(vec![qe_level(1, "UpToDate")]);
        identity.miscselect = "000000ff".to_string();
        identity.miscselect_mask = "000000ff".to_string();
        let err = check_qe_identity(&identity, &qe_report(1)).unwrap_err();
        assert_eq!(err.category, ErrorCategory::QeIdentityMismatch);
        assert!(err.detail.contains("miscselect"), "{}", err.detail);
    }

    #[test]
    fn qe_identity_miscselect_difference_outside_mask_passes() {
        let mut identity = qe_identity(vec![qe_level(1, "UpToDate")]);
        identity.miscselect = "000000ff".to_string();
        identity.miscselect_mask = "ffffff00".to_string();
        assert!(check_qe_identity(&identity, &qe_report(1)).is_ok());
    }

    #[test]
    fn qe_identity_attributes_mismatch_inside_mask_rejects() {
        let mut identity = qe_identity(vec![qe_level(1, "UpToDate")]);
        identity.attributes = format!("{}ff", "00".repeat(15));
        identity.attributes_mask = format!("{}ff", "00".repeat(15));
        let err = check_qe_identity(&identity, &qe_report(1)).unwrap_err();
        assert_eq!(err.category, ErrorCategory::QeIdentityMismatch);
        assert!(err.detail.contains("attributes"), "{}", err.detail);
    }

    #[test]
    fn qe_identity_attributes_difference_outside_mask_passes() {
        let mut identity = qe_identity(vec![qe_level(1, "UpToDate")]);
        identity.attributes = format!("{}ff", "00".repeat(15));
        identity.attributes_mask = format!("ff{}", "00".repeat(15));
        assert!(check_qe_identity(&identity, &qe_report(1)).is_ok());
    }
}
