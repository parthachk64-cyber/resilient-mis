# Recovery trace

Synthetic, invented data in a disposable directory. Produced by `resilient-mis walkthrough`; nothing here is hard-coded.

## 1_manager_reads_department_report
- **tenant**: tenant-a
- **department**: ops
- **report_total_minor**: `{"USD": 4708687}`
- **expected_from_client_ledger**: `{"USD": 4708687}`
- **order_count**: 8
- **contributing_versions**: `[["PO-000001", 1, 1], ["PO-000002", 1, 2], ["PO-000005", 1, 5], ["PO-000006", 1, 6], ["PO-000007", 1, 7], ["PO-000010", 1, 10], ["PO-000011", 1, 11], ["PO-000012", 1, 12]]`
- **totals_verified_against_committed_txns**: True
- **redacted_allow_decision**: `{"principal": "p-7326e6a0cb20", "tenant": "tenant-a", "operation": "spending_report", "decision": "allow"}`
- **other_tenant_total_minor**: `{"EUR": 1861340}`
- **manager_a_reading_tenant_b**: denied: access denied or record not available

## 2_checkpoint_revoke_update
- **checkpoint**: `{"snapshot_id": "snap-000001-6ead7041", "sequence": 1, "last_txn": 22}`
- **policy_epoch_after_revocation**: 9
- **update_committed**: `{"record": "PO-000001", "version": 2, "txn_id": 23}`
- **analyst_after_revocation**: denied: access denied or record not available
- **manager_read_after_denial_total_minor**: `{"USD": 5092498}`
- **manager_read_matches_ledger**: True

## 3_detector_replay
- **replayed_events**: 9478
- **alert_events**: 336
- **rule_alert_groups**: 4
- **iforest_alert_events**: 169
- **incidents_in_stream**: 8
- **evidence_file**: alert_evidence.jsonl
- **note**: labels were used only to count incidents here, never as detector input

## 4_outage_and_invalid_candidate
- **fault**: store file deleted (disposable fixture)
- **health_during_outage**: `{"ok": false, "reason": "StoreUnavailable"}`
- **invalid_candidate_result**: candidate rejected (bad_signature); active state left untouched
- **active_store_untouched**: True
- **invalid_became_active**: False

## 5_recovery
- **outcome**: restored
- **snapshot_id**: snap-000001-6ead7041
- **journal**: replayed
- **journal_entries_replayed**: 1
- **last_txn_before_fault**: 23
- **last_restored_txn**: 23
- **lost_committed_updates**: 0
- **readiness_checks**: `{"manager_report_correct": true, "revoked_access_still_denied": true, "new_write_commits": true}`
- **ready**: True
- **phases_s**: `{"fault_to_detected_s": 0.0, "detected_to_restore_start_s": 0.062, "manifest_verification_s": 0.031, "decrypt_and_verify_s": 0.25, "journal_replay_s": 0.188, "cutover_s": 0.015, "cutover_to_ready_s": 0.094, "restore_start_to_ready_s": 0.578, "fault_to_ready_s": 0.64}`
- **report_total_minor_after**: `{"USD": 5092498}`
- **report_total_matches_pre_fault**: True
- **revoked_analyst_still_denied**: True
- **operator_validation**: `{"ok": true, "txns": 24, "record_versions": 24, "decrypted": 24, "last_txn_id": 24, "problems": []}`
- **operator_asking_for_report**: denied (a recovery operator validates the restore but receives no business report)
- **what_survived**: `{"business_records": {"txns": 24, "record_versions": 24, "records": 23}, "policy_epoch_unchanged_by_restore": true, "keys_retained": true}`

## 6a_rerun_with_healthy_store
- **outcome**: already_restored
- **notes**: `["active store already contains the restored history; nothing replaced, later writes preserved"]`
- **store_replaced**: False

## 6b_interrupt_then_retry
- **interruption**: interrupted before cutover
- **active_state_untouched_by_interruption**: True
- **retry_outcome**: restored
- **record_counts_before**: `{"txns": 24, "record_versions": 24, "records": 23}`
- **record_counts_after_retry**: `{"txns": 25, "record_versions": 25, "records": 24}`
- **orders_in_store_minus_orders_acknowledged_by_clients**: 0
- **note**: the canary write made by the readiness probe is in the ledger, so 0 means no order was duplicated or invented
- **revoked_analyst**: denied
- **readiness**: `{"manager_report_correct": true, "revoked_access_still_denied": true, "new_write_commits": true}`

## Summary

- **ready**: True
- **downtime_fault_to_ready_s**: 0.64
- **restore_start_to_ready_s**: 0.578
- **lost_committed_updates**: 0
