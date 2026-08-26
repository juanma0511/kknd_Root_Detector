package com.juanma0511.rootdetector.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.juanma0511.rootdetector.R
import com.juanma0511.rootdetector.model.DetectionItem
import com.juanma0511.rootdetector.model.HwCheckItem

private val detectorTitleResources = mapOf(
    "su_binary" to R.string.det_title_su_binary,
    "root_apps" to R.string.det_title_root_apps,
    "patched_apps" to R.string.det_title_patched_apps,
    "lsposed_companions" to R.string.det_title_lsposed_companions,
    "medium_risk_tools" to R.string.det_title_medium_risk_tools,
    "warning_apps" to R.string.det_title_warning_apps,
    "build_tags" to R.string.det_title_build_tags,
    "dangerous_props" to R.string.det_title_dangerous_props,
    "root_binaries" to R.string.det_title_root_binaries,
    "rw_paths" to R.string.det_title_rw_paths,
    "magisk_files" to R.string.det_title_magisk_files,
    "frida" to R.string.det_title_frida,
    "emulator" to R.string.det_title_emulator,
    "mount_rw" to R.string.det_title_mount_rw,
    "test_keys" to R.string.det_title_test_keys,
    "native_lib_maps" to R.string.det_title_native_lib_maps,
    "magisk_tmpfs" to R.string.det_title_magisk_tmpfs,
    "kernelsu" to R.string.det_title_kernelsu,
    "zygisk_modules" to R.string.det_title_zygisk_modules,
    "su_in_path" to R.string.det_title_su_in_path,
    "selinux" to R.string.det_title_selinux,
    "pm_anomalies" to R.string.det_title_pm_anomalies,
    "mount_namespace" to R.string.det_title_mount_namespace,
    "overlayfs_system" to R.string.det_title_overlayfs_system,
    "zygisk_runtime" to R.string.det_title_zygisk_runtime,
    "tee_available" to R.string.det_title_tee_available,
    "keystore_backing" to R.string.det_title_keystore_backing,
    "strongbox_feature" to R.string.det_title_strongbox_feature,
    "strongbox_key" to R.string.det_title_strongbox_key,
    "verified_boot_state" to R.string.det_title_verified_boot_state,
    "verified_boot_key" to R.string.det_title_verified_boot_key,
    "bootloader_state" to R.string.det_title_bootloader_state,
    "dm_verity" to R.string.det_title_dm_verity,
    "vbmeta_digest" to R.string.det_title_vbmeta_digest,
    "avb_version" to R.string.det_title_avb_version,
    "encryption" to R.string.det_title_encryption,
    "security_patch" to R.string.det_title_security_patch,
    "sig_missing" to R.string.det_title_sig_missing,
    "apk_sig" to R.string.det_title_apk_sig,
    "apk_sig_mismatch" to R.string.det_title_apk_sig_mismatch,
    "apk_sig_error" to R.string.det_title_apk_sig_error,
    "classloader_hook" to R.string.det_title_classloader_hook,
    "classloader_path" to R.string.det_title_classloader_path,
    "classloader_ok" to R.string.det_title_classloader_ok,
    "apk_missing" to R.string.det_title_apk_missing,
    "apk_size" to R.string.det_title_apk_size,
    "apk_size_changed" to R.string.det_title_apk_size_changed,
    "apk_size_ok" to R.string.det_title_apk_size_ok,
    "apk_size_error" to R.string.det_title_apk_size_error,
    "user_ca_kt" to R.string.det_title_user_ca_kt,
    "user_ca_ok" to R.string.det_title_user_ca_ok,
    "user_ca_error" to R.string.det_title_user_ca_error,
    "attest_chain_tee" to R.string.det_title_attest_chain_tee,
    "attest_chain_sb" to R.string.det_title_attest_chain_sb,
    "attest_root_trust" to R.string.det_title_attest_root_trust,
    "lineage_services" to R.string.det_title_lineage_services,
    "lineage_permissions" to R.string.det_title_lineage_permissions,
    "lineage_files" to R.string.det_title_lineage_init,
    "lineage_sepolicy" to R.string.det_title_lineage_sepolicy,
    "custom_rom" to R.string.det_title_custom_rom,
    "kernel_cmdline" to R.string.det_title_kernel_cmdline,
    "env_hooks" to R.string.det_title_env_hooks,
    "dev_sockets" to R.string.det_title_dev_sockets,
    "zygote_injection" to R.string.det_title_zygote_injection,
    "overlayfs" to R.string.det_title_overlayfs,
    "zygote_fd" to R.string.det_title_zygote_fd,
    "process_caps" to R.string.det_title_process_caps,
    "kernel_patch_window" to R.string.det_title_kernel_patch_window,
    "kernel_newer_than_system" to R.string.det_title_kernel_newer_than_system,
    "boot_state" to R.string.det_title_boot_state,
    "suspicious_mount" to R.string.det_title_suspicious_mount,
    "mountinfo_consistency" to R.string.det_title_mount_info_consistency,
    "binder_services" to R.string.det_title_binder_services,
    "env_scan" to R.string.det_title_env_scan,
    "init_rc_root" to R.string.det_title_init_rc,
    "root_sepolicy" to R.string.det_title_root_sepolicy,
    "memfd_injection" to R.string.det_title_memfd_maps,
    "prop_consistency" to R.string.det_title_property_consistency,
    "build_field_coherence" to R.string.det_title_build_coherence,
    "hide_bypass_modules" to R.string.det_title_hide_bypass,
    "hidden_modules" to R.string.det_title_hidden_modules,
    "hardcoded_framework_sweep" to R.string.det_title_framework_sweep,
    "tmpfs_data" to R.string.det_title_tmpfs_data,
    "su_timestamps" to R.string.det_title_su_timestamps,
    "ld_preload" to R.string.det_title_ld_preload,
    "seccomp_mode" to R.string.det_title_seccomp,
    "tracer_pid" to R.string.det_title_tracer_pid,
    "susfs" to R.string.det_title_susfs,
    "soter_check" to R.string.det_title_soter,
    "xposed_framework" to R.string.det_title_xposed,
    "adb_network" to R.string.det_title_adb_network,
    "developer_options" to R.string.det_title_developer_options,
    "su_directory" to R.string.det_title_su_directory,
    "sdcard_artifacts" to R.string.det_title_external_storage,
    "recovery_artifacts" to R.string.det_title_recovery,
    "init_dotd" to R.string.det_title_init_d,
    "data_local_tmp" to R.string.det_title_data_local_tmp,
    "ksu_temp_root_intent" to R.string.det_title_ksu_temp_root,
    "resetprop_modifications" to R.string.det_title_resetprop,
    "app_zygote_sepolicy" to R.string.det_title_app_zygote_sepolicy,
    "context_validity_oracle" to R.string.det_title_context_validity_oracle,
    "scene_debugfs" to R.string.det_title_scene_debugfs,
    "neozygisk_env" to R.string.det_title_neozygisk_env,
    "skroot" to R.string.det_title_skroot,
    "selinux_seqno" to R.string.det_title_selinux_seqno,
    "install_source" to R.string.det_title_install_source
)

private val detectorDescriptionResources = mapOf(
    "su_binary" to R.string.det_desc_su_binary,
    "root_apps" to R.string.det_desc_root_apps,
    "dangerous_props" to R.string.det_desc_dangerous_props,
    "tee_available" to R.string.det_desc_tee_available,
    "verified_boot_state" to R.string.det_desc_verified_boot_state,
    "apk_sig" to R.string.det_desc_apk_sig,
    "keystore_backing" to R.string.det_desc_keystore_backing,
    "strongbox_feature" to R.string.det_desc_strongbox_feature,
    "strongbox_key" to R.string.det_desc_strongbox_key,
    "verified_boot_key" to R.string.det_desc_verified_boot_key,
    "bootloader_state" to R.string.det_desc_bootloader_state,
    "dm_verity" to R.string.det_desc_dm_verity,
    "encryption" to R.string.det_desc_encryption,
    "security_patch" to R.string.det_desc_security_patch,
    "attest_chain_tee" to R.string.det_desc_attestation,
    "attest_chain_sb" to R.string.det_desc_attestation,
    "attest_root_trust" to R.string.det_desc_attestation
)

@Composable
fun localizedDetectorTitle(item: DetectionItem): String =
    detectorTitleResources[item.id]?.let { stringResource(it) } ?: item.name

@Composable
fun localizedDetectorDescription(item: DetectionItem): String =
    detectorDescriptionResources[item.id]?.let { stringResource(it) } ?: item.description

@Composable
fun localizedHardwareTitle(item: HwCheckItem): String =
    detectorTitleResources[item.id]?.let { stringResource(it) } ?: item.name

@Composable
fun localizedHardwareDescription(item: HwCheckItem): String =
    detectorDescriptionResources[item.id]?.let { stringResource(it) } ?: item.description