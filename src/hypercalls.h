/* Hypercalls.
 *
 * Pasted from arch/arm64/include/asm/kvm_asm.h in the Linux sources.
 * Keep in sync with the OCaml type defn.
 */

/* PASTE -> */

#define __KVM_HOST_SMCCC_FUNC___kvm_hyp_init			0

enum __kvm_host_smccc_func {
	/* Hypercalls available only prior to pKVM finalisation */
	/* __KVM_HOST_SMCCC_FUNC___kvm_hyp_init */
	__KVM_HOST_SMCCC_FUNC___kvm_get_mdcr_el2 = __KVM_HOST_SMCCC_FUNC___kvm_hyp_init + 1,
	__KVM_HOST_SMCCC_FUNC___pkvm_init,
	__KVM_HOST_SMCCC_FUNC___pkvm_create_private_mapping,
	__KVM_HOST_SMCCC_FUNC___pkvm_cpu_set_vector,
	__KVM_HOST_SMCCC_FUNC___kvm_enable_ssbs,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_init_lrs,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_get_gic_config,
	__KVM_HOST_SMCCC_FUNC___kvm_flush_vm_context,
	__KVM_HOST_SMCCC_FUNC___kvm_tlb_flush_vmid_ipa,
	__KVM_HOST_SMCCC_FUNC___kvm_tlb_flush_vmid_ipa_nsh,
	__KVM_HOST_SMCCC_FUNC___kvm_tlb_flush_vmid,
	__KVM_HOST_SMCCC_FUNC___kvm_tlb_flush_vmid_range,
	__KVM_HOST_SMCCC_FUNC___kvm_flush_cpu_context,
	__KVM_HOST_SMCCC_FUNC___pkvm_alloc_module_va,
	__KVM_HOST_SMCCC_FUNC___pkvm_map_module_page,
	__KVM_HOST_SMCCC_FUNC___pkvm_unmap_module_page,
	__KVM_HOST_SMCCC_FUNC___pkvm_init_module,
	__KVM_HOST_SMCCC_FUNC___pkvm_register_hcall,
	__KVM_HOST_SMCCC_FUNC___pkvm_iommu_init,
	__KVM_HOST_SMCCC_FUNC___pkvm_prot_finalize,

	/* Hypercalls available after pKVM finalisation */
	__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_map_guest,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_unmap_guest,
	__KVM_HOST_SMCCC_FUNC___pkvm_relax_perms,
	__KVM_HOST_SMCCC_FUNC___pkvm_wrprotect,
	__KVM_HOST_SMCCC_FUNC___pkvm_dirty_log,
	__KVM_HOST_SMCCC_FUNC___pkvm_tlb_flush_vmid,
	__KVM_HOST_SMCCC_FUNC___kvm_adjust_pc,
	__KVM_HOST_SMCCC_FUNC___kvm_vcpu_run,
	__KVM_HOST_SMCCC_FUNC___kvm_timer_set_cntvoff,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_save_vmcr_aprs,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_restore_vmcr_aprs,
	__KVM_HOST_SMCCC_FUNC___pkvm_init_vm,
	__KVM_HOST_SMCCC_FUNC___pkvm_init_vcpu,
	__KVM_HOST_SMCCC_FUNC___pkvm_start_teardown_vm,
	__KVM_HOST_SMCCC_FUNC___pkvm_finalize_teardown_vm,
	__KVM_HOST_SMCCC_FUNC___pkvm_reclaim_dying_guest_page,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_load,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_put,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_sync_state,
	__KVM_HOST_SMCCC_FUNC___pkvm_load_tracing,
	__KVM_HOST_SMCCC_FUNC___pkvm_teardown_tracing,
	__KVM_HOST_SMCCC_FUNC___pkvm_enable_tracing,
	__KVM_HOST_SMCCC_FUNC___pkvm_swap_reader_tracing,
	__KVM_HOST_SMCCC_FUNC___pkvm_enable_event,
	__KVM_HOST_SMCCC_FUNC___pkvm_hyp_alloc_mgt_refill,
	__KVM_HOST_SMCCC_FUNC___pkvm_hyp_alloc_mgt_reclaimable,
	__KVM_HOST_SMCCC_FUNC___pkvm_hyp_alloc_mgt_reclaim,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_iommu_alloc_domain,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_iommu_free_domain,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_iommu_attach_dev,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_iommu_detach_dev,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_iommu_map_pages,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_iommu_unmap_pages,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_iommu_iova_to_phys,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_hvc_pd,
	__KVM_HOST_SMCCC_FUNC___pkvm_stage2_snapshot,

	/*
	 * Start of the dynamically registered hypercalls. Start a bit
	 * further, just in case some modules...
	 */
	__KVM_HOST_SMCCC_FUNC___dynamic_hcalls = 128,
};

/* <- PASTE */


/* Once again, with reflection.
 *
 * Can be a subset, but we need all the hypercallable hypercalls.
 */

#define CALL(x) { .k = #x, .v = __KVM_HOST_SMCCC_FUNC___ ## x }

struct __kv { const char *k; int v; };

static struct __kv smccc_func_numbers[] = {
	CALL(pkvm_host_share_hyp),
	CALL(pkvm_host_unshare_hyp),
	CALL(pkvm_host_map_guest),
	CALL(pkvm_host_unmap_guest),
	// CALL(pkvm_relax_perms),
	// CALL(pkvm_wrprotect),
	// CALL(pkvm_dirty_log),
	// CALL(pkvm_tlb_flush_vmid),
	CALL(kvm_adjust_pc),
	CALL(kvm_vcpu_run),
	CALL(kvm_timer_set_cntvoff),
	CALL(vgic_v3_save_vmcr_aprs),
	CALL(vgic_v3_restore_vmcr_aprs),
	CALL(pkvm_init_vm),
	CALL(pkvm_init_vcpu),
	CALL(pkvm_start_teardown_vm),
	CALL(pkvm_finalize_teardown_vm),
	CALL(pkvm_reclaim_dying_guest_page),
	CALL(pkvm_vcpu_load),
	CALL(pkvm_vcpu_put),
	CALL(pkvm_vcpu_sync_state),
	// CALL(pkvm_load_tracing),
	// CALL(pkvm_teardown_tracing),
	// CALL(pkvm_enable_tracing),
	// CALL(pkvm_swap_reader_tracing),
	// CALL(pkvm_enable_event),
	CALL(pkvm_hyp_alloc_mgt_refill),
	CALL(pkvm_hyp_alloc_mgt_reclaimable),
	CALL(pkvm_hyp_alloc_mgt_reclaim),
	// CALL(pkvm_host_iommu_alloc_domain),
	// CALL(pkvm_host_iommu_free_domain),
	// CALL(pkvm_host_iommu_attach_dev),
	// CALL(pkvm_host_iommu_detach_dev),
	// CALL(pkvm_host_iommu_map_pages),
	// CALL(pkvm_host_iommu_unmap_pages),
	// CALL(pkvm_host_iommu_iova_to_phys),
	// CALL(pkvm_host_hvc_pd),
	// CALL(pkvm_stage2_snapshot),
        { .k = 0, .v = -1 }
};
