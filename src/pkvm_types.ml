(* Host hypercalls. `enum __kvm_host_smccc_func`, and their ioctl arguments.
 *
 * Keep in sync with `hypercalls.h`.
 *)
type _ host_smccc_func =

(* Hypercalls available only prior to pKVM finalisation *)
  | Kvm_hyp_init
  | Kvm_get_mdcr_el2
  | Pkvm_init
  | Pkvm_create_private_mapping
  | Pkvm_cpu_set_vector
  | Kvm_enable_ssbs
  | Vgic_v3_init_lrs
  | Vgic_v3_get_gic_config
  | Kvm_flush_vm_context
  | Kvm_tlb_flush_vmid_ipa
  | Kvm_tlb_flush_vmid
  | Kvm_flush_cpu_context
  | Pkvm_prot_finalize

(* Hypercalls available after pKVM finalisation *)
  | Pkvm_host_share_hyp    : int64 -> unit host_smccc_func (* highly unsafe *)
  | Pkvm_host_unshare_hyp  : int64 -> unit host_smccc_func
  (* | Pkvm_host_reclaim_page : int64 -> unit host_smccc_func *)
  | Pkvm_host_map_guest    : int64 * int64 * int64 * int64(*TODO: this is enum__kvm_pgtable_prot it is dodgy to hardcode the size here*) -> unit host_smccc_func
  | Pkvm_host_unmap_guest  : int * int64 * int64 * int64(* TODO: or really int8 ?*) -> unit(*TODO: check*) host_smccc_func
  | Pkvm_relax_perms (* TODO: u64 * u64 * u64(or really int8) * enum__kvm_pgtable_prot *)
  | Pkvm_wrprotect         : int * int64 * int64 * int64(* TODO: or really int8 ?*) -> unit(*TODO: check*) host_smccc_func
  | Pkvm_dirty_log         : int64 * int64 -> unit(*TODO: check*) host_smccc_func
  | Pkvm_tlb_flush_vmid    : int -> unit host_smccc_func
  | Kvm_adjust_pc          : int64 -> unit host_smccc_func
  | Kvm_vcpu_run           : int64 -> int host_smccc_func
  | Kvm_timer_set_cntvoff  : int64 -> unit host_smccc_func
  | Vgic_v3_save_vmcr_aprs
  | Vgic_v3_restore_vmcr_aprs
  | Pkvm_init_vm                  : int64 * int64 -> int host_smccc_func
  | Pkvm_init_vcpu                : int * int64 -> unit host_smccc_func
  | Pkvm_start_teardown_vm        : int -> int host_smccc_func
  | Pkvm_finalize_teardown_vm     : int -> unit(*TODO: check*) host_smccc_func
  | Pkvm_reclaim_dying_guest_page : int * int64 * int64 * int64(* TODO: or really int8 ?*) -> int host_smccc_func
  | Pkvm_vcpu_load                : int * int * int64 -> int host_smccc_func
  | Pkvm_vcpu_put                 : unit host_smccc_func
  | Pkvm_vcpu_sync_state          : unit host_smccc_func
  | Pkvm_load_tracing
  | Pkvm_teardown_tracing
  | Pkvm_enable_tracing
  | Pkvm_swap_reader_tracing
  | Pkvm_enable_event
  | Pkvm_hyp_alloc_mgt_refill      : int64 * int64 * int64 -> int host_smccc_func
  | Pkvm_hyp_alloc_mgt_reclaimable
  | Pkvm_hyp_alloc_mgt_reclaim
  | Pkvm_host_iommu_alloc_domain
  | Pkvm_host_iommu_free_domain
  | Pkvm_host_iommu_attach_dev
  | Pkvm_host_iommu_detach_dev
  | Pkvm_host_iommu_map_pages
  | Pkvm_host_iommu_unmap_pages
  | Pkvm_host_iommu_iova_to_phys
  | Pkvm_host_hvc_pd
  | Pkvm_stage2_snapshot

