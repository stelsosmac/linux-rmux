/* SPDX-License-Identifier: MIT */
#ifndef __AMDGPU_PS4_UVD_IRQ_H__
#define __AMDGPU_PS4_UVD_IRQ_H__

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/types.h>

struct amdgpu_device;
struct amdgpu_iv_entry;

#define PS4_UVD_IRQ_SLOTS 3

enum ps4_uvd_irq_first_state {
	PS4_UVD_IRQ_EMPTY,
	PS4_UVD_IRQ_WRITING,
	PS4_UVD_IRQ_READY,
};

struct ps4_uvd_irq_slot {
	atomic64_t arrivals;
	atomic_t wrapped;
	atomic_t first_state;
	/* Immutable after first_state is published READY. CIK initializes these
	 * IV fields; never copy its partly initialized amdgpu_iv_entry wholesale.
	 */
	u32 src_data0;
	u32 ring_id;
	u32 vmid;
	u32 pasid;
	u64 claim_ns;
};

/* GMC_FAULT_TYPES_BEGIN */
#define PS4_UVD_FAULT_VMIDS 16U

/* Raw GMC handler samples; addr remains the unshifted register value. */
struct ps4_uvd_fault_record {
	u32 addr;
	u32 status;
	u32 mc_client;
};

struct ps4_uvd_fault_bucket {
	u64 arrivals;
	bool saturated;
	struct ps4_uvd_fault_record first;
	struct ps4_uvd_fault_record last;
};

struct ps4_uvd_fault_history {
	struct ps4_uvd_fault_bucket total;
	struct ps4_uvd_fault_bucket vmid[PS4_UVD_FAULT_VMIDS];
	/* Literal STATUS == U32_MAX, not proof that a register read failed. */
	struct ps4_uvd_fault_bucket unclassified_status;
};

struct ps4_uvd_fault_snapshot {
	bool active;
	u64 arm_ns;
	struct ps4_uvd_fault_history history;
};
/* GMC_FAULT_TYPES_END */

struct ps4_uvd_irq_observer {
	bool active;
	u64 arm_ns;
	struct ps4_uvd_irq_slot slots[PS4_UVD_IRQ_SLOTS];
	/* GMC_FAULT_FIELDS_BEGIN */
	spinlock_t fault_lock;
	struct ps4_uvd_fault_history fault_history;
	/* GMC_FAULT_FIELDS_END */
};

/* init runs once at device allocation, before IRQ registration. arm is
 * serialized by the existing one-attempt probe gate. Never reset after arm.
 */
void amdgpu_ps4_uvd_irq_init(struct amdgpu_device *adev);
void amdgpu_ps4_uvd_irq_arm(struct amdgpu_device *adev);
void amdgpu_ps4_uvd_irq_observe(struct amdgpu_device *adev,
				const struct amdgpu_iv_entry *entry);
void amdgpu_ps4_uvd_irq_report(struct amdgpu_device *adev);

/* GMC_FAULT_API_BEGIN */
/* The existing arm bounds this history. Initialization is before IRQ setup;
 * there is no clear/reset API. A device reset does not erase observations.
 * Inactive snapshots or saturated buckets cannot qualify an interval.
 * The total covers every observed nonempty handler tuple; exactly one VMID
 * bucket or literal all-ones-status bucket is updated with it. Categories
 * aid diagnosis, not cause attribution; zero is not proof of fault freedom.
 * These functions do not touch GPU registers. No consumer is added here.
 */
void amdgpu_ps4_uvd_irq_record_fault(struct amdgpu_device *adev,
				   u32 addr, u32 status, u32 mc_client);
void amdgpu_ps4_uvd_irq_fault_snapshot(struct amdgpu_device *adev,
				     struct ps4_uvd_fault_snapshot *snapshot);
/* GMC_FAULT_API_END */

#endif
