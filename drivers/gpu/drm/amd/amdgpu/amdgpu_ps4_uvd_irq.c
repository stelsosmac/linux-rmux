// SPDX-License-Identifier: MIT
/* Private PS4 readiness-probe telemetry. Legacy slots observe decoded hardware IH
 * arrivals only: it neither acknowledges a device interrupt nor changes any
 * readiness/guard decision. Default off; no firmware or UVD/GMC register access.
 */
#include <linux/timekeeping.h>

#include "amdgpu.h"
#include "amdgpu_ps4_uvd_irq.h"
#include "ivsrcid/ivsrcid_vislands30.h"
#include "gmc/gmc_7_1_sh_mask.h"

static int ps4_uvd_irq_slot_index(unsigned int src_id)
{
	switch (src_id) {
	case VISLANDS30_IV_SRCID_UVD_SYSTEM_MESSAGE:
		return 0;
	case VISLANDS30_IV_SRCID_GFX_PAGE_INV_FAULT:
		return 1;
	case VISLANDS30_IV_SRCID_GFX_MEM_PROT_FAULT:
		return 2;
	default:
		return -1;
	}
}

void amdgpu_ps4_uvd_irq_init(struct amdgpu_device *adev)
{
	struct ps4_uvd_irq_observer *obs = &adev->ps4_uvd_irq;
	unsigned int i;

	/* Before driver_load_kms and any IRQ hook, never a runtime reset. */
	obs->active = false;
	obs->arm_ns = 0;
	/* GMC_FAULT_INIT_BEGIN */
	spin_lock_init(&obs->fault_lock);
	obs->fault_history = (struct ps4_uvd_fault_history) { };
	/* GMC_FAULT_INIT_END */
	for (i = 0; i < PS4_UVD_IRQ_SLOTS; i++) {
		atomic64_set(&obs->slots[i].arrivals, 0);
		atomic_set(&obs->slots[i].wrapped, 0);
		atomic_set(&obs->slots[i].first_state, PS4_UVD_IRQ_EMPTY);
	}
}

void amdgpu_ps4_uvd_irq_arm(struct amdgpu_device *adev)
{
	struct ps4_uvd_irq_observer *obs = &adev->ps4_uvd_irq;

	if (smp_load_acquire(&obs->active))
		return;
	obs->arm_ns = ktime_get_mono_fast_ns();
	/* Publishes the initialized slots and arm time to IRQ/report readers. */
	smp_store_release(&obs->active, true);
}

void amdgpu_ps4_uvd_irq_observe(struct amdgpu_device *adev,
				const struct amdgpu_iv_entry *entry)
{
	struct ps4_uvd_irq_observer *obs = &adev->ps4_uvd_irq;
	struct ps4_uvd_irq_slot *slot;
	int index;

	if (!smp_load_acquire(&obs->active) ||
	    entry->ih != &adev->irq.ih ||
	    entry->client_id != AMDGPU_IRQ_CLIENTID_LEGACY)
		return;
	index = ps4_uvd_irq_slot_index(entry->src_id);
	if (index < 0)
		return;
	slot = &obs->slots[index];
	/* Unsigned interpretation of atomic64 wrap; flag is sticky. Count and
	 * flag are separate publications, not one coherent report snapshot.
	 */
	if (!(u64)atomic64_inc_return(&slot->arrivals))
		atomic_set(&slot->wrapped, 1);
	if (atomic_cmpxchg(&slot->first_state, PS4_UVD_IRQ_EMPTY,
			   PS4_UVD_IRQ_WRITING) != PS4_UVD_IRQ_EMPTY)
		return;
	/* First claimant, not necessarily the earliest arrival or count 1.
	 * Timestamp is a software sample after claim, not an IH hardware time.
	 */
	slot->claim_ns = ktime_get_mono_fast_ns();
	slot->src_data0 = entry->src_data[0];
	slot->ring_id = entry->ring_id;
	slot->vmid = entry->vmid;
	slot->pasid = entry->pasid;
	atomic_set_release(&slot->first_state, PS4_UVD_IRQ_READY);
}

/* GMC_FAULT_FLOW_BEGIN */
static void ps4_uvd_fault_bucket_record(struct ps4_uvd_fault_bucket *bucket,
				       const struct ps4_uvd_fault_record *record)
{
	/* Caller holds fault_lock. Order is lock acquisition, not hardware time. */
	if (!bucket->arrivals)
		bucket->first = *record;
	bucket->last = *record;
	if (bucket->arrivals != ~0ULL)
		bucket->arrivals++;
	/* Sticky on reaching the limit. An exhausted bucket cannot establish
	 * an unchanged interval, even when its count and last tuple match.
	 */
	if (bucket->arrivals == ~0ULL)
		bucket->saturated = true;
}

/* Called only with the GMC handler's already captured tuple. This records
 * armed handler observations, not all faults or an IH/GMC one-to-one match.
 * A tuple may predate arming through latch, main-IH or soft-IH delay.
 * In particular, an empty snapshot never establishes absence of faults.
 */
void amdgpu_ps4_uvd_irq_record_fault(struct amdgpu_device *adev,
				   u32 addr, u32 status, u32 mc_client)
{
	struct ps4_uvd_irq_observer *obs = &adev->ps4_uvd_irq;
	struct ps4_uvd_fault_history *history = &obs->fault_history;
	struct ps4_uvd_fault_bucket *category;
	struct ps4_uvd_fault_record record = {
		.addr = addr,
		.status = status,
		.mc_client = mc_client,
	};
	unsigned long flags;

	if (!smp_load_acquire(&obs->active))
		return;

	/* Preserve an all-ones status as its own literal class, not VMID15.
	 * No failure or requester-cause inference is attached to this class.
	 */
	if (status == ~0U)
		category = &history->unclassified_status;
	else
		category = &history->vmid[
			REG_GET_FIELD(status, VM_CONTEXT1_PROTECTION_FAULT_STATUS, VMID)];

	spin_lock_irqsave(&obs->fault_lock, flags);
	ps4_uvd_fault_bucket_record(&history->total, &record);
	ps4_uvd_fault_bucket_record(category, &record);
	spin_unlock_irqrestore(&obs->fault_lock, flags);
}

/* Caller owns an adev lifetime reference and a non-NULL output. No GPU,
 * clock, allocation, work submission or reporting operation occurs here.
 * This cut is coherent only for the new GMC tuple history; legacy IH slots
 * keep their original independent atomic publications and report contract.
 */
void amdgpu_ps4_uvd_irq_fault_snapshot(struct amdgpu_device *adev,
				     struct ps4_uvd_fault_snapshot *snapshot)
{
	struct ps4_uvd_irq_observer *obs = &adev->ps4_uvd_irq;
	unsigned long flags;

	*snapshot = (struct ps4_uvd_fault_snapshot) { };
	if (!smp_load_acquire(&obs->active))
		return;

	spin_lock_irqsave(&obs->fault_lock, flags);
	snapshot->active = true;
	snapshot->arm_ns = obs->arm_ns;
	snapshot->history = obs->fault_history;
	spin_unlock_irqrestore(&obs->fault_lock, flags);
}
/* GMC_FAULT_FLOW_END */

void amdgpu_ps4_uvd_irq_report(struct amdgpu_device *adev)
{
	static const unsigned int source_ids[PS4_UVD_IRQ_SLOTS] = {
		VISLANDS30_IV_SRCID_UVD_SYSTEM_MESSAGE,
		VISLANDS30_IV_SRCID_GFX_PAGE_INV_FAULT,
		VISLANDS30_IV_SRCID_GFX_MEM_PROT_FAULT,
	};
	struct ps4_uvd_irq_observer *obs = &adev->ps4_uvd_irq;
	unsigned int i;

	if (!smp_load_acquire(&obs->active)) {
		dev_info(adev->dev, "PS4_UVD_READY IRQ_OBSERVATION armed=0; no observation window\n");
		return;
	}
	dev_info(adev->dev,
		"PS4_UVD_READY IRQ_OBSERVATION armed=1 arm_sw_ns=%llu report_start_sw_ns=%llu hardware_ih_only=1 noncoherent_cut=1 collector_remains_active=1; zero counts prove neither absence nor containment, no readiness inference\n",
		obs->arm_ns, ktime_get_mono_fast_ns());
	for (i = 0; i < PS4_UVD_IRQ_SLOTS; i++) {
		struct ps4_uvd_irq_slot *slot = &obs->slots[i];
		int state = atomic_read_acquire(&slot->first_state);

		/* No spin or wait for a WRITING record. Payload is immutable only
		 * after the READY release/acquire pair; never read it otherwise.
		 * Each counter is a later independent cut, including during printk.
		 */
		if (state == PS4_UVD_IRQ_READY)
			dev_info(adev->dev,
				"PS4_UVD_READY IRQ_ARRIVAL src=%u count=%llu wrapped=%d first_state=READY first_is_claimant=1 claim_sw_ns=%llu data0=%08x ring=%u vmid=%u pasid=%u; IV payload is not a GMC fault-status tuple\n",
				source_ids[i], (u64)atomic64_read(&slot->arrivals),
				atomic_read(&slot->wrapped), slot->claim_ns,
				slot->src_data0, slot->ring_id, slot->vmid, slot->pasid);
		else
			dev_info(adev->dev,
				"PS4_UVD_READY IRQ_ARRIVAL src=%u count=%llu wrapped=%d first_state=%s payload_valid=0\n",
				source_ids[i], (u64)atomic64_read(&slot->arrivals),
				atomic_read(&slot->wrapped),
				state == PS4_UVD_IRQ_EMPTY ? "EMPTY" : "WRITING");
	}
}
