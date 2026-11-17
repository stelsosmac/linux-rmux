// SPDX-License-Identifier: MIT
/*
 * Private PS4 translation diagnostic and owned mapping for a separate,
 * explicitly opted-in UVD readiness probe.
 *
 * Explicit boot-time opt-in only, with built-in AMDGPU. VMID4 stays outside
 * the normal LRU for this boot. A failed enabled diagnostic parks initial
 * device initialization permanently: no local unwind, retry, or reset; normal
 * TTM/client submissions have not yet been enabled. IRQ/fence work can continue.
 * An operator must power off and restore the known-good boot image.
 *
 * Original boot probes retain their allocations and fences until poweroff.
 * The separate preparation-only mode retains the full owned layout but
 * returns without calling UVD. It has a cached read-only status and an
 * ordinary preparation-owner destructor, never a UVD drain/rearm API.
 */
#include <linux/atomic.h>
#include <linux/crc32.h>
#include <linux/ktime.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/overflow.h>
#include <linux/sizes.h>
#include <linux/wait.h>
#include <drm/ttm/ttm_tt.h>

#include "amdgpu.h"
#include "amdgpu_ps4_map_canary.h"
#include "amdgpu_ps4_uvd_ready.h"
#include "amdgpu_reset.h"
#include "gmc/gmc_7_1_d.h"
#include "gmc/gmc_7_1_sh_mask.h"

#define PS4_CANARY_VMID 4
#define PS4_CANARY_VA 0x300000000ULL
#define PS4_CANARY_BYTES 256
#define PS4_CANARY_GUARD 0xa5deadc3U
#define PS4_CANARY_TIMEOUT msecs_to_jiffies(1000)
#define PS4_READY_R_BYTES 0x308000ULL
#define PS4_READY_RB_SLOT 776U
#define PS4_READY_IB_SLOT 778U
#define PS4_READY_IB_BYTES 0x20000ULL
#define PS4_READY_SDMA_SLOT 1021U
#define PS4_READY_MAPPED_PAGES 812U
#define PS4_FRAME_WORK_BYTES 0x40000ULL
#define PS4_FRAME_MAPPED_PAGES 844U
#define PS4_READY_MAX_MAPPED_PAGES PS4_FRAME_MAPPED_PAGES

static bool ps4_map_canary;
module_param_named(ps4_map_canary, ps4_map_canary, bool, 0444);
MODULE_PARM_DESC(ps4_map_canary,
	"Private one-shot PS4 VMID4 copy diagnostic; failure parks boot (default 0)");

static atomic_t ps4_canary_attempted = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(ps4_canary_park_queue);

struct ps4_canary_bo {
	struct amdgpu_bo *bo;
	u64 gpu;
	void *cpu;
};

struct ps4_canary_page {
	u64 dma, pte;
	unsigned long pfn;
	unsigned int slot;
};

struct ps4_canary_state {
	struct amdgpu_device *adev;
	struct ps4_canary_bo pd, pt, src, dst, ib;
	struct ps4_canary_bo r1, uvd_rb, uvd_ib;
	struct ps4_canary_page *pages;
	unsigned int mapped_pages;
	struct dma_fence *fence;
	u64 pd_size, pt_size, pd_index, leaf_index;
	u64 src_va, dst_va, ib_va;
	u32 expected[PS4_CANARY_BYTES / sizeof(u32)];
	u32 expected_ib[PAGE_SIZE / sizeof(u32)];
	bool submitted;
	bool passed;
	bool ready_mode;
	bool ready_layout;
	bool frame_mode;
	bool prepare_only;
};

/* DECODE_FRAME_LAYOUT_BEGIN */
/* Older leaves retain their exact 128KiB work allocation and 812 pages.
 * Only the exclusive first-frame leaf owns the separate 256KiB work BO.
 */
static u64 ps4_canary_work_bytes(const struct ps4_canary_state *s)
{
	return s->frame_mode ? PS4_FRAME_WORK_BYTES : PS4_READY_IB_BYTES;
}

static unsigned int ps4_canary_expected_pages(const struct ps4_canary_state *s)
{
	return s->frame_mode ? PS4_FRAME_MAPPED_PAGES : PS4_READY_MAPPED_PAGES;
}

static unsigned int ps4_canary_work_end_slot(const struct ps4_canary_state *s)
{
	return PS4_READY_IB_SLOT +
		(unsigned int)(ps4_canary_work_bytes(s) >> AMDGPU_GPU_PAGE_SHIFT);
}
/* DECODE_FRAME_LAYOUT_END */

/* LIVE_PREPARE_STATE_BEGIN */
static bool ps4_uvd_live_prepare;
module_param_named(ps4_uvd_live_prepare, ps4_uvd_live_prepare, bool, 0444);
MODULE_PARM_DESC(ps4_uvd_live_prepare,
	"Prepare an owned PS4 VMID4 mapping before clients, then continue boot; no UVD arm (default 0)");

/* A new adev after driver rebind is not permission to repeat this boot. */
static atomic_t ps4_live_prepare_attempted = ATOMIC_INIT(0);

bool amdgpu_ps4_live_prepare_enabled(struct amdgpu_device *adev)
{
	return ps4_uvd_live_prepare && IS_BUILTIN(CONFIG_DRM_AMDGPU) &&
		IS_ENABLED(CONFIG_X86_PS4) &&
		(adev->asic_type == CHIP_LIVERPOOL ||
		 adev->asic_type == CHIP_GLADIUS);
}

void amdgpu_ps4_live_prepare_init(struct amdgpu_device *adev)
{
	struct amdgpu_ps4_live_prepare *p = &adev->ps4_live_prepare;

	/* Never turn a second initialization into permission to prepare again. */
	if (p->initialized) {
		amdgpu_ps4_live_prepare_invalidate(adev, PS4_LIVE_EVENT_REINIT);
		return;
	}
	spin_lock_init(&p->lock);
	p->cached.selected = amdgpu_ps4_live_prepare_enabled(adev);
	p->cached.stage = p->cached.selected ? PS4_LIVE_SELECTED :
		PS4_LIVE_DISABLED;
	p->initialized = true;
}

void amdgpu_ps4_live_prepare_reserved(struct amdgpu_device *adev)
{
	struct amdgpu_ps4_live_prepare *p = &adev->ps4_live_prepare;
	unsigned long flags;

	if (!p->initialized || !p->cached.selected)
		return;
	spin_lock_irqsave(&p->lock, flags);
	p->cached.reservation_seen = true;
	p->cached.allocator_alive = true;
	if (p->cached.stage == PS4_LIVE_SELECTED)
		p->cached.stage = PS4_LIVE_RESERVED;
	spin_unlock_irqrestore(&p->lock, flags);
}

void amdgpu_ps4_live_prepare_invalidate(struct amdgpu_device *adev,
				       enum ps4_live_prepare_event event)
{
	struct amdgpu_ps4_live_prepare *p = &adev->ps4_live_prepare;
	unsigned long flags;

	if (!p->initialized || !p->cached.selected)
		return;
	spin_lock_irqsave(&p->lock, flags);
	++p->cached.observed_generation;
	p->cached.last_event = event;
	if (event == PS4_LIVE_EVENT_VMID_FINI)
		p->cached.allocator_alive = false;
	/* Initial GART setup predates preparation. Every event after the
	 * attempt is one-way invalidation, even if reset/suspend later aborts.
	 */
	if ((p->cached.attempted || event != PS4_LIVE_EVENT_GART_ENABLE) &&
	    p->cached.stage != PS4_LIVE_RELEASING &&
	    p->cached.stage != PS4_LIVE_RELEASED &&
	    p->cached.stage != PS4_LIVE_FAILED) {
		p->cached.stage = PS4_LIVE_INVALIDATED;
		p->cached.error = -ESTALE;
	}
	spin_unlock_irqrestore(&p->lock, flags);
}

void amdgpu_ps4_live_prepare_snapshot(struct amdgpu_device *adev,
				     struct ps4_live_prepare_snapshot *out)
{
	struct amdgpu_ps4_live_prepare *p = &adev->ps4_live_prepare;
	unsigned long flags;

	/* Pure cached-data query: no PM, reset lock, allocation, MMIO or work. */
	if (!p->initialized) {
		memset(out, 0, sizeof(*out));
		return;
	}
	spin_lock_irqsave(&p->lock, flags);
	*out = p->cached;
	spin_unlock_irqrestore(&p->lock, flags);
}

static int ps4_live_prepare_begin(struct amdgpu_device *adev)
{
	struct amdgpu_ps4_live_prepare *p = &adev->ps4_live_prepare;
	unsigned long flags;
	int r = 0;

	if (!p->initialized || !p->cached.selected)
		return -EINVAL;
	spin_lock_irqsave(&p->lock, flags);
	if (p->cached.attempted)
		r = -EALREADY;
	else if (p->cached.stage != PS4_LIVE_RESERVED ||
		 !p->cached.reservation_seen || !p->cached.allocator_alive)
		r = -EINVAL;
	else if (atomic_cmpxchg(&ps4_live_prepare_attempted, 0, 1))
		r = -EALREADY;
	else {
		p->cached.attempted = true;
		p->cached.stage = PS4_LIVE_PREPARING;
		p->cached.proof_generation = p->cached.observed_generation;
	}
	spin_unlock_irqrestore(&p->lock, flags);
	return r;
}

static void ps4_live_prepare_failure(struct amdgpu_device *adev, int error)
{
	struct amdgpu_ps4_live_prepare *p = &adev->ps4_live_prepare;
	unsigned long flags;

	if (!p->initialized || !p->cached.selected)
		return;
	spin_lock_irqsave(&p->lock, flags);
	p->cached.stage = PS4_LIVE_FAILED;
	p->cached.error = error;
	spin_unlock_irqrestore(&p->lock, flags);
}

static void ps4_live_prepare_attach(struct amdgpu_device *adev,
				    struct ps4_canary_state *s)
{
	struct amdgpu_ps4_live_prepare *p = &adev->ps4_live_prepare;
	unsigned long flags;

	spin_lock_irqsave(&p->lock, flags);
	p->pending = s;
	p->cached.retained = true;
	spin_unlock_irqrestore(&p->lock, flags);
}

static int ps4_live_prepare_publish(struct amdgpu_device *adev,
				     struct ps4_canary_state *s, u32 crc)
{
	struct amdgpu_ps4_live_prepare *p = &adev->ps4_live_prepare;
	unsigned long flags;
	int r = 0;

	if (!p->initialized || !p->cached.selected || !s)
		return -EINVAL;
	/* The caller has completed fence, exact pattern/guard and exclusivity
	 * checks. No ready helper or firmware access precedes this branch.
	 */
	spin_lock_irqsave(&p->lock, flags);
	if (p->pending != s || p->owner || !s->prepare_only ||
	    !s->ready_layout || s->ready_mode || !s->passed ||
	    !s->submitted || !s->fence || !s->pd.bo ||
	    s->mapped_pages != PS4_READY_MAPPED_PAGES ||
	    !adev->ps4_canary_fences_initialized ||
	    p->cached.stage != PS4_LIVE_PREPARING ||
	    p->cached.proof_generation != p->cached.observed_generation ||
	    !p->cached.allocator_alive || atomic_read(&adev->gpu_reset_counter)) {
		r = -ESTALE;
	} else {
		p->owner = s;
		p->pending = NULL;
		p->cached.pd_addr = amdgpu_gmc_pd_addr(s->pd.bo);
		p->cached.pd_bytes = s->pd_size;
		p->cached.pt_bytes = s->pt_size;
		p->cached.r1_bytes = PS4_READY_R_BYTES;
		p->cached.rb_bytes = PAGE_SIZE;
		p->cached.ib_bytes = PS4_READY_IB_BYTES;
		p->cached.mapped_pages = s->mapped_pages;
		p->cached.copy_crc = crc;
		p->cached.proof_reset_counter = 0;
		p->cached.proof_ns = ktime_get_ns();
		p->cached.proof_passed = true;
		p->cached.error = 0;
		p->cached.stage = PS4_LIVE_PREPARED;
	}
	spin_unlock_irqrestore(&p->lock, flags);
	return r;
}

static void ps4_live_prepare_free_bo(struct ps4_canary_bo *bo)
{
	amdgpu_bo_free_kernel(&bo->bo, &bo->gpu, &bo->cpu);
}

void amdgpu_ps4_live_prepare_fini(struct amdgpu_device *adev)
{
	struct amdgpu_ps4_live_prepare *p = &adev->ps4_live_prepare;
	struct ps4_canary_state *s;
	unsigned long flags;

	if (!p->initialized || !p->cached.selected)
		return;
	spin_lock_irqsave(&p->lock, flags);
	s = p->owner;
	if (!s) {
		spin_unlock_irqrestore(&p->lock, flags);
		return;
	}
	/* Only a successful preparation returns to device initialization.
	 * Failed preparation parks before normal removal can begin. The sole
	 * SDMA job completed; no UVD consumer has ever received these BOs.
	 * IP hw_fini has run; TTM and its DMA mappings still exist at this seam.
	 */
	p->owner = NULL;
	p->cached.stage = PS4_LIVE_RELEASING;
	spin_unlock_irqrestore(&p->lock, flags);
	dma_fence_put(s->fence);
	ps4_live_prepare_free_bo(&s->uvd_ib);
	ps4_live_prepare_free_bo(&s->uvd_rb);
	ps4_live_prepare_free_bo(&s->r1);
	ps4_live_prepare_free_bo(&s->ib);
	ps4_live_prepare_free_bo(&s->dst);
	ps4_live_prepare_free_bo(&s->src);
	ps4_live_prepare_free_bo(&s->pt);
	ps4_live_prepare_free_bo(&s->pd);
	kfree(s->pages);
	kfree(s);
	spin_lock_irqsave(&p->lock, flags);
	p->cached.stage = PS4_LIVE_RELEASED;
	p->cached.retained = false;
	spin_unlock_irqrestore(&p->lock, flags);
}
/* LIVE_PREPARE_STATE_END */

/* Original parked boot probes keep their legacy retained owner. */
static struct ps4_canary_state *ps4_canary_retained;

bool amdgpu_ps4_uvd_runtime_legacy_conflict(void)
{
	return ps4_map_canary || ps4_uvd_live_prepare;
}

bool amdgpu_ps4_map_canary_enabled(struct amdgpu_device *adev)
{
	if (amdgpu_ps4_uvd_runtime_enabled(adev))
		return false;
	return (ps4_map_canary || amdgpu_ps4_uvd_decode_frame_requested() ||
		amdgpu_ps4_uvd_message_create_requested() ||
		amdgpu_ps4_uvd_ready_enabled(adev) ||
		amdgpu_ps4_live_prepare_enabled(adev)) &&
		IS_BUILTIN(CONFIG_DRM_AMDGPU) &&
		IS_ENABLED(CONFIG_X86_PS4) &&
		(adev->asic_type == CHIP_LIVERPOOL ||
		 adev->asic_type == CHIP_GLADIUS);
}

bool amdgpu_ps4_map_canary_completed(struct amdgpu_device *adev)
{
	return ps4_canary_retained && ps4_canary_retained->adev == adev &&
		!ps4_canary_retained->ready_mode && ps4_canary_retained->passed;
}

bool amdgpu_ps4_map_canary_reserve(struct amdgpu_device *adev,
				 unsigned int vmhub, unsigned int vmid)
{
	return amdgpu_ps4_map_canary_enabled(adev) && vmhub == AMDGPU_GFXHUB(0) &&
		vmid == PS4_CANARY_VMID;
}

static __noreturn void ps4_canary_park(struct amdgpu_device *adev,
				     const char *stage, int error)
{
	ps4_live_prepare_failure(adev, error);
	dev_err(adev->dev,
		"PS4_MAP_CANARY FAIL stage=%s error=%d; PARKED no retry/reset/cleanup; power off and restore rollback\n",
		stage, error);
	/* TASK_IDLE is uninterruptible without hung-task noise. No wake exists. */
	for (;;)
		wait_event_idle(ps4_canary_park_queue, false);
}

static int ps4_canary_exclusive_init(struct amdgpu_device *adev)
{
	static const enum amd_ip_block_type topology[] = {
		AMD_IP_BLOCK_TYPE_COMMON, AMD_IP_BLOCK_TYPE_GMC,
		AMD_IP_BLOCK_TYPE_IH, AMD_IP_BLOCK_TYPE_DCE,
		AMD_IP_BLOCK_TYPE_GFX, AMD_IP_BLOCK_TYPE_SDMA,
	};
	unsigned long flags;
	unsigned int i;
	bool empty;

	if (IS_ENABLED(CONFIG_HSA_AMD) || adev->mman.buffer_funcs_enabled ||
	    adev->accel_working || !adev->irq.installed ||
	    adev->num_ip_blocks != ARRAY_SIZE(topology) ||
	    amdgpu_in_reset(adev) ||
	    atomic_read(&adev->gpu_reset_counter))
		return -EBUSY;
	for (i = 0; i < ARRAY_SIZE(topology); ++i)
		if (!adev->ip_blocks[i].version ||
		    adev->ip_blocks[i].version->type != topology[i] ||
		    !adev->ip_blocks[i].status.hw)
			return -EINVAL;
	for (i = 0; i < AMDGPU_MAX_RINGS; ++i) {
		struct amdgpu_ring *ring = adev->rings[i];

		if (!ring || !ring->sched.ready)
			continue;
		spin_lock_irqsave(&ring->sched.job_list_lock, flags);
		empty = list_empty(&ring->sched.pending_list);
		spin_unlock_irqrestore(&ring->sched.job_list_lock, flags);
		if (!empty || delayed_work_pending(&ring->sched.work_tdr) ||
		    work_pending(&ring->sched.work_run_job))
			return -EBUSY;
	}
	return 0;
}

static int ps4_canary_geometry(struct amdgpu_device *adev,
			       struct ps4_canary_state *s)
{
	const u64 max_pfn = adev->vm_manager.max_pfn;
	u64 leaf_entries, root_entries, root_bytes;
	u64 span = s->ready_layout ? SZ_4M : 3 * AMDGPU_GPU_PAGE_SIZE;
	u64 va_end, end_pfn;
	u32 control, start, end;
	struct amdgpu_vmid_mgr *mgr =
		&adev->vm_manager.id_mgr[AMDGPU_GFXHUB(0)];

	/* This diagnostic has only been designed for the measured two-level VM. */
	if (PAGE_SIZE != AMDGPU_GPU_PAGE_SIZE ||
	    adev->vm_manager.num_level != 1 ||
	    adev->vm_manager.root_level != AMDGPU_VM_PDB0 ||
	    adev->vm_manager.block_size != 10 || !max_pfn ||
	    max_pfn > U32_MAX || mgr->num_ids != 8 ||
	    !list_empty(&mgr->ids[PS4_CANARY_VMID].list))
		return -EINVAL;

	leaf_entries = 1ULL << adev->vm_manager.block_size;
	root_entries = DIV_ROUND_UP_ULL(max_pfn, leaf_entries);
	if (check_mul_overflow(root_entries, sizeof(u64), &root_bytes) ||
	    root_bytes > SZ_1M)
		return -EOVERFLOW;
	s->pd_size = ALIGN(root_bytes, PAGE_SIZE);
	s->pt_size = leaf_entries * sizeof(u64);
	s->pd_index = (PS4_CANARY_VA >> AMDGPU_GPU_PAGE_SHIFT) /
		leaf_entries;
	s->leaf_index = (PS4_CANARY_VA >> AMDGPU_GPU_PAGE_SHIFT) %
		leaf_entries;
	if (check_add_overflow(PS4_CANARY_VA, span, &va_end))
		return -EOVERFLOW;
	end_pfn = va_end >> AMDGPU_GPU_PAGE_SHIFT;
	if (s->pd_index >= root_entries ||
	    s->leaf_index + (span >> AMDGPU_GPU_PAGE_SHIFT) > leaf_entries ||
	    end_pfn > max_pfn ||
	    s->pd_index * sizeof(u64) + sizeof(u64) > s->pd_size ||
	    (s->leaf_index + (span >> AMDGPU_GPU_PAGE_SHIFT)) * sizeof(u64) >
		s->pt_size)
		return -ERANGE;
	/* VMID0 must not be able to pass this canary by a normal aperture alias. */
	if ((PS4_CANARY_VA <= adev->gmc.gart_end &&
	     va_end - 1 >= adev->gmc.gart_start) ||
	    (PS4_CANARY_VA <= adev->gmc.vram_end &&
	     va_end - 1 >= adev->gmc.vram_start))
		return -ERANGE;

	start = RREG32(mmVM_CONTEXT0_PAGE_TABLE_START_ADDR + PS4_CANARY_VMID);
	end = RREG32(mmVM_CONTEXT0_PAGE_TABLE_END_ADDR + PS4_CANARY_VMID);
	control = RREG32(mmVM_CONTEXT1_CNTL);
	if (start || end != max_pfn - 1 ||
	    REG_GET_FIELD(control, VM_CONTEXT1_CNTL, ENABLE_CONTEXT) != 1 ||
	    REG_GET_FIELD(control, VM_CONTEXT1_CNTL, PAGE_TABLE_DEPTH) != 1 ||
	    REG_GET_FIELD(control, VM_CONTEXT1_CNTL, PAGE_TABLE_BLOCK_SIZE) !=
		adev->vm_manager.block_size - 9)
		return -EINVAL;
	return 0;
}

static int ps4_canary_alloc(struct amdgpu_device *adev,
			    struct ps4_canary_bo *bo, u64 size, u32 domain)
{
	int r;

	r = amdgpu_bo_create_kernel(adev, size, PAGE_SIZE, domain,
				    &bo->bo, &bo->gpu, &bo->cpu);
	if (r)
		return r;
	if (!bo->cpu || amdgpu_bo_size(bo->bo) < size ||
	    bo->gpu & AMDGPU_GPU_PAGE_MASK ||
	    bo->bo->tbo.resource->mem_type !=
		(domain == AMDGPU_GEM_DOMAIN_VRAM ? TTM_PL_VRAM : TTM_PL_TT))
		return -EINVAL;
	return 0;
}

static int ps4_canary_leaf_pte(struct amdgpu_device *adev,
			       struct ps4_canary_bo *bo, u64 *pte)
{
	u64 offset, index, required, dma;

	if (!adev->gart.ptr || !bo->bo->tbo.ttm ||
	    !bo->bo->tbo.ttm->dma_address ||
	    bo->gpu < adev->gmc.gart_start ||
	    bo->gpu > adev->gmc.gart_end ||
	    AMDGPU_GPU_PAGE_SIZE - 1 > adev->gmc.gart_end - bo->gpu)
		return -ERANGE;
	offset = bo->gpu - adev->gmc.gart_start;
	if (offset & AMDGPU_GPU_PAGE_MASK)
		return -EINVAL;
	index = offset >> AMDGPU_GPU_PAGE_SHIFT;
	if (index >= adev->gart.num_gpu_pages ||
	    index * sizeof(u64) + sizeof(u64) > adev->gart.table_size)
		return -ERANGE;
	*pte = readq((void __iomem *)adev->gart.ptr + index * sizeof(u64));
	required = AMDGPU_PTE_VALID | AMDGPU_PTE_SYSTEM |
		AMDGPU_PTE_READABLE | AMDGPU_PTE_WRITEABLE;
	dma = bo->bo->tbo.ttm->dma_address[0];
	if ((*pte & required) != required ||
	    (*pte & adev->gmc.pte_addr_mask) != dma ||
	    (dma & ~adev->gmc.pte_addr_mask))
		return -EINVAL;
	return 0;
}

static int ps4_canary_vram_range(struct amdgpu_device *adev,
				 struct ps4_canary_bo *bo, u64 size, u64 *end)
{
	if (!bo->bo || !bo->cpu || !bo->bo->tbo.resource ||
	    !bo->bo->tbo.pin_count || amdgpu_bo_size(bo->bo) != size ||
	    bo->bo->tbo.resource->mem_type != TTM_PL_VRAM ||
	    !size || (size & AMDGPU_GPU_PAGE_MASK) ||
	    (bo->gpu & AMDGPU_GPU_PAGE_MASK) ||
	    check_add_overflow(bo->gpu, size, end))
		return -EINVAL;
	if (bo->gpu < adev->gmc.vram_start || *end - 1 > adev->gmc.vram_end ||
	    ((*end - 1) & ~(adev->gmc.pte_addr_mask | AMDGPU_GPU_PAGE_MASK)) ||
	    (bo->gpu & ~adev->gmc.pte_addr_mask))
		return -ERANGE;
	return 0;
}

/* Collect and validate every native GTT page before writing the private PT. */
static int ps4_canary_add_bo_pages(struct amdgpu_device *adev,
				   struct ps4_canary_state *s,
				   struct ps4_canary_bo *bo, u64 bytes,
				   unsigned int first_slot)
{
	struct ttm_tt *ttm;
	u64 count, flags, required;
	unsigned int p, j;

	if (!bo->bo || !bo->cpu || !bo->bo->tbo.resource ||
	    !bo->bo->tbo.pin_count || bo->bo->tbo.type != ttm_bo_type_kernel ||
	    bo->bo->tbo.resource->mem_type != TTM_PL_TT ||
	    amdgpu_bo_size(bo->bo) != bytes || !bytes ||
	    (bytes & AMDGPU_GPU_PAGE_MASK) || !adev->gart.ptr)
		return -EINVAL;
	ttm = bo->bo->tbo.ttm;
	count = bytes >> AMDGPU_GPU_PAGE_SHIFT;
	if (!ttm || !ttm->dma_address || !ttm->pages ||
	    (ttm->page_flags & TTM_TT_FLAG_EXTERNAL) ||
	    !ttm_tt_is_populated(ttm) || count > ttm->num_pages ||
	    first_slot >= s->pt_size / sizeof(u64) ||
	    count > s->pt_size / sizeof(u64) - first_slot ||
	    s->mapped_pages > ps4_canary_expected_pages(s) ||
	    count > ps4_canary_expected_pages(s) - s->mapped_pages)
		return -ERANGE;
	flags = amdgpu_ttm_tt_pte_flags(adev, ttm, bo->bo->tbo.resource);
	required = AMDGPU_PTE_VALID | AMDGPU_PTE_SYSTEM |
		AMDGPU_PTE_READABLE | AMDGPU_PTE_WRITEABLE;
	if ((flags & required) != required || (flags & adev->gmc.pte_addr_mask))
		return -EINVAL;

	for (p = 0; p < count; ++p) {
		struct ps4_canary_page *page = &s->pages[s->mapped_pages];
		u64 offset, gpu, index, pte_offset, pte, dma;
		unsigned long pfn;
		unsigned int slot = first_slot + p;

		if (!ttm->pages[p] ||
		    check_mul_overflow((u64)p, (u64)AMDGPU_GPU_PAGE_SIZE, &offset) ||
		    check_add_overflow(bo->gpu, offset, &gpu) ||
		    gpu < adev->gmc.gart_start || gpu > adev->gmc.gart_end ||
		    AMDGPU_GPU_PAGE_SIZE - 1 > adev->gmc.gart_end - gpu ||
		    ((gpu - adev->gmc.gart_start) & AMDGPU_GPU_PAGE_MASK))
			return -ERANGE;
		index = (gpu - adev->gmc.gart_start) >> AMDGPU_GPU_PAGE_SHIFT;
		if (index >= adev->gart.num_gpu_pages ||
		    check_mul_overflow(index, (u64)sizeof(u64), &pte_offset) ||
		    pte_offset > adev->gart.table_size ||
		    sizeof(u64) > adev->gart.table_size - pte_offset)
			return -ERANGE;
		dma = ttm->dma_address[p];
		if (dma & ~adev->gmc.pte_addr_mask)
			return -ERANGE;
		pte = readq((void __iomem *)adev->gart.ptr + pte_offset);
		if (pte != (dma | flags))
			return -EINVAL;
		pfn = page_to_pfn(ttm->pages[p]);
		for (j = 0; j < s->mapped_pages; ++j)
			if (s->pages[j].slot == slot || s->pages[j].dma == dma ||
			    s->pages[j].pfn == pfn)
				return -EINVAL;
		page->dma = dma;
		page->pte = pte;
		page->pfn = pfn;
		page->slot = slot;
		++s->mapped_pages;
	}
	return 0;
}

static int ps4_canary_ready_pages(struct amdgpu_device *adev,
				  struct ps4_canary_state *s, u64 ptes[3])
{
	u64 pd_end, pt_end;
	unsigned int i;
	int r;

	r = ps4_canary_vram_range(adev, &s->pd, s->pd_size, &pd_end);
	if (!r)
		r = ps4_canary_vram_range(adev, &s->pt, s->pt_size, &pt_end);
	if (r)
		return r;
	if (s->pd.bo == s->pt.bo ||
	    (s->pd.gpu < pt_end && s->pt.gpu < pd_end))
		return -EINVAL;
	/* CPU-only metadata is retained on the heap, never a large stack array. */
	s->pages = kcalloc(PS4_READY_MAX_MAPPED_PAGES, sizeof(*s->pages), GFP_KERNEL);
	if (!s->pages)
		return -ENOMEM;
	r = ps4_canary_add_bo_pages(adev, s, &s->r1, PS4_READY_R_BYTES, 0);
	if (!r)
		r = ps4_canary_add_bo_pages(adev, s, &s->uvd_rb,
			AMDGPU_GPU_PAGE_SIZE, PS4_READY_RB_SLOT);
	if (!r)
		r = ps4_canary_add_bo_pages(adev, s, &s->uvd_ib,
			ps4_canary_work_bytes(s), PS4_READY_IB_SLOT);
	if (!r)
		r = ps4_canary_add_bo_pages(adev, s, &s->src,
			AMDGPU_GPU_PAGE_SIZE, PS4_READY_SDMA_SLOT);
	if (!r)
		r = ps4_canary_add_bo_pages(adev, s, &s->dst,
			AMDGPU_GPU_PAGE_SIZE, PS4_READY_SDMA_SLOT + 1);
	if (!r)
		r = ps4_canary_add_bo_pages(adev, s, &s->ib,
			AMDGPU_GPU_PAGE_SIZE, PS4_READY_SDMA_SLOT + 2);
	if (r)
		return r;
	if (s->mapped_pages != ps4_canary_expected_pages(s))
		return -EINVAL;
	for (i = 0; i < 3; ++i)
		ptes[i] = s->pages[s->mapped_pages - 3 + i].pte;
	return 0;
}

/* DECODE_FRAME_PT_READBACK_BEGIN */
/* CPU preparation/readback evidence only: this is not a claim that UVD has
 * observed every page, nor a proof of DMA quiescence.  No PTE is changed here.
 * The inventory is in increasing slot order; every unmapped hole stays zero.
 */
static bool ps4_canary_frame_pt_valid(const struct ps4_canary_state *s)
{
	unsigned int slot, page = 0;

	if (!s || !s->frame_mode || !s->ready_mode || !s->ready_layout ||
	    s->prepare_only || !s->pages || !s->pt.bo || !s->pt.cpu ||
	    s->leaf_index || s->pt_size != 1024U * sizeof(u64) ||
	    amdgpu_bo_size(s->pt.bo) != s->pt_size ||
	    s->mapped_pages != ps4_canary_expected_pages(s))
		return false;
	for (slot = 0; slot < 1024U; ++slot) {
		u64 expected = 0;

		if (page < s->mapped_pages && s->pages[page].slot == slot)
			expected = s->pages[page++].pte;
		if (readq((void __iomem *)s->pt.cpu + slot * sizeof(u64)) != expected)
			return false;
	}
	return page == s->mapped_pages;
}
/* DECODE_FRAME_PT_READBACK_END */

/* Borrow exactly the ring already validated with all expected unique DMA/PFN pages.
 * Do not call add_bo_pages again: it mutates the retained page inventory.
 * The successful fence/pattern control flow, not s->passed, establishes precheck.
 */
static bool ps4_canary_token_ring(struct ps4_canary_state *s,
				 struct amdgpu_ps4_uvd_ring *rb)
{
	struct ps4_canary_bo *bo = &s->uvd_rb;

	if (s != ps4_canary_retained || !s->ready_mode || !s->submitted ||
	    !s->fence || !bo->bo || !bo->cpu || ((unsigned long)bo->cpu & 3U) ||
	    !bo->bo->tbo.resource || !bo->bo->tbo.pin_count ||
	    bo->bo->tbo.type != ttm_bo_type_kernel ||
	    bo->bo->tbo.resource->mem_type != TTM_PL_TT ||
	    amdgpu_bo_size(bo->bo) != AMDGPU_GPU_PAGE_SIZE ||
	    s->mapped_pages != ps4_canary_expected_pages(s))
		return false;
	rb->cpu = bo->cpu;
	rb->bytes = amdgpu_bo_size(bo->bo);
	/* bo->gpu is the native GART alias, not this private VMID4 address. */
	rb->private_va = PS4_CANARY_VA +
		(u64)PS4_READY_RB_SLOT * AMDGPU_GPU_PAGE_SIZE;
	return true;
}

/* IB_DATA_OWNED_PAGE_BEGIN */
/* Borrow only the first page of the existing, separately mapped 128KiB BO.
 * The completed precheck and final exclusivity check precede this call.
 * The original SDMA src/dst/IB evidence and the page inventory stay intact.
 */
static bool ps4_canary_ib_data_page(struct ps4_canary_state *s,
				    struct amdgpu_ps4_uvd_ring *ib_page)
{
	struct ps4_canary_bo *bo;

	if (!s || !ib_page)
		return false;
	bo = &s->uvd_ib;

	if (s != ps4_canary_retained || !s->ready_mode || !s->submitted ||
	    !s->fence || !bo->bo || !bo->cpu || ((unsigned long)bo->cpu & 3U) ||
	    !bo->bo->tbo.resource || !bo->bo->tbo.pin_count ||
	    bo->bo->tbo.type != ttm_bo_type_kernel ||
	    bo->bo->tbo.resource->mem_type != TTM_PL_TT ||
	    amdgpu_bo_size(bo->bo) != PS4_READY_IB_BYTES ||
	    bo->bo == s->uvd_rb.bo || s->mapped_pages != PS4_READY_MAPPED_PAGES)
		return false;
	ib_page->cpu = bo->cpu;
	ib_page->bytes = AMDGPU_GPU_PAGE_SIZE;
	ib_page->private_va = PS4_CANARY_VA +
		(u64)PS4_READY_IB_SLOT * AMDGPU_GPU_PAGE_SIZE;
	return true;
}
/* IB_DATA_OWNED_PAGE_END */

/* MESSAGE_CREATE_OWNED_BACKING_BEGIN */
/* Borrow the complete existing 128KiB allocation; no additional BO or PTE. */
static bool ps4_canary_message_backing(struct ps4_canary_state *s,
				      struct amdgpu_ps4_uvd_ring *backing)
{
	struct ps4_canary_bo *bo;

	if (!s || !backing)
		return false;
	bo = &s->uvd_ib;
	if (s != ps4_canary_retained || !s->ready_mode || !s->submitted ||
	    !s->fence || !bo->bo || !bo->cpu || ((unsigned long)bo->cpu & 3U) ||
	    !bo->bo->tbo.resource || !bo->bo->tbo.pin_count ||
	    bo->bo->tbo.type != ttm_bo_type_kernel ||
	    bo->bo->tbo.resource->mem_type != TTM_PL_TT ||
	    amdgpu_bo_size(bo->bo) != PS4_READY_IB_BYTES ||
	    bo->bo == s->uvd_rb.bo || s->mapped_pages != PS4_READY_MAPPED_PAGES)
		return false;
	backing->cpu = bo->cpu;
	backing->bytes = PS4_READY_IB_BYTES;
	/* bo->gpu is a different native GART alias; never use it here. */
	backing->private_va = PS4_CANARY_VA +
		(u64)PS4_READY_IB_SLOT * AMDGPU_GPU_PAGE_SIZE;
	return true;
}
/* MESSAGE_CREATE_OWNED_BACKING_END */

/* DECODE_FRAME_OWNED_BACKING_BEGIN */
/* Borrow the full separately owned 256KiB frame BO, never firmware storage.
 * The normal UVD main ring remains its own 4096-byte allocation.  The frame
 * gate is immutable, and the complete mapping was validated before publish.
 */
static bool ps4_canary_frame_backing(struct ps4_canary_state *s,
				    struct amdgpu_ps4_uvd_ring *backing)
{
	struct ps4_canary_bo *bo;

	if (!s || !backing || !s->frame_mode ||
	    !amdgpu_ps4_uvd_decode_frame_requested() ||
	    !amdgpu_ps4_uvd_decode_frame_options_valid(s->adev))
		return false;
	bo = &s->uvd_ib;
	if (s != ps4_canary_retained || !s->ready_mode || !s->submitted ||
	    !s->fence || !bo->bo || !bo->cpu || ((unsigned long)bo->cpu & 3U) ||
	    !bo->bo->tbo.resource || !bo->bo->tbo.pin_count ||
	    bo->bo->tbo.type != ttm_bo_type_kernel ||
	    bo->bo->tbo.resource->mem_type != TTM_PL_TT ||
	    amdgpu_bo_size(bo->bo) != PS4_FRAME_WORK_BYTES ||
	    bo->bo == s->uvd_rb.bo || !ps4_canary_frame_pt_valid(s))
		return false;
	backing->cpu = bo->cpu;
	backing->bytes = PS4_FRAME_WORK_BYTES;
	/* The native bo->gpu alias is never a command address for VMID4. */
	backing->private_va = PS4_CANARY_VA +
		(u64)PS4_READY_IB_SLOT * AMDGPU_GPU_PAGE_SIZE;
	return true;
}
/* DECODE_FRAME_OWNED_BACKING_END */

void amdgpu_ps4_map_canary_run(struct amdgpu_device *adev)
{
	struct amdgpu_ring *ring = &adev->sdma.instance[0].ring;
	struct ps4_canary_state *s;
	struct amdgpu_job *job;
	u64 ptes[3], pt_addr, pt_flags;
	u32 *src, *dst, crc;
	unsigned int i;
	long waited;
	int r;

	if (!amdgpu_ps4_map_canary_enabled(adev))
		return;
	/* Reject the raw frame gate before allocating state or any BO.  The
	 * ready helper checks raw older leaves; map-only and raw live preparation
	 * belong to this file and must not disappear behind an enabled predicate.
	 */
	if (amdgpu_ps4_uvd_decode_frame_requested() &&
	    (ps4_map_canary || ps4_uvd_live_prepare ||
	     !amdgpu_ps4_uvd_decode_frame_options_valid(adev)))
		ps4_canary_park(adev, "decode-frame-conflicting-gates", -EINVAL);
	/* Reject a selected CREATE leaf even when ready was omitted. */
	if (amdgpu_ps4_uvd_message_create_requested() &&
	    (ps4_map_canary || !amdgpu_ps4_uvd_message_create_options_valid(adev)))
		ps4_canary_park(adev, "message-create-conflicting-gates", -EINVAL);
	if (ps4_map_canary && amdgpu_ps4_uvd_ready_requested())
		ps4_canary_park(adev, "conflicting-boot-gates", -EINVAL);
	if (amdgpu_ps4_live_prepare_enabled(adev)) {
		if (ps4_map_canary || amdgpu_ps4_uvd_boot_probe_requested())
			ps4_canary_park(adev, "live-prepare-conflicting-gates", -EINVAL);
		if (IS_ENABLED(CONFIG_PM) || !IS_ENABLED(CONFIG_DEBUG_FS))
			ps4_canary_park(adev, "live-prepare-config", -EINVAL);
		r = ps4_live_prepare_begin(adev);
		if (r)
			ps4_canary_park(adev, "live-prepare-begin", r);
	} else if (atomic_cmpxchg(&ps4_canary_attempted, 0, 1)) {
		ps4_canary_park(adev, "second-init-refused", -EALREADY);
	}
	dev_info(adev->dev,
		 "PS4_MAP_CANARY BEGIN vmid=4 va=0x%llx bytes=%u timeout_ms=1000 UVD=off\n",
		 PS4_CANARY_VA, PS4_CANARY_BYTES);
	r = ps4_canary_exclusive_init(adev);
	if (r)
		ps4_canary_park(adev, "exclusive-init", r);
	if (!ring->sched.ready || !ring->fence_drv.initialized ||
	    adev->mman.buffer_funcs_enabled ||
	    ring->vm_hub != AMDGPU_GFXHUB(0) ||
	    !adev->mman.buffer_funcs ||
	    !adev->mman.buffer_funcs->emit_copy_buffer ||
	    !ring->funcs->emit_vm_flush)
		ps4_canary_park(adev, "ring-preflight", -EINVAL);

	s = kzalloc_obj(*s);
	if (!s)
		ps4_canary_park(adev, "state-allocation", -ENOMEM);
	s->adev = adev;
	s->ready_mode = amdgpu_ps4_uvd_ready_enabled(adev);
	s->frame_mode = amdgpu_ps4_uvd_decode_frame_requested();
	s->prepare_only = amdgpu_ps4_live_prepare_enabled(adev);
	s->ready_layout = s->ready_mode || s->prepare_only;
	if (s->prepare_only)
		ps4_live_prepare_attach(adev, s);
	else
		ps4_canary_retained = s;
	s->src_va = PS4_CANARY_VA + (s->ready_layout ?
		(u64)PS4_READY_SDMA_SLOT * AMDGPU_GPU_PAGE_SIZE : 0);
	s->dst_va = s->src_va + AMDGPU_GPU_PAGE_SIZE;
	s->ib_va = s->dst_va + AMDGPU_GPU_PAGE_SIZE;
	r = ps4_canary_geometry(adev, s);
	if (r)
		ps4_canary_park(adev, "geometry", r);
	r = ps4_canary_alloc(adev, &s->pd, s->pd_size, AMDGPU_GEM_DOMAIN_VRAM);
	if (!r)
		r = ps4_canary_alloc(adev, &s->pt, s->pt_size, AMDGPU_GEM_DOMAIN_VRAM);
	if (!r)
		r = ps4_canary_alloc(adev, &s->src, PAGE_SIZE, AMDGPU_GEM_DOMAIN_GTT);
	if (!r)
		r = ps4_canary_alloc(adev, &s->dst, PAGE_SIZE, AMDGPU_GEM_DOMAIN_GTT);
	if (!r)
		r = ps4_canary_alloc(adev, &s->ib, PAGE_SIZE, AMDGPU_GEM_DOMAIN_GTT);
	if (!r && s->ready_layout)
		r = ps4_canary_alloc(adev, &s->r1, PS4_READY_R_BYTES,
			AMDGPU_GEM_DOMAIN_GTT);
	if (!r && s->ready_layout)
		r = ps4_canary_alloc(adev, &s->uvd_rb, PAGE_SIZE,
			AMDGPU_GEM_DOMAIN_GTT);
	if (!r && s->ready_layout)
		r = ps4_canary_alloc(adev, &s->uvd_ib, ps4_canary_work_bytes(s),
			AMDGPU_GEM_DOMAIN_GTT);
	if (r)
		ps4_canary_park(adev, "bo-allocation", r);

	/* Avoid calling GMC7's BUG_ON-based PDE helper with unchecked addresses. */
	if ((s->pd.gpu | s->pt.gpu) & ~adev->gmc.pte_addr_mask)
		ps4_canary_park(adev, "table-address-domain", -ERANGE);
	if (s->ready_layout) {
		r = ps4_canary_ready_pages(adev, s, ptes);
	} else {
		r = ps4_canary_leaf_pte(adev, &s->src, &ptes[0]);
		if (!r)
			r = ps4_canary_leaf_pte(adev, &s->dst, &ptes[1]);
		if (!r)
			r = ps4_canary_leaf_pte(adev, &s->ib, &ptes[2]);
	}
	if (r)
		ps4_canary_park(adev, "owned-gart-pte", r);
	if (!((ptes[0] ^ ptes[1]) & adev->gmc.pte_addr_mask) ||
	    !((ptes[0] ^ ptes[2]) & adev->gmc.pte_addr_mask) ||
	    !((ptes[1] ^ ptes[2]) & adev->gmc.pte_addr_mask))
		ps4_canary_park(adev, "physical-page-alias", -EINVAL);

	memset_io((void __iomem *)s->pd.cpu, 0, s->pd_size);
	memset_io((void __iomem *)s->pt.cpu, 0, s->pt_size);
	amdgpu_gmc_get_pde_for_bo(s->pt.bo, adev->vm_manager.root_level,
				  &pt_addr, &pt_flags);
	if (!(pt_flags & AMDGPU_PTE_VALID) || (pt_flags & AMDGPU_PTE_SYSTEM))
		ps4_canary_park(adev, "vram-pde", -EINVAL);
	amdgpu_gmc_set_pte_pde(adev, s->pd.cpu, s->pd_index, pt_addr, pt_flags);
	if (s->ready_layout) {
		for (i = 0; i < s->mapped_pages; ++i)
			writeq(s->pages[i].pte, (void __iomem *)s->pt.cpu +
			       s->pages[i].slot * sizeof(u64));
		memset(s->r1.cpu, 0, PS4_READY_R_BYTES);
		memset(s->uvd_rb.cpu, 0, PAGE_SIZE);
		memset(s->uvd_ib.cpu, 0, ps4_canary_work_bytes(s));
		if (s->frame_mode && !ps4_canary_frame_pt_valid(s))
			ps4_canary_park(adev, "decode-frame-private-pte-readback", -EINVAL);
		dev_info(adev->dev,
			 "PS4_MAP_CANARY READY_LAYOUT pages=%u guards=777,%u..1020 sdma_slots=1021..1023 all_dma_pfn_unique=1\n",
			 s->mapped_pages, ps4_canary_work_end_slot(s));
	} else {
		for (i = 0; i < ARRAY_SIZE(ptes); ++i)
			writeq(ptes[i], (void __iomem *)s->pt.cpu +
			       (s->leaf_index + i) * sizeof(u64));
	}

	src = s->src.cpu;
	dst = s->dst.cpu;
	for (i = 0; i < PAGE_SIZE / sizeof(u32); ++i) {
		src[i] = PS4_CANARY_GUARD;
		dst[i] = PS4_CANARY_GUARD;
	}
	for (i = 0; i < ARRAY_SIZE(s->expected); ++i)
		src[i] = s->expected[i] = 0x50533400U ^ (i * 0x01020409U);
	for (i = 0; i < PAGE_SIZE / sizeof(u32); ++i)
		((u32 *)s->ib.cpu)[i] = PS4_CANARY_GUARD;
	r = amdgpu_job_alloc(adev, NULL, NULL, NULL, 1, 0, GFP_KERNEL, &job);
	if (r)
		ps4_canary_park(adev, "job-allocation", r);
	job->num_ibs = 1;
	job->vmid = PS4_CANARY_VMID;
	job->vm_pd_addr = amdgpu_gmc_pd_addr(s->pd.bo);
	job->vm_needs_flush = true;
	/* Owned BO, no SA allocation: submit_direct job_free cannot release it. */
	job->ibs[0].ptr = s->ib.cpu;
	job->ibs[0].gpu_addr = s->ib_va;
	adev->mman.buffer_funcs->emit_copy_buffer(&job->ibs[0], s->src_va,
		s->dst_va, PS4_CANARY_BYTES, 0);
	amdgpu_ring_pad_ib(ring, &job->ibs[0]);
	if (!job->ibs[0].length_dw || job->ibs[0].length_dw > PAGE_SIZE / sizeof(u32))
		ps4_canary_park(adev, "ib-bounds", -ERANGE);
	memcpy(s->expected_ib, s->ib.cpu, PAGE_SIZE);
	r = ps4_canary_exclusive_init(adev);
	if (r)
		ps4_canary_park(adev, "pre-submit-exclusive-init", r);

	/* Same CPU publication order as amdgpu_vm_cpu_commit, before ring TLB flush. */
	mb();
	amdgpu_device_flush_hdp(adev, NULL);
	dev_info(adev->dev,
		 "PS4_MAP_CANARY MAP max_pfn=0x%llx block=%u pd_bytes=0x%llx pde=0x%llx pt_bytes=0x%llx src_pte=0x%llx dst_pte=0x%llx ib_pte=0x%llx\n",
		 adev->vm_manager.max_pfn, adev->vm_manager.block_size,
		 s->pd_size, s->pd_index, s->pt_size, ptes[0], ptes[1], ptes[2]);
	r = amdgpu_job_submit_direct(job, ring, &s->fence);
	if (r) {
		/* Pre-commit error: still deliberately retain job and BOs while parked. */
		ps4_canary_park(adev, "submit", r);
	}
	s->submitted = true;
	waited = dma_fence_wait_timeout(s->fence, false, PS4_CANARY_TIMEOUT);
	if (waited <= 0)
		ps4_canary_park(adev, "completion", waited ? (int)waited : -ETIMEDOUT);
	r = dma_fence_get_status(s->fence);
	if (r <= 0)
		ps4_canary_park(adev, "fence-status", r ? r : -EIO);
	amdgpu_device_invalidate_hdp(adev, NULL);
	mb();
	if (memcmp(dst, s->expected, sizeof(s->expected)) ||
	    memcmp(src, s->expected, sizeof(s->expected)) ||
	    memcmp(s->ib.cpu, s->expected_ib, PAGE_SIZE))
		ps4_canary_park(adev, "pattern-readback", -EILSEQ);
	for (i = ARRAY_SIZE(s->expected); i < PAGE_SIZE / sizeof(u32); ++i)
		if (dst[i] != PS4_CANARY_GUARD || src[i] != PS4_CANARY_GUARD)
			ps4_canary_park(adev, "guard-readback", -EILSEQ);
	crc = crc32_le(~0U, (u8 *)dst, PS4_CANARY_BYTES) ^ ~0U;
	if (s->prepare_only) {
		r = ps4_canary_exclusive_init(adev);
		if (r)
			ps4_canary_park(adev, "pre-prepare-exclusive-init", r);
		s->passed = true;
		r = ps4_live_prepare_publish(adev, s, crc);
		if (r)
			ps4_canary_park(adev, "live-prepare-publish", r);
		dev_info(adev->dev,
			 "PS4_LIVE_PREPARE PREPARED vmid=4 pages=%u copy_crc32=%08x historical_sdma_proof=1 retained=1 UVD_setup=never arm=absent; continuing normal initialization\n",
			 s->mapped_pages, crc);
		return;
	}
	if (s->ready_mode) {
		struct amdgpu_ps4_uvd_ring token_ring = { 0 };
		struct amdgpu_ps4_uvd_ring message_backing = { 0 };
		struct amdgpu_ps4_uvd_ring frame_backing = { 0 };
		/* IB_DATA_BORROW_DECL_BEGIN */
		struct amdgpu_ps4_uvd_ring ib_page = { 0 };
		/* IB_DATA_BORROW_DECL_END */

		r = ps4_canary_exclusive_init(adev);
		if (r)
			ps4_canary_park(adev, "pre-ready-exclusive-init", r);
		dev_info(adev->dev,
			 "PS4_MAP_CANARY PRECHECK_PASS vmid=4 src_va=0x%llx dst_va=0x%llx ib_va=0x%llx bytes=%u crc32=%08x retained=1; entering ready probe\n",
			 s->src_va, s->dst_va, s->ib_va, PS4_CANARY_BYTES, crc);
		/* No PTE changes after precheck. The ready stage owns firmware data
		 * publication before release and never returns or frees our BOs.
		 */
		if ((amdgpu_ps4_uvd_token_requested() ||
		     amdgpu_ps4_uvd_message_create_requested() ||
		     amdgpu_ps4_uvd_decode_frame_requested()) &&
		    !ps4_canary_token_ring(s, &token_ring))
			ps4_canary_park(adev, "token-owned-ring", -EINVAL);
		if (amdgpu_ps4_uvd_message_create_requested() &&
		    !ps4_canary_message_backing(s, &message_backing))
			ps4_canary_park(adev, "message-create-owned-backing", -EINVAL);
		if (s->frame_mode &&
		    !ps4_canary_frame_backing(s, &frame_backing))
			ps4_canary_park(adev, "decode-frame-owned-backing", -EINVAL);
		/* IB_DATA_BORROW_BEGIN */
		if (amdgpu_ps4_uvd_ib_data_requested() &&
		    !ps4_canary_ib_data_page(s, &ib_page))
			ps4_canary_park(adev, "ib-data-owned-page", -EINVAL);
		/* IB_DATA_BORROW_END */
		amdgpu_ps4_uvd_ready_run(adev, s->r1.cpu,
			(size_t)PS4_READY_R_BYTES, amdgpu_gmc_pd_addr(s->pd.bo),
			(amdgpu_ps4_uvd_token_requested() ||
			 amdgpu_ps4_uvd_message_create_requested() ||
			 amdgpu_ps4_uvd_decode_frame_requested()) ? &token_ring : NULL,
			s->frame_mode ? &frame_backing :
			amdgpu_ps4_uvd_message_create_requested() ? &message_backing :
			(amdgpu_ps4_uvd_ib_data_requested() ? &ib_page : NULL));
		/* Defensive local terminal path also gives object-only objtool a
		 * valid continuation for the external readiness helper call.
		 */
		ps4_canary_park(adev, "ready-stage-returned", -EIO);
	}
	s->passed = true;
	dev_info(adev->dev,
		 "PS4_MAP_CANARY PASS vmid=4 bytes=%u exact_words=%zu crc32=%08x first=%08x last=%08x guards=ok retained_until_poweroff=1 UVD=off\n",
		 PS4_CANARY_BYTES, ARRAY_SIZE(s->expected), crc,
		 dst[0], dst[ARRAY_SIZE(s->expected) - 1]);
}
