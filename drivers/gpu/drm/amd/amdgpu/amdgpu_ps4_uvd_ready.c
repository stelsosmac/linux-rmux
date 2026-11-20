// SPDX-License-Identifier: MIT
/*
 * Private boot-only Liverpool UVD startup and fixed-reference frame driver.
 *
 * Public source comparison: Linux a2de78ee6ed8bf8cd99d177c74865a6e8c3cb6ea,
 * uvd_v5_0.c:uvd_v5_0_start/uvd_v5_0_mc_resume and uvd_v6_0.c:mc_resume,
 * uvd_5_0_{d,sh_mask}.h. Register compatibility with Liverpool is an explicit
 * experiment, not established by the matching public names. Historical layout:
 * public linux-ps4-kernel 0cbe1644c38bf2030f74526b6670490271b89716,
 * active 0034..0060. Other untyped historical addresses remain omitted.
 *
 * This runs only after the separate owned-VMID4 SDMA copy precheck. No normal
 * UVD IP registration, retries, idle worker or return to TTM clients exists.
 * The default readiness path submits nothing. A separate immutable token gate
 * permits one bounded context-write experiment after the ready convention.
 * Every outcome parks without releasing firmware or mapped BOs.
 * Ready does not prove DMA quiescence, decoding or a safe shutdown procedure.
 */
#include <linux/atomic.h>
#include <linux/crc32.h>
#include <crypto/sha2.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/ktime.h>
#include <linux/moduleparam.h>
#include <linux/math64.h>
#include <linux/unaligned.h>
#include <linux/wait.h>
#include "amdgpu_ps4_uvd_runtime.h"

#include "amdgpu.h"
#include "amdgpu_ps4_uvd_ready.h"
#include "amdgpu_ps4_uvd_frame_fixture.h"
#include "amdgpu_ps4_uvd_ring_plan.h"
/* IB_DATA_INCLUDE_BEGIN */
#include "amdgpu_ps4_uvd_ib_data_plan.h"
/* IB_DATA_INCLUDE_END */
#include "amdgpu_reset.h"
#include "atom.h"
#include "atombios.h"
#include "uvd/uvd_5_0_d.h"
#include "uvd/uvd_5_0_sh_mask.h"
#include "oss/oss_2_0_d.h"
#include "oss/oss_2_0_sh_mask.h"
#include "gmc/gmc_7_1_d.h"

#define PS4_READY_FW "orbis/liverpool_uvd.bin"

/* rmux: a deferred start runs after SDMA/accel are up; report them as off then. */
static inline bool ps4_boot_buffer_funcs(struct amdgpu_device *adev)
{
	return amdgpu_ps4_uvd_deferred_active() ? false : adev->mman.buffer_funcs_enabled;
}
static inline bool ps4_boot_accel(struct amdgpu_device *adev)
{
	return amdgpu_ps4_uvd_deferred_active() ? false : adev->accel_working;
}
#define PS4_READY_FW_BYTES 314168U
#define PS4_READY_PAYLOAD_BYTES 313912U
#define PS4_READY_PAYLOAD_OFFSET 256U
#define PS4_READY_FW_VERSION 0x012a6509U
#define PS4_READY_PAYLOAD_CRC 0xa465ba07U /* FW 12.00/12.02 */
#define PS4_READY_PAYLOAD_CRC_1250 0x1c5fb4fcU /* FW 12.50 */
#define PS4_READY_R1_BYTES 0x1e0000U
#define PS4_READY_BACKING_BYTES 0x308000U
#define PS4_READY_VCPU_VA 0x300000000ULL
#define PS4_READY_RB_VA 0x300308000ULL
#define PS4_READY_IB_VA 0x30030a000ULL
#define PS4_READY_BIT 2U /* VCPU_REPORT convention used by public v5/v6 start */
#define PS4_READY_LIMIT_NS (2ULL * NSEC_PER_SEC)
#define PS4_READY_HOLD (UVD_SOFT_RESET__LMI_SOFT_RESET_MASK | \
	UVD_SOFT_RESET__VCPU_SOFT_RESET_MASK | \
	UVD_SOFT_RESET__RBC_SOFT_RESET_MASK | \
	UVD_SOFT_RESET__LMI_UMC_SOFT_RESET_MASK)

/* Cross-generation candidate, not a proved Liverpool register contract:
 * Linux a2de78ee6ed8bf8cd99d177c74865a6e8c3cb6ea,
 * vcn/vcn_1_0_offset.h names UVD_LMI_VCPU_CACHE_VMID at 0x053c;
 * vcn_1_0_sh_mask.h defines mask 0xf, shift 0. Five shared UVD6 anchors
 * have the same +0x3800 difference, predicting classic offset 0x3d3c.
 * Public GPL 0060 also writes its low nibble, default 4; its clock-divider
 * label is not adopted. No public callsite establishes Liverpool semantics.
 * EXP007 did not sample this register: initial nibble 14 is a hypothesis
 * precondition, distinct from the observed UMC fault's VMID 14.
 */
#define PS4_READY_UVD_VCPU_CACHE_VMID 0x3d3cU
#define PS4_READY_UVD_VCPU_CACHE_VMID_MASK 0xfU
#define PS4_READY_UVD_VCPU_CACHE_VMID_INITIAL 14U
#define PS4_READY_UVD_VCPU_CACHE_VMID_OWNED 4U

static bool ps4_uvd_ready;
module_param_named(ps4_uvd_ready, ps4_uvd_ready, bool, 0444);
MODULE_PARM_DESC(ps4_uvd_ready,
	"Private one-shot PS4 UVD VCPU readiness probe; always parks boot (default 0)");

/* Separate default-off observation policy. It never enables ring fetch or
 * interrupts. Only the post-release poll may observe raw MASTINT 0 or 2.
 * Held and RBC-release checks retain the original strict predicate.
 */
static bool ps4_uvd_poll_state;
module_param_named(ps4_uvd_poll_state, ps4_uvd_poll_state, bool, 0444);
MODULE_PARM_DESC(ps4_uvd_poll_state,
	"Observe PS4 ready convention with poll MASTINT 0/2; requires ps4_uvd_ready, always parks (default 0)");

/* Private immutable boot gate; requires ready+poll_state, never runtime. */
static bool ps4_uvd_token;
module_param_named(ps4_uvd_token, ps4_uvd_token, bool, 0444);
MODULE_PARM_DESC(ps4_uvd_token,
	"One PS4 UVD context-token hypothesis; requires ready+poll_state, always parks (default 0)");

/* Separate default-off immutable main-ring DATA0 readback control. */
static bool ps4_uvd_data_control;
module_param_named(ps4_uvd_data_control, ps4_uvd_data_control, bool, 0444);
MODULE_PARM_DESC(ps4_uvd_data_control,
	"One PS4 UVD DATA0 readback control; requires token+ready+poll_state, always parks (default 0)");

/* Separate default-off immutable PS4 UVD status-transition observation. */
static bool ps4_uvd_status_observation;
module_param_named(ps4_uvd_status_observation, ps4_uvd_status_observation, bool, 0444);
MODULE_PARM_DESC(ps4_uvd_status_observation,
	"One PS4 UVD STATUS bit16 transition observation of the EXP005 DATA0 packet; requires token+ready+poll_state, records bit16, never accepts (default 0)");

/* IB_DATA_PARAMETER_BEGIN */
/* Immutable default-off boot diagnostic; all outcomes retain and park. */
static bool ps4_uvd_ib_data;
module_param_named(ps4_uvd_ib_data, ps4_uvd_ib_data, bool, 0444);
MODULE_PARM_DESC(ps4_uvd_ib_data,
	"One PS4 UVD IB-only DATA0 marker; requires token+ready+poll_state, excludes data_control/status_observation, always parks (default 0)");

bool amdgpu_ps4_uvd_ib_data_requested(void)
{
	return ps4_uvd_ib_data;
}
/* IB_DATA_PARAMETER_END */

/* MESSAGE_CREATE_PARAMETER_BEGIN */
/* Immutable boot-only gate; no live endpoint or repeated submission. */
static bool ps4_uvd_message_create;
module_param_named(ps4_uvd_message_create, ps4_uvd_message_create, bool, 0444);
MODULE_PARM_DESC(ps4_uvd_message_create,
	"One PS4 UVD public CREATE plus polled prefix fence; requires ready+poll_state, excludes all other probes, always parks (default 0)");

bool amdgpu_ps4_uvd_message_create_requested(void)
{
	return ps4_uvd_message_create;
}

bool amdgpu_ps4_uvd_message_create_options_valid(struct amdgpu_device *adev)
{
	return ps4_uvd_ready && ps4_uvd_poll_state && !ps4_uvd_token &&
		!ps4_uvd_data_control && !ps4_uvd_status_observation &&
		!ps4_uvd_ib_data && !amdgpu_ps4_live_prepare_enabled(adev) &&
		amdgpu_ps4_uvd_ready_enabled(adev);
}
/* MESSAGE_CREATE_PARAMETER_END */

/* DECODE_FRAME_PARAMETER_BEGIN */
/* Immutable, exclusive boot-only one-picture driver bring-up. */
static bool ps4_uvd_decode_frame;
module_param_named(ps4_uvd_decode_frame, ps4_uvd_decode_frame, bool, 0444);
MODULE_PARM_DESC(ps4_uvd_decode_frame,
	"One PS4 UVD CREATE/DECODE/DESTROY reference picture; requires ready+poll_state, excludes all older probes, always parks (default 0)");

bool amdgpu_ps4_uvd_decode_frame_requested(void)
{
	return ps4_uvd_decode_frame;
}

bool amdgpu_ps4_uvd_decode_frame_options_valid(struct amdgpu_device *adev)
{
	return ps4_uvd_ready && ps4_uvd_poll_state && !ps4_uvd_token &&
		!ps4_uvd_data_control && !ps4_uvd_status_observation &&
		!ps4_uvd_ib_data && !ps4_uvd_message_create &&
		!amdgpu_ps4_live_prepare_enabled(adev) &&
		amdgpu_ps4_uvd_ready_enabled(adev);
}
/* DECODE_FRAME_PARAMETER_END */

bool amdgpu_ps4_uvd_token_requested(void)
{
	return ps4_uvd_token;
}

static atomic_t ps4_ready_attempted = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(ps4_ready_park_queue);
/* Retained operation/firmware now belongs to adev; admission stays global. */

/* A preparation-only boot rejects every legacy probe switch. */
bool amdgpu_ps4_uvd_boot_probe_requested(void)
{
	return ps4_uvd_ready || ps4_uvd_poll_state || ps4_uvd_token ||
		ps4_uvd_data_control || ps4_uvd_status_observation ||
		ps4_uvd_ib_data || ps4_uvd_message_create || ps4_uvd_decode_frame;
}

bool amdgpu_ps4_uvd_ready_requested(void)
{
	return ps4_uvd_ready;
}

bool amdgpu_ps4_uvd_ready_enabled(struct amdgpu_device *adev)
{
	return ps4_uvd_ready && IS_BUILTIN(CONFIG_DRM_AMDGPU) &&
		IS_ENABLED(CONFIG_X86_PS4) &&
		(adev->asic_type == CHIP_LIVERPOOL ||
		 adev->asic_type == CHIP_GLADIUS);
}

static __noreturn void ps4_ready_park(struct amdgpu_device *adev,
				    const char *result, int error)
{
	amdgpu_ps4_uvd_irq_report(adev);
	dev_err(adev->dev,
		"PS4_UVD_READY RESULT=%s error=%d PARKED retained; full poweroff required, no retry/reset/cleanup\n",
		result, error);
	for (;;)
		wait_event_idle(ps4_ready_park_queue, false);
}

/* Pure bounds/header/CRC validation, also exercised by synthetic host fixtures.
 * No firmware header is trusted before the 32-byte common header is bounded.
 * The staged exact-file hash is an operator/package contract, not a substitute
 * for runtime validation. No other ASIC image or differently sized member fits.
 */
static int ps4_ready_validate_firmware(const u8 *data, size_t size,
				     u32 *payload_crc)
{
	u32 offset, bytes, crc;

	if (!data || !payload_crc || size != PS4_READY_FW_BYTES || size < 32)
		return -EINVAL;
	if (get_unaligned_le32(data) != size ||
	    get_unaligned_le32(data + 4) != 32 ||
	    get_unaligned_le16(data + 8) != 1 ||
	    get_unaligned_le16(data + 10) != 0 ||
	    get_unaligned_le16(data + 12) != 4 ||
	    get_unaligned_le16(data + 14) != 2 ||
	    get_unaligned_le32(data + 16) != PS4_READY_FW_VERSION)
		return -EINVAL;
	offset = get_unaligned_le32(data + 24);
	bytes = get_unaligned_le32(data + 20);
	if (offset != PS4_READY_PAYLOAD_OFFSET ||
	    bytes != PS4_READY_PAYLOAD_BYTES || offset > size ||
	    bytes > size - offset || bytes > PS4_READY_R1_BYTES ||
	    bytes > 0x7d000U || offset + bytes != size)
		return -ERANGE;
	crc = crc32_le(~0U, data + offset, bytes) ^ ~0U;
	if (crc != get_unaligned_le32(data + 28) ||
	    (crc != PS4_READY_PAYLOAD_CRC && crc != PS4_READY_PAYLOAD_CRC_1250))
		return -EBADMSG;
	*payload_crc = crc;
	return 0;
}

/* Bounded counterpart of atom.c:amdgpu_atom_parse_cmd_header. This validates
 * the existing command table only; it does not execute Atom a second time.
 * amdgpu_atombios_get_clock_dividers supplies post_divider only for crev4/6.
 * The normal Atom interpreter remains responsible for executing its bytecode.
 */
static int ps4_ready_validate_atom_table(const u8 *bios, size_t size,
				       u32 master, u32 index)
{
	u32 slot, table, length;

	if (!bios || master > size || size - master < 4 ||
	    index > (U32_MAX - 4) / 2)
		return -EINVAL;
	slot = 4 + index * 2;
	length = get_unaligned_le16(bios + master);
	if (length < 4 || length > size - master ||
	    slot > length || length - slot < 2)
		return -ERANGE;
	table = get_unaligned_le16(bios + master + slot);
	if (!table || table > size || size - table < ATOM_CT_CODE_PTR)
		return -ERANGE;
	length = get_unaligned_le16(bios + table);
	if (length <= ATOM_CT_CODE_PTR || length > size - table)
		return -ERANGE;
	if (bios[table + 3] != 4 && bios[table + 3] != 6)
		return -EOPNOTSUPP;
	return 0;
}

static int ps4_ready_clock_preflight(struct amdgpu_device *adev)
{
	struct atom_context *ctx = adev->mode_info.atom_context;
	int index = GetIndexIntoMasterTable(COMMAND, ComputeMemoryEnginePLL);

	if (!adev->asic_funcs || !adev->asic_funcs->set_uvd_clocks ||
	    !adev->reg.smc.rreg || !adev->reg.smc.wreg ||
	    !adev->reg.uvd_ctx.rreg || !adev->reg.uvd_ctx.wreg ||
	    !adev->bios || !ctx || ctx->bios != adev->bios || !ctx->card ||
	    !ctx->card->reg_read || !ctx->card->reg_write ||
	    !ctx->card->mc_read || !ctx->card->mc_write ||
	    !ctx->card->pll_read || !ctx->card->pll_write || !ctx->iio)
		return -EINVAL;
	return ps4_ready_validate_atom_table(adev->bios, adev->bios_size,
					     ctx->cmd_table, index);
}

/* Preserve the indexed selector, including across read/modify/write. */
static u32 ps4_ready_ctx(struct amdgpu_device *adev, u32 index,
			u32 preserve, u32 bits, bool write)
{
	unsigned long flags;
	u32 saved, value;

	spin_lock_irqsave(&adev->reg.uvd_ctx.lock, flags);
	saved = RREG32(mmUVD_CTX_INDEX);
	WREG32(mmUVD_CTX_INDEX, index);
	value = RREG32(mmUVD_CTX_DATA);
	if (write) {
		value = (value & preserve) | bits;
		WREG32(mmUVD_CTX_DATA, value);
	}
	WREG32(mmUVD_CTX_INDEX, saved);
	spin_unlock_irqrestore(&adev->reg.uvd_ctx.lock, flags);
	return value;
}

static void ps4_ready_snapshot(struct amdgpu_device *adev, const char *phase)
{
	dev_info(adev->dev,
		"PS4_UVD_READY SNAP %s status=%08x reset=%08x lmi2=%08x int=%08x vcpu=%08x rbc=%08x "
		"vcpu_cache_candidate=%08x\n",
		phase, RREG32(mmUVD_STATUS), RREG32(mmUVD_SOFT_RESET),
		RREG32(mmUVD_LMI_CTRL2), RREG32(mmUVD_MASTINT_EN),
		RREG32(mmUVD_VCPU_CNTL), RREG32(mmUVD_RBC_RB_CNTL),
		RREG32(PS4_READY_UVD_VCPU_CACHE_VMID));
	dev_info(adev->dev,
		"PS4_UVD_READY VMID %s int=%08x int2=%08x int3=%08x cache=%08x rb=%08x ib=%08x\n",
		phase, ps4_ready_ctx(adev, ixUVD_LMI_VMID_INTERNAL, 0, 0, false),
		ps4_ready_ctx(adev, ixUVD_LMI_VMID_INTERNAL2, 0, 0, false),
		ps4_ready_ctx(adev, ixUVD_LMI_VMID_INTERNAL3, 0, 0, false),
		ps4_ready_ctx(adev, ixUVD_LMI_CACHE_CTRL, 0, 0, false),
		RREG32(mmUVD_LMI_RBC_RB_VMID), RREG32(mmUVD_LMI_RBC_IB_VMID));
	dev_info(adev->dev,
		"PS4_UVD_READY BAR %s vcpu=%08x:%08x rb=%08x:%08x ib=%08x:%08x ib_size=%08x\n",
		phase, RREG32(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_HIGH),
		RREG32(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_LOW),
		RREG32(mmUVD_LMI_RBC_RB_64BIT_BAR_HIGH),
		RREG32(mmUVD_LMI_RBC_RB_64BIT_BAR_LOW),
		RREG32(mmUVD_LMI_RBC_IB_64BIT_BAR_HIGH),
		RREG32(mmUVD_LMI_RBC_IB_64BIT_BAR_LOW), RREG32(mmUVD_RBC_IB_SIZE));
	dev_info(adev->dev,
		"PS4_UVD_READY CACHE %s off_size=%08x/%08x,%08x/%08x,%08x/%08x rp=%08x wp=%08x\n",
		phase, RREG32(mmUVD_VCPU_CACHE_OFFSET0), RREG32(mmUVD_VCPU_CACHE_SIZE0),
		RREG32(mmUVD_VCPU_CACHE_OFFSET1), RREG32(mmUVD_VCPU_CACHE_SIZE1),
		RREG32(mmUVD_VCPU_CACHE_OFFSET2), RREG32(mmUVD_VCPU_CACHE_SIZE2),
		RREG32(mmUVD_RBC_RB_RPTR), RREG32(mmUVD_RBC_RB_WPTR));
}

/* Source-only observability draft. Field bits identify values actually read;
 * zero in an unread field is not a sampled register value. Preserve dev3's
 * MMIO order and short circuit: RBC, interrupt mask, IB size, WPTR, RPTR.
 */
enum ps4_ready_guard_field {
	PS4_GUARD_RBC = 1U << 0,
	PS4_GUARD_INT = 1U << 1,
	PS4_GUARD_IB = 1U << 2,
	PS4_GUARD_WP = 1U << 3,
	PS4_GUARD_RP = 1U << 4,
};

enum ps4_ready_guard_failure {
	PS4_GUARD_FETCH = 1U << 0,
	PS4_GUARD_UPDATE = 1U << 1,
	PS4_GUARD_VCPU = 1U << 2,
	PS4_GUARD_SYS = 1U << 3,
	PS4_GUARD_IB_NONZERO = 1U << 4,
	PS4_GUARD_WP_NONZERO = 1U << 5,
	PS4_GUARD_RP_NONZERO = 1U << 6,
	PS4_GUARD_INT_UNKNOWN = 1U << 7,
	PS4_GUARD_INT_REGRESSION = 1U << 8,
};

static bool ps4_ready_fetch_guard_sample(struct amdgpu_device *adev,
					struct ps4_ready_guard_sample *sample,
					bool permit_observed_vcpu)
{
	*sample = (struct ps4_ready_guard_sample) { 0 };
	sample->rbc = RREG32(mmUVD_RBC_RB_CNTL);
	sample->sampled |= PS4_GUARD_RBC;
	if (!(sample->rbc & UVD_RBC_RB_CNTL__RB_NO_FETCH_MASK))
		sample->failed |= PS4_GUARD_FETCH;
	if (!(sample->rbc & UVD_RBC_RB_CNTL__RB_NO_UPDATE_MASK))
		sample->failed |= PS4_GUARD_UPDATE;
	if (sample->failed)
		return false;

	sample->mastint = RREG32(mmUVD_MASTINT_EN);
	sample->sampled |= PS4_GUARD_INT;
	if ((sample->mastint & UVD_MASTINT_EN__VCPU_EN_MASK) &&
	    !permit_observed_vcpu)
		sample->failed |= PS4_GUARD_VCPU;
	if (sample->mastint & UVD_MASTINT_EN__SYS_EN_MASK)
		sample->failed |= PS4_GUARD_SYS;
	/* In the new poll policy, only exact raw 0/2 are admitted. This is
	 * an observed-state hypothesis, not an interrupt-direction claim.
	 */
	if (permit_observed_vcpu &&
	    (sample->mastint & ~(UVD_MASTINT_EN__VCPU_EN_MASK |
				 UVD_MASTINT_EN__SYS_EN_MASK)))
		sample->failed |= PS4_GUARD_INT_UNKNOWN;
	if (sample->failed)
		return false;

	sample->ib_size = RREG32(mmUVD_RBC_IB_SIZE);
	sample->sampled |= PS4_GUARD_IB;
	if (sample->ib_size) {
		sample->failed = PS4_GUARD_IB_NONZERO;
		return false;
	}

	sample->wptr = RREG32(mmUVD_RBC_RB_WPTR);
	sample->sampled |= PS4_GUARD_WP;
	if (sample->wptr) {
		sample->failed = PS4_GUARD_WP_NONZERO;
		return false;
	}

	sample->rptr = RREG32(mmUVD_RBC_RB_RPTR);
	sample->sampled |= PS4_GUARD_RP;
	if (sample->rptr) {
		sample->failed = PS4_GUARD_RP_NONZERO;
		return false;
	}
	return true;
}

static void ps4_ready_guard_log(struct amdgpu_device *adev, const char *phase,
			       const struct ps4_ready_guard_sample *sample)
{
	/* A preceding outer condition may have skipped this guard entirely, or
	 * a later one may have failed after the guard passed. Neither is a guard
	 * failure. Callers clear the sample before a potentially skipped guard.
	 */
	if (!sample->sampled || !sample->failed)
		return;
	/* Call only after existing caller snapshots and immediately before its
	 * held terminal. Those snapshots are later, non-atomic observations;
	 * these saved values decided the guard and require no extra UVD reads.
	 */
	dev_err(adev->dev,
		"PS4_UVD_READY GUARD_DECISION phase=%s sampled=%02x failed=%02x rbc=%08x int=%08x ib=%08x wp=%08x rp=%08x\n",
		phase, sample->sampled, sample->failed, sample->rbc, sample->mastint,
		sample->ib_size, sample->wptr, sample->rptr);
}

/* Read and log before any setup write; a different initial selector refutes
 * this experiment's precondition and is terminal, not an alternate VMID test.
 */
static int ps4_ready_cache_vmid_preflight(struct amdgpu_device *adev,
					u32 *original)
{
	*original = RREG32(PS4_READY_UVD_VCPU_CACHE_VMID);
	dev_info(adev->dev,
		"PS4_UVD_READY CACHE_VMID_CANDIDATE before=%08x mask=%08x expected_initial=14 owned=4; cross-generation hypothesis\n",
		*original, PS4_READY_UVD_VCPU_CACHE_VMID_MASK);
	if ((*original & PS4_READY_UVD_VCPU_CACHE_VMID_MASK) !=
	    PS4_READY_UVD_VCPU_CACHE_VMID_INITIAL)
		return -EINVAL;
	return 0;
}

static u32 ps4_ready_cache_vmid_owned(u32 original)
{
	return (original & ~PS4_READY_UVD_VCPU_CACHE_VMID_MASK) |
		PS4_READY_UVD_VCPU_CACHE_VMID_OWNED;
}

/* Called only after confirmed holds. The entire original word must still
 * match: do not overwrite upper bits that changed during the hold sequence.
 * No release or retry follows any failure; the caller parks with BO/fw held.
 */
static int ps4_ready_cache_vmid_program_held(struct amdgpu_device *adev,
					u32 original)
{
	u32 value = RREG32(PS4_READY_UVD_VCPU_CACHE_VMID);
	u32 expected = ps4_ready_cache_vmid_owned(original);

	if (value != original ||
	    (value & PS4_READY_UVD_VCPU_CACHE_VMID_MASK) !=
	    PS4_READY_UVD_VCPU_CACHE_VMID_INITIAL)
		return -EIO;
	WREG32(PS4_READY_UVD_VCPU_CACHE_VMID, expected);
	value = RREG32(PS4_READY_UVD_VCPU_CACHE_VMID);
	dev_info(adev->dev,
		"PS4_UVD_READY CACHE_VMID_CANDIDATE held before=%08x expected=%08x readback=%08x\n",
		original, expected, value);
	return value == expected ? 0 : -EIO;
}

static int ps4_ready_setup_held(struct amdgpu_device *adev,
				u32 cache_vmid_original)
{
	u32 value;
	int r;

	/* v5 start ordering: mask, stall, initial held reset, scoped SRBM release.
	 * RBC is initially held; its one initial release keeps NO_FETCH set.
	 */
	WREG32(mmUVD_MASTINT_EN, RREG32(mmUVD_MASTINT_EN) &
		~(UVD_MASTINT_EN__VCPU_EN_MASK | UVD_MASTINT_EN__SYS_EN_MASK));
	WREG32(mmUVD_LMI_CTRL2, RREG32(mmUVD_LMI_CTRL2) |
		UVD_LMI_CTRL2__STALL_ARB_UMC_MASK);
	mdelay(1);
	WREG32(mmUVD_SOFT_RESET, RREG32(mmUVD_SOFT_RESET) | PS4_READY_HOLD);
	mdelay(5);
	WREG32(mmSRBM_SOFT_RESET, RREG32(mmSRBM_SOFT_RESET) &
		~SRBM_SOFT_RESET__SOFT_RESET_UVD_MASK);
	mdelay(5);
	/* Establish the held/reset claim BEFORE a clock may change partially. */
	if ((RREG32(mmUVD_SOFT_RESET) & PS4_READY_HOLD) != PS4_READY_HOLD ||
	    !(RREG32(mmUVD_LMI_CTRL2) & UVD_LMI_CTRL2__STALL_ARB_UMC_MASK) ||
	    (RREG32(mmUVD_MASTINT_EN) &
	     (UVD_MASTINT_EN__VCPU_EN_MASK | UVD_MASTINT_EN__SYS_EN_MASK)))
		return -EIO;

	/* The candidate's only new hardware write stays inside confirmed holds,
	 * before clocks, RBC release or UMC unstall. Preserve every upper bit.
	 */
	r = ps4_ready_cache_vmid_program_held(adev, cache_vmid_original);
	if (r)
		return r;

	/* Public uvd_v5_0_hw_init policy; one callback, VCLK then DCLK.
	 * cik.c rejects an unrepresentable divider BEFORE that control write.
	 * A DCLK failure may follow a successful VCLK write: caller parks held.
	 */
	r = amdgpu_asic_set_uvd_clocks(adev, 10000, 10000);
	if (r)
		return r;

	WREG32(mmUVD_CGC_CTRL, RREG32(mmUVD_CGC_CTRL) &
		~UVD_CGC_CTRL__DYN_CLOCK_MODE_MASK);
	WREG32(mmUVD_CGC_GATE, RREG32(mmUVD_CGC_GATE) & 0xfff00008U);
	WREG32(mmUVD_SUVD_CGC_GATE, RREG32(mmUVD_SUVD_CGC_GATE) & 0xffffe000U);
	WREG32(mmUVD_VCPU_CNTL, RREG32(mmUVD_VCPU_CNTL) | UVD_VCPU_CNTL__CLK_EN_MASK);

	/* Public5/6 UDEC uses the current GFX layout. This observed-driver
	 * precondition is 0x02011003; the additional MIF trio remains a hypothesis.
	 */
	value = adev->gfx.config.gb_addr_config;
	WREG32(mmUVD_UDEC_DB_ADDR_CONFIG, value);
	WREG32(mmUVD_UDEC_DBW_ADDR_CONFIG, value);
	WREG32(mmUVD_UDEC_ADDR_CONFIG, value);
	WREG32(mmUVD_MIF_CURR_ADDR_CONFIG, value);
	WREG32(mmUVD_MIF_RECON1_ADDR_CONFIG, value);
	WREG32(mmUVD_MIF_REF_ADDR_CONFIG, value);
	WREG32(mmUVD_LMI_SWAP_CNTL, 0);
	WREG32(mmUVD_MP_SWAP_CNTL, 0);
	/* Historical 0x203108, using public field meanings where defined. */
	value = 8 | UVD_LMI_CTRL__WRITE_CLEAN_TIMER_EN_MASK |
		UVD_LMI_CTRL__MASK_MC_URGENT_MASK |
		UVD_LMI_CTRL__DATA_COHERENCY_EN_MASK |
		UVD_LMI_CTRL__VCPU_DATA_COHERENCY_EN_MASK;
	WREG32(mmUVD_LMI_CTRL, value);
	WREG32(mmUVD_MPC_CNTL, 0x10);
	WREG32(mmUVD_MPC_SET_MUXA0, 0x040c2040);
	WREG32(mmUVD_MPC_SET_MUXA1, 0);
	WREG32(mmUVD_MPC_SET_MUXB0, 0x040c2040);
	WREG32(mmUVD_MPC_SET_MUXB1, 0);
	WREG32(mmUVD_MPC_SET_ALU, 0);
	WREG32(mmUVD_MPC_SET_MUX, 0x88);

	/* Public5/6 requester fields; JPEG/reserved high fields stay unchanged. */
	ps4_ready_ctx(adev, ixUVD_LMI_VMID_INTERNAL, 0xff000000, 0x00444444, true);
	ps4_ready_ctx(adev, ixUVD_LMI_VMID_INTERNAL2, 0, 0x44444444, true);
	ps4_ready_ctx(adev, ixUVD_LMI_VMID_INTERNAL3, 0xffff0000, 0x4444, true);
	WREG32(mmUVD_LMI_RBC_RB_VMID, 4);
	WREG32(mmUVD_LMI_RBC_IB_VMID, 4);

	WREG32(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_LOW, lower_32_bits(PS4_READY_VCPU_VA));
	WREG32(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_HIGH, upper_32_bits(PS4_READY_VCPU_VA));
	WREG32(mmUVD_LMI_ADDR_EXT, 0);
	WREG32(mmUVD_LMI_EXT40_ADDR, 0);
	/* v5/v6 mc_resume: relative offset in eight-byte units; SIZE is BYTES.
	 * [0,7d000), [7d000,bd000), [bd000,1dd800) all fit the owned R1 BO.
	 */
	WREG32(mmUVD_VCPU_CACHE_OFFSET0, 0);
	WREG32(mmUVD_VCPU_CACHE_SIZE0, 0x7d000);
	WREG32(mmUVD_VCPU_CACHE_OFFSET1, 0xfa00);
	WREG32(mmUVD_VCPU_CACHE_SIZE1, 0x40000);
	WREG32(mmUVD_VCPU_CACHE_OFFSET2, 0x17a00);
	WREG32(mmUVD_VCPU_CACHE_SIZE2, 0x120800);

	value = 0;
	value = REG_SET_FIELD(value, UVD_RBC_RB_CNTL, RB_BUFSZ, 12); /* 4KiB */
	value = REG_SET_FIELD(value, UVD_RBC_RB_CNTL, RB_BLKSZ, 8);
	value = REG_SET_FIELD(value, UVD_RBC_RB_CNTL, RB_NO_FETCH, 1);
	value = REG_SET_FIELD(value, UVD_RBC_RB_CNTL, RB_NO_UPDATE, 1);
	value = REG_SET_FIELD(value, UVD_RBC_RB_CNTL, RB_RPTR_WR_EN, 1);
	WREG32(mmUVD_RBC_RB_CNTL, value);
	WREG32(mmUVD_LMI_RBC_RB_64BIT_BAR_LOW, lower_32_bits(PS4_READY_RB_VA));
	WREG32(mmUVD_LMI_RBC_RB_64BIT_BAR_HIGH, upper_32_bits(PS4_READY_RB_VA));
	WREG32(mmUVD_LMI_RBC_IB_64BIT_BAR_LOW, lower_32_bits(PS4_READY_IB_VA));
	WREG32(mmUVD_LMI_RBC_IB_64BIT_BAR_HIGH, upper_32_bits(PS4_READY_IB_VA));
	WREG32(mmUVD_RBC_IB_SIZE, 0);
	WREG32(mmUVD_RBC_RB_WPTR, 0);
	WREG32(mmUVD_RBC_RB_RPTR, 0);
	ps4_ready_ctx(adev, ixUVD_LMI_CACHE_CTRL,
		~UVD_LMI_CACHE_CTRL__VCPU_EN_MASK, 0, true);
	WREG32(mmUVD_VCPU_CNTL, RREG32(mmUVD_VCPU_CNTL) &
		~UVD_VCPU_CNTL__TIMEOUT_DIS_MASK);
	return 0;
}

/* Checked before the initial RBC release/UMC unstall. A field mismatch is a
 * failed compatibility hypothesis, never a reason to try alternative MMIO.
 */
static bool ps4_ready_programmed(struct amdgpu_device *adev,
				 u32 cache_vmid_expected)
{
	return RREG32(PS4_READY_UVD_VCPU_CACHE_VMID) == cache_vmid_expected &&
		(ps4_ready_ctx(adev, ixUVD_LMI_VMID_INTERNAL, 0, 0, false) &
		0x00ffffff) == 0x00444444 &&
		ps4_ready_ctx(adev, ixUVD_LMI_VMID_INTERNAL2, 0, 0, false) == 0x44444444 &&
		(ps4_ready_ctx(adev, ixUVD_LMI_VMID_INTERNAL3, 0, 0, false) &
		0xffff) == 0x4444 &&
		!(ps4_ready_ctx(adev, ixUVD_LMI_CACHE_CTRL, 0, 0, false) &
		  UVD_LMI_CACHE_CTRL__VCPU_EN_MASK) &&
		RREG32(mmUVD_LMI_RBC_RB_VMID) == 4 &&
		RREG32(mmUVD_LMI_RBC_IB_VMID) == 4 &&
		RREG32(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_LOW) == lower_32_bits(PS4_READY_VCPU_VA) &&
		RREG32(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_HIGH) == upper_32_bits(PS4_READY_VCPU_VA) &&
		RREG32(mmUVD_LMI_RBC_RB_64BIT_BAR_LOW) == lower_32_bits(PS4_READY_RB_VA) &&
		RREG32(mmUVD_LMI_RBC_RB_64BIT_BAR_HIGH) == upper_32_bits(PS4_READY_RB_VA) &&
		RREG32(mmUVD_LMI_RBC_IB_64BIT_BAR_LOW) == lower_32_bits(PS4_READY_IB_VA) &&
		RREG32(mmUVD_LMI_RBC_IB_64BIT_BAR_HIGH) == upper_32_bits(PS4_READY_IB_VA) &&
		RREG32(mmUVD_VCPU_CACHE_OFFSET0) == 0 &&
		RREG32(mmUVD_VCPU_CACHE_SIZE0) == 0x7d000 &&
		RREG32(mmUVD_VCPU_CACHE_OFFSET1) == 0xfa00 &&
		RREG32(mmUVD_VCPU_CACHE_SIZE1) == 0x40000 &&
		RREG32(mmUVD_VCPU_CACHE_OFFSET2) == 0x17a00 &&
		RREG32(mmUVD_VCPU_CACHE_SIZE2) == 0x120800 &&
		RREG32(mmUVD_RBC_IB_SIZE) == 0 &&
		RREG32(mmUVD_RBC_RB_WPTR) == 0 && RREG32(mmUVD_RBC_RB_RPTR) == 0 &&
		(RREG32(mmUVD_RBC_RB_CNTL) &
		 (UVD_RBC_RB_CNTL__RB_NO_FETCH_MASK | UVD_RBC_RB_CNTL__RB_NO_UPDATE_MASK)) ==
		(UVD_RBC_RB_CNTL__RB_NO_FETCH_MASK | UVD_RBC_RB_CNTL__RB_NO_UPDATE_MASK);
}

/* TOKEN_FLOW_BEGIN: extracted verbatim by the host fixture. */
#define PS4_TOKEN_BASELINE 0x43505532U
#define PS4_TOKEN_VALUE 0x55564432U
#define PS4_TOKEN_LIMIT_NS (250ULL * NSEC_PER_MSEC)
#define PS4_TOKEN_RBC_HELD 0x1101080cU
#define PS4_TOKEN_RBC_FETCH 0x1100080cU

enum ps4_token_phase { PS4_TOKEN_HELD, PS4_TOKEN_EMPTY, PS4_TOKEN_SUBMITTED };

struct ps4_token_sample {
	u32 status, mastint, rbc, ib_size, wptr, rptr, context;
	u32 wptr_cntl, rptr_addr, fault, reset_count, in_reset, pd;
	u32 bad_kind, bad_reg, bad_value, bad_mask, bad_expected;
	bool failed;
};

static bool ps4_token_descriptor_valid(const struct amdgpu_ps4_uvd_ring *rb)
{
	return rb && rb->cpu && !((unsigned long)rb->cpu & 3U) &&
		(unsigned long)rb->cpu <= ~0UL - (PS4_UVD_RING_BYTES - 1U) &&
		rb->bytes == PS4_UVD_RING_BYTES && rb->private_va == PS4_READY_RB_VA;
}

/* Save the first deciding value. kind: 0=MMIO, 1=indexed UVD, 2=driver,
 * 3=MMIO upper bound. No later snapshot is substituted for this evidence.
 */
static bool ps4_token_expect(struct ps4_token_sample *s, u32 kind, u32 reg,
			     u32 value, u32 mask, u32 expected)
{
	if ((value & mask) == expected)
		return true;
	s->failed = true;
	s->bad_kind = kind;
	s->bad_reg = reg;
	s->bad_value = value;
	s->bad_mask = mask;
	s->bad_expected = expected;
	return false;
}

static bool ps4_token_sample(struct amdgpu_device *adev,
			    struct ps4_token_sample *s, enum ps4_token_phase phase,
			    u64 pd_addr, u32 cache_vmid, u32 fault_base, int reset_base)
{
	u32 value;

	*s = (struct ps4_token_sample) { 0 };
	/* Every field printed by CORE is sampled, even on an early rejection. */
	s->status = RREG32(mmUVD_STATUS);
	s->mastint = RREG32(mmUVD_MASTINT_EN);
	s->rbc = RREG32(mmUVD_RBC_RB_CNTL);
	s->ib_size = RREG32(mmUVD_RBC_IB_SIZE);
	s->wptr = RREG32(mmUVD_RBC_RB_WPTR);
	s->rptr = RREG32(mmUVD_RBC_RB_RPTR);
	s->context = RREG32(mmUVD_CONTEXT_ID);
	s->wptr_cntl = RREG32(mmUVD_RBC_RB_WPTR_CNTL);
	s->rptr_addr = RREG32(mmUVD_RBC_RB_RPTR_ADDR);
	s->fault = RREG32(mmVM_CONTEXT1_PROTECTION_FAULT_STATUS);
	s->reset_count = atomic_read(&adev->gpu_reset_counter);
	s->in_reset = amdgpu_in_reset(adev);
	s->pd = RREG32(mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR + 4);
#define TOKEN_SAVED(reg, got, want) \
	if (!ps4_token_expect(s, 0, reg, got, ~0U, want)) return false
	/* Public UVD5 names bit0 RBC_BUSY; tolerate only after fetch. This
	 * comparison does not prove Liverpool busy semantics or DMA quiescence.
	 */
	if (!ps4_token_expect(s, 0, mmUVD_STATUS, s->status,
		phase == PS4_TOKEN_HELD ? ~0U : ~(u32)UVD_STATUS__RBC_BUSY_MASK,
		PS4_READY_BIT))
		return false;
	TOKEN_SAVED(mmUVD_MASTINT_EN, s->mastint, UVD_MASTINT_EN__VCPU_EN_MASK);
	TOKEN_SAVED(mmUVD_RBC_RB_CNTL, s->rbc,
		phase == PS4_TOKEN_HELD ? PS4_TOKEN_RBC_HELD : PS4_TOKEN_RBC_FETCH);
	TOKEN_SAVED(mmUVD_RBC_IB_SIZE, s->ib_size, 0);
	TOKEN_SAVED(mmUVD_RBC_RB_WPTR_CNTL, s->wptr_cntl, 0);
	TOKEN_SAVED(mmUVD_RBC_RB_RPTR_ADDR, s->rptr_addr, 0);
	TOKEN_SAVED(mmUVD_RBC_RB_WPTR, s->wptr,
		phase == PS4_TOKEN_SUBMITTED ? PS4_UVD_SUBMIT_DWORDS : 0);
	if (phase != PS4_TOKEN_SUBMITTED) {
		TOKEN_SAVED(mmUVD_RBC_RB_RPTR, s->rptr, 0);
	} else if (s->rptr > PS4_UVD_SUBMIT_DWORDS) {
		return ps4_token_expect(s, 3, mmUVD_RBC_RB_RPTR,
					s->rptr, ~0U, PS4_UVD_SUBMIT_DWORDS);
	}
	TOKEN_SAVED(mmVM_CONTEXT1_PROTECTION_FAULT_STATUS, s->fault, fault_base);
	TOKEN_SAVED(mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR + 4, s->pd, pd_addr >> 12);
	if (!ps4_token_expect(s, 2, 1, s->reset_count, ~0U, reset_base) ||
	    !ps4_token_expect(s, 2, 2, s->in_reset, ~0U, 0) ||
	    !ps4_token_expect(s, 2, 3, ps4_boot_buffer_funcs(adev), ~0U, 0) ||
	    !ps4_token_expect(s, 2, 4, ps4_boot_accel(adev), ~0U, 0))
		return false;
#define TOKEN_REG(reg, mask, want) \
	if (!ps4_token_expect(s, 0, reg, RREG32(reg), mask, want)) return false
	TOKEN_REG(PS4_READY_UVD_VCPU_CACHE_VMID, ~0U, cache_vmid);
	TOKEN_REG(mmUVD_LMI_RBC_RB_VMID, ~0U, 4);
	TOKEN_REG(mmUVD_LMI_RBC_IB_VMID, ~0U, 4);
	TOKEN_REG(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_LOW, ~0U, lower_32_bits(PS4_READY_VCPU_VA));
	TOKEN_REG(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_HIGH, ~0U, upper_32_bits(PS4_READY_VCPU_VA));
	TOKEN_REG(mmUVD_LMI_RBC_RB_64BIT_BAR_LOW, ~0U, lower_32_bits(PS4_READY_RB_VA));
	TOKEN_REG(mmUVD_LMI_RBC_RB_64BIT_BAR_HIGH, ~0U, upper_32_bits(PS4_READY_RB_VA));
	TOKEN_REG(mmUVD_LMI_RBC_IB_64BIT_BAR_LOW, ~0U, lower_32_bits(PS4_READY_IB_VA));
	TOKEN_REG(mmUVD_LMI_RBC_IB_64BIT_BAR_HIGH, ~0U, upper_32_bits(PS4_READY_IB_VA));
	TOKEN_REG(mmUVD_VCPU_CACHE_OFFSET0, ~0U, 0);
	TOKEN_REG(mmUVD_VCPU_CACHE_SIZE0, ~0U, 0x7d000);
	TOKEN_REG(mmUVD_VCPU_CACHE_OFFSET1, ~0U, 0xfa00);
	TOKEN_REG(mmUVD_VCPU_CACHE_SIZE1, ~0U, 0x40000);
	TOKEN_REG(mmUVD_VCPU_CACHE_OFFSET2, ~0U, 0x17a00);
	TOKEN_REG(mmUVD_VCPU_CACHE_SIZE2, ~0U, 0x120800);
	TOKEN_REG(mmUVD_LMI_SWAP_CNTL, ~0U, 0);
	TOKEN_REG(mmUVD_MP_SWAP_CNTL, ~0U, 0);
	TOKEN_REG(mmUVD_LMI_ADDR_EXT, ~0U, 0);
	TOKEN_REG(mmUVD_LMI_EXT40_ADDR, ~0U, 0);
	TOKEN_REG(mmUVD_SOFT_RESET, PS4_READY_HOLD, 0);
	TOKEN_REG(mmUVD_LMI_CTRL2, UVD_LMI_CTRL2__STALL_ARB_UMC_MASK, 0);
#define TOKEN_CTX(index, mask, want) do { \
	value = ps4_ready_ctx(adev, index, 0, 0, false); \
	if (!ps4_token_expect(s, 1, index, value, mask, want)) return false; \
} while (0)
	TOKEN_CTX(ixUVD_LMI_VMID_INTERNAL, 0x00ffffff, 0x00444444);
	TOKEN_CTX(ixUVD_LMI_VMID_INTERNAL2, ~0U, 0x44444444);
	TOKEN_CTX(ixUVD_LMI_VMID_INTERNAL3, 0xffff, 0x4444);
	TOKEN_CTX(ixUVD_LMI_CACHE_CTRL, UVD_LMI_CACHE_CTRL__VCPU_EN_MASK, 0);
#undef TOKEN_CTX
#undef TOKEN_REG
#undef TOKEN_SAVED
	return true;
}

static __noreturn void ps4_token_stop(struct amdgpu_device *adev,
	const char *result, int error, const struct ps4_token_sample *s,
	bool enabled, bool submitted, u64 elapsed)
{
	if (s) {
		dev_err(adev->dev,
			"PS4_UVD_TOKEN CORE sampled=all status=%08x int=%08x rbc=%08x ib=%08x wp=%08x rp=%08x ctx=%08x wpc=%08x rpa=%08x fault=%08x reset=%u in_reset=%u pd=%08x\n",
			s->status, s->mastint, s->rbc, s->ib_size, s->wptr, s->rptr,
			s->context, s->wptr_cntl, s->rptr_addr, s->fault,
			s->reset_count, s->in_reset, s->pd);
		if (s->failed)
			dev_err(adev->dev,
				"PS4_UVD_TOKEN GUARD kind=%u reg=%08x value=%08x mask=%08x expected=%08x; saved deciding read\n",
				s->bad_kind, s->bad_reg, s->bad_value, s->bad_mask, s->bad_expected);
	}
	dev_info(adev->dev,
		"PS4_UVD_TOKEN END result=%s enabled=%d submitted=%d elapsed_us=%llu; IRQ cut observational, retained, no quiescence/decode claim\n",
		result, enabled, submitted, div_u64(elapsed, 1000));
	ps4_ready_park(adev, result, error);
}

/* This fixed token is single-attempt only. Do not reuse it in a later
 * accepted boot or advertise transport support from this one experiment.
 */
static __noreturn void ps4_token_run(struct amdgpu_device *adev,
	const struct amdgpu_ps4_uvd_ring *rb, u64 pd_addr, u32 cache_vmid,
	u32 fault_base, int reset_base)
{
	struct ps4_uvd_ring_plan plan;
	struct ps4_uvd_ring_request request;
	struct ps4_token_sample sample;
	u64 started, elapsed;
	u32 baseline_readback;
	bool valid;

	if (!ps4_uvd_token || !ps4_uvd_ready || !ps4_uvd_poll_state ||
	    !ps4_token_descriptor_valid(rb) || !pd_addr ||
	    (pd_addr & 0xfff) || (pd_addr >> 12) > U32_MAX)
		ps4_token_stop(adev, "TOKEN_DESCRIPTOR_OR_GATES", -EINVAL, NULL, false, false, 0);
	if (!ps4_token_sample(adev, &sample, PS4_TOKEN_HELD, pd_addr,
			      cache_vmid, fault_base, reset_base))
		ps4_token_stop(adev, "TOKEN_PRECONDITION", -EIO, &sample, false, false, 0);
	request = (struct ps4_uvd_ring_request) {
		.gpu_base = rb->private_va, .baseline = PS4_TOKEN_BASELINE,
		.token = PS4_TOKEN_VALUE, .context_before_baseline = sample.context,
		.initial_rptr_raw = sample.rptr, .initial_wptr_raw = sample.wptr,
	};
	if (ps4_uvd_build_ring(rb->cpu, rb->bytes, request, &plan) != PS4_UVD_PLAN_OK)
		ps4_token_stop(adev, "TOKEN_PLAN_REJECTED", -EINVAL, &sample, false, false, 0);
	dev_info(adev->dev,
		"PS4_UVD_TOKEN PREPARED bytes=4096 submit_dw=16 va=%llx baseline=%08x token=%08x crc=%08x; BLKSZ8 and DWORD units are hypotheses\n",
		rb->private_va, PS4_TOKEN_BASELINE, PS4_TOKEN_VALUE,
		crc32_le(~0U, rb->cpu, rb->bytes) ^ ~0U);
	WREG32(mmUVD_CONTEXT_ID, PS4_TOKEN_BASELINE);
	baseline_readback = RREG32(mmUVD_CONTEXT_ID);
	if (baseline_readback != PS4_TOKEN_BASELINE) {
		dev_err(adev->dev,
			"PS4_UVD_TOKEN BASELINE_DIRECT reg=%08x value=%08x expected=%08x; no CORE resample\n",
			mmUVD_CONTEXT_ID, baseline_readback, PS4_TOKEN_BASELINE);
		ps4_token_stop(adev, "TOKEN_BASELINE_READBACK", -EIO, NULL, false, false, 0);
	}
	/* Native x86 APU may return early in the HDP helper; no direct flush added. */
	mb();
	amdgpu_device_flush_hdp(adev, NULL);
	if (!ps4_token_sample(adev, &sample, PS4_TOKEN_HELD, pd_addr,
			      cache_vmid, fault_base, reset_base) ||
	    !ps4_token_expect(&sample, 0, mmUVD_CONTEXT_ID, sample.context,
			      ~0U, PS4_TOKEN_BASELINE))
		ps4_token_stop(adev, "TOKEN_BASELINE_OR_PUBLICATION_GUARD", -EIO, &sample, false, false, 0);
	started = ktime_get_ns();
	WREG32(mmUVD_RBC_RB_CNTL, PS4_TOKEN_RBC_FETCH);
	valid = ps4_token_sample(adev, &sample, PS4_TOKEN_EMPTY, pd_addr,
				cache_vmid, fault_base, reset_base);
	elapsed = ktime_get_ns() - started;
	if (elapsed >= PS4_TOKEN_LIMIT_NS)
		ps4_token_stop(adev, "TOKEN_ENABLE_TIMEOUT", -ETIMEDOUT, &sample, true, false, elapsed);
	if (!valid || !ps4_token_expect(&sample, 0, mmUVD_CONTEXT_ID,
					sample.context, ~0U, PS4_TOKEN_BASELINE))
		ps4_token_stop(adev, "TOKEN_ENABLE_GUARD", -EIO, &sample, true, false, elapsed);
	mb();
	elapsed = ktime_get_ns() - started;
	if (elapsed >= PS4_TOKEN_LIMIT_NS)
		ps4_token_stop(adev, "TOKEN_BEFORE_SUBMIT_TIMEOUT", -ETIMEDOUT, &sample, true, false, elapsed);
	WREG32(mmUVD_RBC_RB_WPTR, plan.publish_wptr_raw);
	dev_info(adev->dev, "PS4_UVD_TOKEN SUBMITTED raw_wptr=16 once; no trap/IB/fence command\n");
	for (;;) {
		valid = ps4_token_sample(adev, &sample, PS4_TOKEN_SUBMITTED,
			pd_addr, cache_vmid, fault_base, reset_base);
		elapsed = ktime_get_ns() - started;
		if (elapsed >= PS4_TOKEN_LIMIT_NS)
			ps4_token_stop(adev, "TOKEN_TIMEOUT", -ETIMEDOUT, &sample, true, true, elapsed);
		if (!valid)
			ps4_token_stop(adev, "TOKEN_SUBMITTED_GUARD", -EIO, &sample, true, true, elapsed);
		if (sample.context != PS4_TOKEN_BASELINE && sample.context != PS4_TOKEN_VALUE) {
			ps4_token_expect(&sample, 0, mmUVD_CONTEXT_ID, sample.context, ~0U, PS4_TOKEN_VALUE);
			ps4_token_stop(adev, "TOKEN_UNEXPECTED_CONTEXT", -EIO, &sample, true, true, elapsed);
		}
		if (sample.context == PS4_TOKEN_VALUE && sample.rptr == PS4_UVD_SUBMIT_DWORDS)
			ps4_token_stop(adev, "TOKEN_TRANSPORT_OBSERVED", 0, &sample, true, true, elapsed);
		/* RPTR16 + old baseline can be a sequential-read race: keep polling. */
		usleep_range(100, 200);
	}
}
/* TOKEN_FLOW_END */

/* DATA_CONTROL_FLOW_BEGIN: extracted verbatim by the host fixture. */
#define PS4_DATA_BASELINE 0x43504435U
#define PS4_DATA_VALUE 0x55564435U
#define PS4_DATA_CONTEXT_BASELINE 0x43504335U
#define PS4_DATA_CONTEXT_VALUE 0x43545835U
#define PS4_DATA_LIMIT_NS (250ULL * NSEC_PER_MSEC)

struct ps4_data_sample {
	struct ps4_token_sample core;
	u32 data;
};

struct ps4_data_progress {
	u32 samples, consecutive, joint_samples, last_rptr;
	bool data_seen, context_seen, transport_seen;
	u64 first_data_ns, first_context_ns, first_joint_ns, first_transport_ns;
};

static bool ps4_data_control_inputs_valid(const struct amdgpu_ps4_uvd_ring *rb,
					  u64 pd_addr)
{
	return ps4_uvd_data_control && ps4_uvd_token && ps4_uvd_ready &&
		ps4_uvd_poll_state && ps4_token_descriptor_valid(rb) && pd_addr &&
		!(pd_addr & 0xfff) && (pd_addr >> 12) <= U32_MAX;
}

/* The unchanged complete CORE read sequence, then DATA0. This is neither an
 * atomic snapshot nor a general readback/persistence contract for DATA0.
 */
static bool ps4_data_sample(struct amdgpu_device *adev,
	struct ps4_data_sample *sample, enum ps4_token_phase phase,
	u64 pd_addr, u32 cache_vmid, u32 fault_base, int reset_base)
{
	bool valid = ps4_token_sample(adev, &sample->core, phase, pd_addr,
				      cache_vmid, fault_base, reset_base);

	sample->data = RREG32(mmUVD_GPCOM_VCPU_DATA0);
	return valid;
}

static bool ps4_data_baselines(struct ps4_data_sample *sample)
{
	return ps4_token_expect(&sample->core, 0, mmUVD_GPCOM_VCPU_DATA0,
			       sample->data, ~0U, PS4_DATA_BASELINE) &&
		ps4_token_expect(&sample->core, 0, mmUVD_CONTEXT_ID,
				 sample->core.context, ~0U, PS4_DATA_CONTEXT_BASELINE);
}

static __noreturn void ps4_data_stop(struct amdgpu_device *adev,
	const char *result, int error, const struct ps4_data_sample *sample,
	const struct ps4_data_progress *progress, bool enabled, bool submitted,
	u64 elapsed)
{
	if (sample) {
		const struct ps4_token_sample *s = &sample->core;

		dev_err(adev->dev,
			"PS4_UVD_DATA CORE sampled=all_then_data0 status=%08x int=%08x rbc=%08x ib=%08x wp=%08x rp=%08x ctx=%08x data=%08x wpc=%08x rpa=%08x fault=%08x reset=%u in_reset=%u pd=%08x\n",
			s->status, s->mastint, s->rbc, s->ib_size, s->wptr, s->rptr,
			s->context, sample->data, s->wptr_cntl, s->rptr_addr, s->fault,
			s->reset_count, s->in_reset, s->pd);
		if (s->failed)
			dev_err(adev->dev,
				"PS4_UVD_DATA GUARD kind=%u reg=%08x value=%08x mask=%08x expected=%08x; saved deciding read\n",
				s->bad_kind, s->bad_reg, s->bad_value, s->bad_mask, s->bad_expected);
	}
	dev_info(adev->dev,
		"PS4_UVD_DATA END result=%s enabled=%d submitted=%d elapsed_ns=%llu samples=%u consecutive=%u joint_samples=%u data_seen=%d context_seen=%d transport_seen=%d last_rptr=%u first_data_ns=%llu first_context_ns=%llu first_joint_ns=%llu first_transport_ns=%llu; times include software/logging, sequential observations, retained, no decode/containment/quiescence claim\n",
		result, enabled, submitted, (unsigned long long)elapsed,
		progress->samples, progress->consecutive, progress->joint_samples,
		progress->data_seen, progress->context_seen, progress->transport_seen, progress->last_rptr,
		(unsigned long long)progress->first_data_ns,
		(unsigned long long)progress->first_context_ns,
		(unsigned long long)progress->first_joint_ns,
		(unsigned long long)progress->first_transport_ns);
	ps4_ready_park(adev, result, error);
}

/* DATA0 is a public parameter/low-address operand, not documented scratch.
 * Only the parameter and a context trailer are submitted: no CMD write, even
 * zero, and no DATA1/IB/fence/trap/ENGINE command. Omitting CMD is not a proof
 * that Liverpool firmware has no side effects. Existing mappings, lifetime,
 * setup and all old token helpers remain unchanged. Every outcome parks.
 */
static __noreturn void ps4_data_control_run(struct amdgpu_device *adev,
	const struct amdgpu_ps4_uvd_ring *rb, u64 pd_addr, u32 cache_vmid,
	u32 fault_base, int reset_base)
{
	struct ps4_uvd_ring_plan plan;
	struct ps4_uvd_ring_request request;
	struct ps4_data_sample sample;
	struct ps4_data_progress progress = { 0 };
	u64 started, elapsed;
	u32 readback;
	bool valid;

	if (!ps4_data_control_inputs_valid(rb, pd_addr))
		ps4_data_stop(adev, "DATA_DESCRIPTOR_OR_GATES", -EINVAL,
			NULL, &progress, false, false, 0);
	if (!ps4_data_sample(adev, &sample, PS4_TOKEN_HELD, pd_addr,
			     cache_vmid, fault_base, reset_base))
		ps4_data_stop(adev, "DATA_PRECONDITION", -EIO,
			&sample, &progress, false, false, 0);
	if (sample.data == PS4_DATA_VALUE ||
	    sample.core.context == PS4_DATA_CONTEXT_VALUE)
		ps4_data_stop(adev, "DATA_STALE_RESULT", -EBUSY,
			&sample, &progress, false, false, 0);
	request = (struct ps4_uvd_ring_request) {
		.gpu_base = rb->private_va, .baseline = PS4_DATA_CONTEXT_BASELINE,
		.token = PS4_DATA_CONTEXT_VALUE,
		.context_before_baseline = sample.core.context,
		.initial_rptr_raw = sample.core.rptr,
		.initial_wptr_raw = sample.core.wptr,
	};
	if (ps4_uvd_build_ring(rb->cpu, rb->bytes, request, &plan) != PS4_UVD_PLAN_OK)
		ps4_data_stop(adev, "DATA_PLAN_REJECTED", -EINVAL,
			&sample, &progress, false, false, 0);
	/* The planner initializes all 4096 bytes with count=0 pairs. Replace
	 * only the first two pairs before any fetch; all other pairs remain NOP.
	 */
	ps4_uvd_store_le32(rb->cpu, mmUVD_GPCOM_VCPU_DATA0);
	ps4_uvd_store_le32((u8 *)rb->cpu + 4, PS4_DATA_VALUE);
	ps4_uvd_store_le32((u8 *)rb->cpu + 8, mmUVD_CONTEXT_ID);
	ps4_uvd_store_le32((u8 *)rb->cpu + 12, PS4_DATA_CONTEXT_VALUE);
	dev_info(adev->dev,
		"PS4_UVD_DATA PREPARED bytes=4096 submit_dw=16 va=%llx data_baseline=%08x data_value=%08x context_baseline=%08x context_value=%08x crc=%08x; DATA0 readback and BLKSZ8/DWORD units are hypotheses\n",
		rb->private_va, PS4_DATA_BASELINE, PS4_DATA_VALUE,
		PS4_DATA_CONTEXT_BASELINE, PS4_DATA_CONTEXT_VALUE,
		crc32_le(~0U, rb->cpu, rb->bytes) ^ ~0U);
	WREG32(mmUVD_GPCOM_VCPU_DATA0, PS4_DATA_BASELINE);
	readback = RREG32(mmUVD_GPCOM_VCPU_DATA0);
	if (readback != PS4_DATA_BASELINE) {
		dev_err(adev->dev,
			"PS4_UVD_DATA BASELINE_DIRECT reg=%08x value=%08x expected=%08x; no CORE resample\n",
			mmUVD_GPCOM_VCPU_DATA0, readback, PS4_DATA_BASELINE);
		ps4_data_stop(adev, "DATA_BASELINE_READBACK", -EIO,
			NULL, &progress, false, false, 0);
	}
	WREG32(mmUVD_CONTEXT_ID, PS4_DATA_CONTEXT_BASELINE);
	readback = RREG32(mmUVD_CONTEXT_ID);
	if (readback != PS4_DATA_CONTEXT_BASELINE) {
		dev_err(adev->dev,
			"PS4_UVD_DATA BASELINE_DIRECT reg=%08x value=%08x expected=%08x; no CORE resample\n",
			mmUVD_CONTEXT_ID, readback, PS4_DATA_CONTEXT_BASELINE);
		ps4_data_stop(adev, "DATA_CONTEXT_BASELINE_READBACK", -EIO,
			NULL, &progress, false, false, 0);
	}
	dev_info(adev->dev,
		"PS4_UVD_DATA CPU_BASELINES observed data=%08x context=%08x; fetch remains inhibited\n",
		PS4_DATA_BASELINE, readback);
	mb();
	amdgpu_device_flush_hdp(adev, NULL);
	if (!ps4_data_sample(adev, &sample, PS4_TOKEN_HELD, pd_addr,
			     cache_vmid, fault_base, reset_base) ||
	    !ps4_data_baselines(&sample))
		ps4_data_stop(adev, "DATA_BASELINE_OR_PUBLICATION_GUARD", -EIO,
			&sample, &progress, false, false, 0);
	dev_info(adev->dev,
		"PS4_UVD_DATA ENABLE_BEGIN held_baselines=data:%08x/context:%08x; empty ring only, next write clears NO_FETCH\n",
		sample.data, sample.core.context);
	started = ktime_get_ns();
	WREG32(mmUVD_RBC_RB_CNTL, PS4_TOKEN_RBC_FETCH);
	valid = ps4_data_sample(adev, &sample, PS4_TOKEN_EMPTY, pd_addr,
				cache_vmid, fault_base, reset_base);
	elapsed = ktime_get_ns() - started;
	if (elapsed >= PS4_DATA_LIMIT_NS)
		ps4_data_stop(adev, "DATA_ENABLE_TIMEOUT", -ETIMEDOUT,
			&sample, &progress, true, false, elapsed);
	if (!valid || !ps4_data_baselines(&sample))
		ps4_data_stop(adev, "DATA_ENABLE_GUARD", -EIO,
			&sample, &progress, true, false, elapsed);
	dev_info(adev->dev,
		"PS4_UVD_DATA PUBLICATION_BEGIN empty_baselines=data:%08x/context:%08x elapsed_ns=%llu; next write sole WPTR16 after deadline check\n",
		sample.data, sample.core.context, (unsigned long long)elapsed);
	mb();
	elapsed = ktime_get_ns() - started;
	if (elapsed >= PS4_DATA_LIMIT_NS)
		ps4_data_stop(adev, "DATA_BEFORE_SUBMIT_TIMEOUT", -ETIMEDOUT,
			&sample, &progress, true, false, elapsed);
	WREG32(mmUVD_RBC_RB_WPTR, plan.publish_wptr_raw);
	dev_info(adev->dev,
		"PS4_UVD_DATA SUBMITTED raw_wptr=16 once; DATA0, CONTEXT_ID, NOP only, no CMD/DATA1/IB/fence/trap\n");
	for (;;) {
		valid = ps4_data_sample(adev, &sample, PS4_TOKEN_SUBMITTED,
			pd_addr, cache_vmid, fault_base, reset_base);
		++progress.samples;
		elapsed = ktime_get_ns() - started;
		/* Deadline wins over an apparently successful deciding sample. */
		if (elapsed >= PS4_DATA_LIMIT_NS) {
			const char *result = "DATA_TIMEOUT";

			if (valid && progress.transport_seen && !progress.data_seen &&
			    sample.data == PS4_DATA_BASELINE &&
			    sample.core.context == PS4_DATA_CONTEXT_VALUE &&
			    sample.core.rptr == PS4_UVD_SUBMIT_DWORDS &&
			    sample.core.wptr == PS4_UVD_SUBMIT_DWORDS)
				result = "DATA_NOT_OBSERVED_WITH_TRANSPORT";
			ps4_data_stop(adev, result, -ETIMEDOUT,
				&sample, &progress, true, true, elapsed);
		}
		if (!valid)
			ps4_data_stop(adev, "DATA_SUBMITTED_GUARD", -EIO,
				&sample, &progress, true, true, elapsed);
		if (sample.data != PS4_DATA_BASELINE && sample.data != PS4_DATA_VALUE) {
			ps4_token_expect(&sample.core, 0, mmUVD_GPCOM_VCPU_DATA0,
					 sample.data, ~0U, PS4_DATA_VALUE);
			ps4_data_stop(adev, "DATA_UNEXPECTED_VALUE", -EIO,
				&sample, &progress, true, true, elapsed);
		}
		if (sample.core.context != PS4_DATA_CONTEXT_BASELINE &&
		    sample.core.context != PS4_DATA_CONTEXT_VALUE) {
			ps4_token_expect(&sample.core, 0, mmUVD_CONTEXT_ID,
					 sample.core.context, ~0U, PS4_DATA_CONTEXT_VALUE);
			ps4_data_stop(adev, "DATA_UNEXPECTED_CONTEXT", -EIO,
				&sample, &progress, true, true, elapsed);
		}
		if (progress.data_seen && sample.data == PS4_DATA_BASELINE)
			ps4_data_stop(adev, "DATA_OBSERVATION_REGRESSION", -EIO,
				&sample, &progress, true, true, elapsed);
		if (progress.context_seen && sample.core.context == PS4_DATA_CONTEXT_BASELINE)
			ps4_data_stop(adev, "DATA_CONTEXT_REGRESSION", -EIO,
				&sample, &progress, true, true, elapsed);
		if (sample.core.rptr < progress.last_rptr)
			ps4_data_stop(adev, "DATA_POINTER_REGRESSION", -EIO,
				&sample, &progress, true, true, elapsed);
		progress.last_rptr = sample.core.rptr;
		if (!progress.transport_seen &&
		    sample.core.context == PS4_DATA_CONTEXT_VALUE &&
		    sample.core.rptr == PS4_UVD_SUBMIT_DWORDS &&
		    sample.core.wptr == PS4_UVD_SUBMIT_DWORDS) {
			progress.transport_seen = true;
			progress.first_transport_ns = elapsed;
		}
		if (!progress.data_seen && sample.data == PS4_DATA_VALUE) {
			progress.data_seen = true;
			progress.first_data_ns = elapsed;
		}
		if (!progress.context_seen && sample.core.context == PS4_DATA_CONTEXT_VALUE) {
			progress.context_seen = true;
			progress.first_context_ns = elapsed;
		}
		if (sample.data == PS4_DATA_VALUE &&
		    sample.core.context == PS4_DATA_CONTEXT_VALUE &&
		    sample.core.rptr == PS4_UVD_SUBMIT_DWORDS &&
		    sample.core.wptr == PS4_UVD_SUBMIT_DWORDS) {
			if (!progress.joint_samples)
				progress.first_joint_ns = elapsed;
			++progress.joint_samples;
			if (++progress.consecutive == 2)
				ps4_data_stop(adev, "DATA_READBACK_CONTROL_OBSERVED", 0,
					&sample, &progress, true, true, elapsed);
		} else {
			progress.consecutive = 0;
		}
		/* Baseline plus a fresh trailer can straddle sequential reads.
		 * Keep polling unless a previously observed fresh value regressed.
		 */
		usleep_range(100, 200);
	}
}
/* DATA_CONTROL_FLOW_END */
/* STATUS_OBS_FLOW_BEGIN: extracted verbatim by the host fixture. */

/* Bounded observation of EXP005's STATUS bit16 onset and persistence.
 * The ring payload, four direct stores and publication count are retained.
 * The added pre-WPTR direct read, longer enabled-dwell log, before-sample
 * deadline checks and post-window indexed sweep change instrumentation.
 * The three earlier full samples still make 24 selector stores; the new
 * pre-WPTR read and record loop make none. Indexed invariants are not
 * observed between the ENABLE sample and the permitted endpoint sweep.
 * No command, clear, reset or resubmission is added. bit16 is recorded,
 * never accepted, credited or cleared; no outcome names its semantics.
 * Saved samples are printed in full; terminal GPU/UVD register access
 * precedes all reporting. UART reporting itself may use console MMIO.
 */
#define PS4_STOBS_LIMIT_NS (250ULL * NSEC_PER_MSEC)
#define PS4_STOBS_BIT16 0x00010000U
#define PS4_STOBS_FINE_SLEEP_LOW 100U
#define PS4_STOBS_FINE_SLEEP_HIGH 200U
#define PS4_STOBS_COARSE_SLEEP_LOW 12000U
#define PS4_STOBS_COARSE_SLEEP_HIGH 12500U
#define PS4_STOBS_FINE_SAMPLES 24U
#define PS4_STOBS_COARSE_SAMPLES 16U
#define PS4_STOBS_RECORDS (PS4_STOBS_FINE_SAMPLES + PS4_STOBS_COARSE_SAMPLES)

struct ps4_stobs_record {
	u64 elapsed_ns;
	u64 elapsed_end_ns;
	struct ps4_data_sample sample;
	bool bit16;
};

static struct ps4_stobs_record ps4_stobs_log[PS4_STOBS_RECORDS];
static unsigned ps4_stobs_record_count;
static u64 ps4_stobs_publish_ns;

static bool ps4_stobs_inputs_valid(const struct amdgpu_ps4_uvd_ring *rb,
	const u64 pd_addr)
{
	return ps4_uvd_status_observation && ps4_uvd_token && ps4_uvd_ready &&
		ps4_uvd_poll_state && ps4_token_descriptor_valid(rb) && pd_addr &&
		!(pd_addr & 0xfff) && (pd_addr >> 12) <= U32_MAX;
}

/* The single rule difference against ps4_token_sample, isolated here. The
 * submitted phase additionally tolerates exactly STATUS bit16
 * (2|0x00010000); HELD and EMPTY keep the strict original rule. Tolerance
 * observes; it never accepts, credits, clears or widens any other value.
 */
static bool ps4_stobs_status_expect(struct ps4_token_sample *s,
	enum ps4_token_phase phase)
{
	u32 mask = phase == PS4_TOKEN_HELD ? ~0U : ~(u32)UVD_STATUS__RBC_BUSY_MASK;

	return ps4_token_expect(s, 0, mmUVD_STATUS, s->status, mask,
		phase == PS4_TOKEN_SUBMITTED &&
		(s->status & mask) == (PS4_READY_BIT | PS4_STOBS_BIT16) ?
		s->status & mask : PS4_READY_BIT);
}

/* STATUS_OBS_CORE_SAMPLE: copies the ps4_token_sample body verbatim except
 * three documented differences, all restored and asserted byte-equal by
 * check.py: the status rule above, the indexed TOKEN_CTX reads moved to
 * ps4_stobs_ctx_sweep after the window (per-record reads write no UVD
 * registers), and the then-unused u32 declaration. Full direct-MMIO guard
 * coverage stays per record.
 */
static bool ps4_stobs_core_sample(struct amdgpu_device *adev,
			    struct ps4_token_sample *s, enum ps4_token_phase phase,
			    u64 pd_addr, u32 cache_vmid, u32 fault_base, int reset_base)
{
	*s = (struct ps4_token_sample) { 0 };
	/* Every field printed by CORE is sampled, even on an early rejection. */
	s->status = RREG32(mmUVD_STATUS);
	s->mastint = RREG32(mmUVD_MASTINT_EN);
	s->rbc = RREG32(mmUVD_RBC_RB_CNTL);
	s->ib_size = RREG32(mmUVD_RBC_IB_SIZE);
	s->wptr = RREG32(mmUVD_RBC_RB_WPTR);
	s->rptr = RREG32(mmUVD_RBC_RB_RPTR);
	s->context = RREG32(mmUVD_CONTEXT_ID);
	s->wptr_cntl = RREG32(mmUVD_RBC_RB_WPTR_CNTL);
	s->rptr_addr = RREG32(mmUVD_RBC_RB_RPTR_ADDR);
	s->fault = RREG32(mmVM_CONTEXT1_PROTECTION_FAULT_STATUS);
	s->reset_count = atomic_read(&adev->gpu_reset_counter);
	s->in_reset = amdgpu_in_reset(adev);
	s->pd = RREG32(mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR + 4);
#define TOKEN_SAVED(reg, got, want) \
	if (!ps4_token_expect(s, 0, reg, got, ~0U, want)) return false
	/* STOBS: submitted-phase STATUS additionally tolerates exactly bit16.
	 * The comparison observes bit16; it does not prove busy semantics,
	 * GPCOM naming, DMA quiescence or any Liverpool field specification.
	 */
	if (!ps4_stobs_status_expect(s, phase))
		return false;
	TOKEN_SAVED(mmUVD_MASTINT_EN, s->mastint, UVD_MASTINT_EN__VCPU_EN_MASK);
	TOKEN_SAVED(mmUVD_RBC_RB_CNTL, s->rbc,
		phase == PS4_TOKEN_HELD ? PS4_TOKEN_RBC_HELD : PS4_TOKEN_RBC_FETCH);
	TOKEN_SAVED(mmUVD_RBC_IB_SIZE, s->ib_size, 0);
	TOKEN_SAVED(mmUVD_RBC_RB_WPTR_CNTL, s->wptr_cntl, 0);
	TOKEN_SAVED(mmUVD_RBC_RB_RPTR_ADDR, s->rptr_addr, 0);
	TOKEN_SAVED(mmUVD_RBC_RB_WPTR, s->wptr,
		phase == PS4_TOKEN_SUBMITTED ? PS4_UVD_SUBMIT_DWORDS : 0);
	if (phase != PS4_TOKEN_SUBMITTED) {
		TOKEN_SAVED(mmUVD_RBC_RB_RPTR, s->rptr, 0);
	} else if (s->rptr > PS4_UVD_SUBMIT_DWORDS) {
		return ps4_token_expect(s, 3, mmUVD_RBC_RB_RPTR,
					s->rptr, ~0U, PS4_UVD_SUBMIT_DWORDS);
	}
	TOKEN_SAVED(mmVM_CONTEXT1_PROTECTION_FAULT_STATUS, s->fault, fault_base);
	TOKEN_SAVED(mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR + 4, s->pd, pd_addr >> 12);
	if (!ps4_token_expect(s, 2, 1, s->reset_count, ~0U, reset_base) ||
	    !ps4_token_expect(s, 2, 2, s->in_reset, ~0U, 0) ||
	    !ps4_token_expect(s, 2, 3, ps4_boot_buffer_funcs(adev), ~0U, 0) ||
	    !ps4_token_expect(s, 2, 4, ps4_boot_accel(adev), ~0U, 0))
		return false;
#define TOKEN_REG(reg, mask, want) \
	if (!ps4_token_expect(s, 0, reg, RREG32(reg), mask, want)) return false
	TOKEN_REG(PS4_READY_UVD_VCPU_CACHE_VMID, ~0U, cache_vmid);
	TOKEN_REG(mmUVD_LMI_RBC_RB_VMID, ~0U, 4);
	TOKEN_REG(mmUVD_LMI_RBC_IB_VMID, ~0U, 4);
	TOKEN_REG(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_LOW, ~0U, lower_32_bits(PS4_READY_VCPU_VA));
	TOKEN_REG(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_HIGH, ~0U, upper_32_bits(PS4_READY_VCPU_VA));
	TOKEN_REG(mmUVD_LMI_RBC_RB_64BIT_BAR_LOW, ~0U, lower_32_bits(PS4_READY_RB_VA));
	TOKEN_REG(mmUVD_LMI_RBC_RB_64BIT_BAR_HIGH, ~0U, upper_32_bits(PS4_READY_RB_VA));
	TOKEN_REG(mmUVD_LMI_RBC_IB_64BIT_BAR_LOW, ~0U, lower_32_bits(PS4_READY_IB_VA));
	TOKEN_REG(mmUVD_LMI_RBC_IB_64BIT_BAR_HIGH, ~0U, upper_32_bits(PS4_READY_IB_VA));
	TOKEN_REG(mmUVD_VCPU_CACHE_OFFSET0, ~0U, 0);
	TOKEN_REG(mmUVD_VCPU_CACHE_SIZE0, ~0U, 0x7d000);
	TOKEN_REG(mmUVD_VCPU_CACHE_OFFSET1, ~0U, 0xfa00);
	TOKEN_REG(mmUVD_VCPU_CACHE_SIZE1, ~0U, 0x40000);
	TOKEN_REG(mmUVD_VCPU_CACHE_OFFSET2, ~0U, 0x17a00);
	TOKEN_REG(mmUVD_VCPU_CACHE_SIZE2, ~0U, 0x120800);
	TOKEN_REG(mmUVD_LMI_SWAP_CNTL, ~0U, 0);
	TOKEN_REG(mmUVD_MP_SWAP_CNTL, ~0U, 0);
	TOKEN_REG(mmUVD_LMI_ADDR_EXT, ~0U, 0);
	TOKEN_REG(mmUVD_LMI_EXT40_ADDR, ~0U, 0);
	TOKEN_REG(mmUVD_SOFT_RESET, PS4_READY_HOLD, 0);
	TOKEN_REG(mmUVD_LMI_CTRL2, UVD_LMI_CTRL2__STALL_ARB_UMC_MASK, 0);
	/* Indexed context reads moved after the window (STOBS review B1);
	 * ps4_stobs_ctx_sweep performs the identical frozen block.
	 */
#undef TOKEN_REG
#undef TOKEN_SAVED
	return true;
}

static bool ps4_stobs_ctx_sweep(struct amdgpu_device *adev,
	struct ps4_token_sample *s)
{
	u32 value;

#define TOKEN_CTX(index, mask, want) do { \
	value = ps4_ready_ctx(adev, index, 0, 0, false); \
	if (!ps4_token_expect(s, 1, index, value, mask, want)) return false; \
} while (0)
	TOKEN_CTX(ixUVD_LMI_VMID_INTERNAL, 0x00ffffff, 0x00444444);
	TOKEN_CTX(ixUVD_LMI_VMID_INTERNAL2, ~0U, 0x44444444);
	TOKEN_CTX(ixUVD_LMI_VMID_INTERNAL3, 0xffff, 0x4444);
	TOKEN_CTX(ixUVD_LMI_CACHE_CTRL, UVD_LMI_CACHE_CTRL__VCPU_EN_MASK, 0);
#undef TOKEN_CTX
	return true;
}

/* Full governed record sampling: copied core sample above, then DATA0 read
 * last (the family sampled=all_then_data0 order), then the value
 * allowances. bit16 is derived from the recorded STATUS, never acted on.
 */
static bool ps4_stobs_monitor(struct amdgpu_device *adev,
	struct ps4_data_sample *sample, u64 pd_addr, u32 cache_vmid,
	u32 fault_base, int reset_base, bool *bit16)
{
	u32 masked;
	bool valid;

	valid = ps4_stobs_core_sample(adev, &sample->core, PS4_TOKEN_SUBMITTED,
		pd_addr, cache_vmid, fault_base, reset_base);
	sample->data = RREG32(mmUVD_GPCOM_VCPU_DATA0);
	masked = sample->core.status & ~UVD_STATUS__RBC_BUSY_MASK;
	*bit16 = masked == (PS4_READY_BIT | PS4_STOBS_BIT16);
	if (!valid)
		return false;
	if (sample->data != PS4_DATA_BASELINE && sample->data != PS4_DATA_VALUE) {
		ps4_token_expect(&sample->core, 0, mmUVD_GPCOM_VCPU_DATA0,
				 sample->data, ~0U, PS4_DATA_VALUE);
		return false;
	}
	if (sample->core.context != PS4_DATA_CONTEXT_BASELINE &&
	    sample->core.context != PS4_DATA_CONTEXT_VALUE) {
		ps4_token_expect(&sample->core, 0, mmUVD_CONTEXT_ID,
				 sample->core.context, ~0U, PS4_DATA_CONTEXT_VALUE);
		return false;
	}
	return true;
}

static __noreturn void ps4_stobs_stop(struct amdgpu_device *adev,
	const char *result, int error, const struct ps4_data_sample *failing,
	bool enabled, bool submitted, u64 elapsed, u64 pd_addr, u32 cache_vmid,
	u32 fault_base, int reset_base, bool with_final)
{
	struct ps4_data_sample final = { 0 };
	bool final_valid = false, sweep_valid = false, markers = false;
	bool prev = false, persisted = false, onset = false;
	u32 records = ps4_stobs_record_count, fine = 0, clears = 0, sets = 0;
	u32 data_regressions = 0, context_regressions = 0;
	u32 prev_data = 0, prev_context = 0;
	u32 sweep_kind = 0, sweep_reg = 0, sweep_value = 0, sweep_mask = 0;
	u32 sweep_expected = 0;
	u64 onset_ns = 0;
	int bit16_first = -1, first_clear = -1;
	const struct ps4_stobs_record *last = records ?
		&ps4_stobs_log[records - 1] : NULL;
	const struct ps4_data_sample *f = failing;
	const char *log_class = "STOBS_NO_RECORDS";
	u32 i;

	/* Completed outcomes only: the terminal record sample runs first,
	 * and the post-window indexed sweep runs only when that sample is
	 * valid; both finish before the first terminal report (host
	 * finding 1). Guard and fault terminals take no follow-up MMIO or
	 * sweeps: the saved deciding sample and the terminal reason are
	 * preserved and the run parks. A failed terminal core sample is
	 * itself an error observation: under the no-follow-up-after-error
	 * policy it prohibits the sweep and its selector stores, the
	 * outcome is reported STOBS_FINAL_GUARD with the core sample's own
	 * guard metadata, and no class change follows. The sweep's
	 * 8 CTX_INDEX stores stay after the observation window, declared
	 * as the post-window intervention.
	 * final_valid covers the core predicates only; terminal DATA0 and
	 * CONTEXT_ID allowances are not rechecked. The endpoint sweep has
	 * its own validity and failure result, separate from log_class.
	 */
	if (with_final) {
		final_valid = ps4_stobs_core_sample(adev, &final.core,
			PS4_TOKEN_SUBMITTED, pd_addr, cache_vmid, fault_base,
			reset_base);
		final.data = RREG32(mmUVD_GPCOM_VCPU_DATA0);
		if (final_valid) {
			sweep_valid = ps4_stobs_ctx_sweep(adev, &final.core);
			if (!sweep_valid) {
				sweep_kind = final.core.bad_kind;
				sweep_reg = final.core.bad_reg;
				sweep_value = final.core.bad_value;
				sweep_mask = final.core.bad_mask;
				sweep_expected = final.core.bad_expected;
				result = "STOBS_CTX_SWEEP_GUARD";
				error = -EIO;
			}
		}
		dev_info(adev->dev,
			"PS4_UVD_STOBS FINAL_CORE sampled=all_then_data0 status=%08x int=%08x rbc=%08x ib=%08x wp=%08x rp=%08x ctx=%08x data=%08x wpc=%08x rpa=%08x fault=%08x reset=%u in_reset=%u pd=%08x valid=%d\n",
			final.core.status, final.core.mastint, final.core.rbc,
			final.core.ib_size, final.core.wptr, final.core.rptr,
			final.core.context, final.data, final.core.wptr_cntl,
			final.core.rptr_addr, final.core.fault,
			final.core.reset_count, final.core.in_reset,
			final.core.pd, final_valid);
		if (!final_valid) {
			result = "STOBS_FINAL_GUARD";
			error = -EIO;
			dev_err(adev->dev,
				"PS4_UVD_STOBS FINAL_GUARD kind=%u reg=%08x value=%08x mask=%08x expected=%08x\n",
				final.core.bad_kind, final.core.bad_reg,
				final.core.bad_value, final.core.bad_mask,
				final.core.bad_expected);
		}
		if (final_valid)
			dev_info(adev->dev,
				"PS4_UVD_STOBS CTX_SWEEP valid=%d kind=%u reg=%08x value=%08x mask=%08x expected=%08x\n",
				sweep_valid, sweep_kind, sweep_reg, sweep_value,
				sweep_mask, sweep_expected);
	}
	if (failing) {
		if (f->core.failed)
			dev_err(adev->dev,
				"PS4_UVD_STOBS GUARD kind=%u reg=%08x value=%08x mask=%08x expected=%08x; saved deciding read\n",
				f->core.bad_kind, f->core.bad_reg, f->core.bad_value,
				f->core.bad_mask, f->core.bad_expected);
		dev_info(adev->dev,
			"PS4_UVD_STOBS GUARD_FULL sampled=all_then_data0 status=%08x int=%08x rbc=%08x ib=%08x wp=%08x rp=%08x ctx=%08x data=%08x wpc=%08x rpa=%08x fault=%08x reset=%u in_reset=%u pd=%08x valid=%d\n",
			f->core.status, f->core.mastint, f->core.rbc,
			f->core.ib_size, f->core.wptr, f->core.rptr,
			f->core.context, f->data, f->core.wptr_cntl,
			f->core.rptr_addr, f->core.fault,
			f->core.reset_count, f->core.in_reset, f->core.pd,
			!f->core.failed);
	}
	for (i = 0; i < records; ++i) {
		const struct ps4_stobs_record *r = &ps4_stobs_log[i];

		if (i < PS4_STOBS_FINE_SAMPLES)
			++fine;
		if (r->bit16) {
			if (bit16_first < 0) {
				bit16_first = (int)i;
				onset_ns = r->elapsed_ns;
				onset = r->sample.data == PS4_DATA_VALUE ||
					r->sample.core.context ==
					PS4_DATA_CONTEXT_VALUE ||
					(r->sample.core.rptr ==
					PS4_UVD_SUBMIT_DWORDS &&
					r->sample.core.wptr ==
					PS4_UVD_SUBMIT_DWORDS);
			}
			if (!prev)
				++sets;
		} else if (prev) {
			if (!clears)
				first_clear = (int)i;
			++clears;
		}
		prev = r->bit16;
		if (r->sample.data == PS4_DATA_VALUE ||
		    r->sample.core.context == PS4_DATA_CONTEXT_VALUE)
			markers = true;
		/* A value regression is one adjacent-record fresh-to-baseline
		 * transition: the previous record carried the fresh packet
		 * value and this record carries the planted baseline (host
		 * finding 2). Baseline-only runs have no edges; the counter
		 * never measures the length of a baseline run. Non-terminal
		 * by design, declared and counted (review B8).
		 */
		if (i && prev_data == PS4_DATA_VALUE &&
		    r->sample.data == PS4_DATA_BASELINE)
			++data_regressions;
		if (i && prev_context == PS4_DATA_CONTEXT_VALUE &&
		    r->sample.core.context == PS4_DATA_CONTEXT_BASELINE)
			++context_regressions;
		prev_data = r->sample.data;
		prev_context = r->sample.core.context;
		dev_info(adev->dev,
			"PS4_UVD_STOBS REC i=%u elapsed_us=%llu t_end_us=%llu status=%08x int=%08x rbc=%08x ib=%08x wp=%08x rp=%08x ctx=%08x data=%08x wpc=%08x rpa=%08x fault=%08x reset=%u in_reset=%u pd=%08x bit16=%d\n",
			i, (unsigned long long)div_u64(r->elapsed_ns, 1000),
			(unsigned long long)div_u64(r->elapsed_end_ns, 1000),
			r->sample.core.status, r->sample.core.mastint,
			r->sample.core.rbc, r->sample.core.ib_size,
			r->sample.core.wptr, r->sample.core.rptr,
			r->sample.core.context, r->sample.data,
			r->sample.core.wptr_cntl, r->sample.core.rptr_addr,
			r->sample.core.fault, r->sample.core.reset_count,
			r->sample.core.in_reset, r->sample.core.pd, r->bit16);
	}
	persisted = bit16_first >= 0 && !clears && sets == 1;
	/* Describe the saved records even when the terminal result is a
	 * failure. This pattern does not qualify incomplete guard coverage.
	 */
	if (submitted && records) {
		if (bit16_first < 0)
			log_class = markers ? "STOBS_BIT16_ABSENT_MARKERS" :
				"STOBS_BIT16_ABSENT_NO_MARKERS";
		else if (persisted)
			log_class = "STOBS_BIT16_PERSISTENT";
		else if (sets == 1)
			log_class = "STOBS_BIT16_TRANSIENT";
		else
			log_class = "STOBS_BIT16_TOGGLING";
	}
	/* Only completed valid outcomes change their terminal result. */
	if (result && error == 0 && submitted && records)
		result = log_class;
	dev_info(adev->dev,
		"PS4_UVD_STOBS END result=%s log_class=%s enabled=%d submitted=%d elapsed_ns=%llu publish_ns=%llu records=%u fine=%u bit16_first=%d onset_ns=%llu sets=%u bit16_clears=%u first_clear=%d markers=%d persistent=%d onset_with_values=%d data_regressions=%u context_regressions=%u accepted=0 last_wp=%u last_rp=%u last_data=%08x last_ctx=%08x final_valid=%d sweep_valid=%d; times include software/logging, sequential observations, retained, no acceptance/crediting, no decode/containment/quiescence claim\n",
		result, log_class, enabled, submitted, (unsigned long long)elapsed,
		(unsigned long long)ps4_stobs_publish_ns, records, fine,
		bit16_first, (unsigned long long)onset_ns, sets, clears,
		first_clear, markers, persisted, onset, data_regressions,
		context_regressions, last ? last->sample.core.wptr : 0,
		last ? last->sample.core.rptr : 0,
		last ? last->sample.data : 0,
		last ? last->sample.core.context : 0, final_valid,
		sweep_valid);
	ps4_ready_park(adev, result, error);
}

/* Observation of one identical EXP005 packet publication. Its deadline
 * anchor and pre-publication store sequence are retained. Added direct
 * reads, stop sites, longer enabled-dwell logging, before-sample deadline
 * priority and the endpoint selector sweep are declared changes. Values may
 * regress without stopping: fresh value disappearance is itself transition
 * evidence, unlike the crediting semantics it replaces. Pointer regression
 * remains a safety terminal.
 */
static __noreturn void ps4_stobs_run(struct amdgpu_device *adev,
	const struct amdgpu_ps4_uvd_ring *rb, u64 pd_addr, u32 cache_vmid,
	u32 fault_base, int reset_base)
{
	struct ps4_uvd_ring_plan plan;
	struct ps4_uvd_ring_request request;
	struct ps4_data_sample sample;
	u64 started, elapsed;
	u32 readback, last_rptr;
	bool valid, ok, bit16;

	ps4_stobs_record_count = 0;
	if (!ps4_stobs_inputs_valid(rb, pd_addr))
		ps4_stobs_stop(adev, "STOBS_DESCRIPTOR_OR_GATES", -EINVAL,
			NULL, false, false, 0, pd_addr, cache_vmid,
			fault_base, reset_base, false);
	if (!ps4_data_sample(adev, &sample, PS4_TOKEN_HELD, pd_addr,
			     cache_vmid, fault_base, reset_base))
		ps4_stobs_stop(adev, "STOBS_PRECONDITION", -EIO, &sample,
			false, false, 0, pd_addr, cache_vmid, fault_base,
			reset_base, false);
	if (sample.data == PS4_DATA_VALUE ||
	    sample.core.context == PS4_DATA_CONTEXT_VALUE)
		ps4_stobs_stop(adev, "STOBS_STALE_RESULT", -EBUSY, &sample,
			false, false, 0, pd_addr, cache_vmid, fault_base,
			reset_base, false);
	request = (struct ps4_uvd_ring_request) {
		.gpu_base = rb->private_va, .baseline = PS4_DATA_CONTEXT_BASELINE,
		.token = PS4_DATA_CONTEXT_VALUE,
		.context_before_baseline = sample.core.context,
		.initial_rptr_raw = sample.core.rptr,
		.initial_wptr_raw = sample.core.wptr,
	};
	if (ps4_uvd_build_ring(rb->cpu, rb->bytes, request, &plan) != PS4_UVD_PLAN_OK)
		ps4_stobs_stop(adev, "STOBS_PLAN_REJECTED", -EINVAL, &sample,
			false, false, 0, pd_addr, cache_vmid, fault_base,
			reset_base, false);
	/* Same page as EXP005: planner fill of count=0 pairs, then only the
	 * first two pairs replaced before any fetch. CRC equals cadc2d79.
	 */
	ps4_uvd_store_le32(rb->cpu, mmUVD_GPCOM_VCPU_DATA0);
	ps4_uvd_store_le32((u8 *)rb->cpu + 4, PS4_DATA_VALUE);
	ps4_uvd_store_le32((u8 *)rb->cpu + 8, mmUVD_CONTEXT_ID);
	ps4_uvd_store_le32((u8 *)rb->cpu + 12, PS4_DATA_CONTEXT_VALUE);
	dev_info(adev->dev,
		"PS4_UVD_STOBS PREPARED bytes=4096 submit_dw=16 va=%llx data_baseline=%08x data_value=%08x context_baseline=%08x context_value=%08x crc=%08x; identical EXP005 packet, observation only\n",
		rb->private_va, PS4_DATA_BASELINE, PS4_DATA_VALUE,
		PS4_DATA_CONTEXT_BASELINE, PS4_DATA_CONTEXT_VALUE,
		crc32_le(~0U, rb->cpu, rb->bytes) ^ ~0U);
	WREG32(mmUVD_GPCOM_VCPU_DATA0, PS4_DATA_BASELINE);
	readback = RREG32(mmUVD_GPCOM_VCPU_DATA0);
	if (readback != PS4_DATA_BASELINE) {
		dev_err(adev->dev,
			"PS4_UVD_STOBS BASELINE_DIRECT reg=%08x value=%08x expected=%08x; no CORE resample\n",
			mmUVD_GPCOM_VCPU_DATA0, readback, PS4_DATA_BASELINE);
		ps4_stobs_stop(adev, "STOBS_BASELINE_READBACK", -EIO, NULL,
			false, false, 0, pd_addr, cache_vmid, fault_base,
			reset_base, false);
	}
	WREG32(mmUVD_CONTEXT_ID, PS4_DATA_CONTEXT_BASELINE);
	readback = RREG32(mmUVD_CONTEXT_ID);
	if (readback != PS4_DATA_CONTEXT_BASELINE) {
		dev_err(adev->dev,
			"PS4_UVD_STOBS BASELINE_DIRECT reg=%08x value=%08x expected=%08x; no CORE resample\n",
			mmUVD_CONTEXT_ID, readback, PS4_DATA_CONTEXT_BASELINE);
		ps4_stobs_stop(adev, "STOBS_CONTEXT_BASELINE_READBACK", -EIO,
			NULL, false, false, 0, pd_addr, cache_vmid, fault_base,
			reset_base, false);
	}
	dev_info(adev->dev,
		"PS4_UVD_STOBS CPU_BASELINES observed data=%08x context=%08x; fetch remains inhibited\n",
		PS4_DATA_BASELINE, readback);
	mb();
	amdgpu_device_flush_hdp(adev, NULL);
	if (!ps4_data_sample(adev, &sample, PS4_TOKEN_HELD, pd_addr,
			     cache_vmid, fault_base, reset_base) ||
	    !ps4_data_baselines(&sample))
		ps4_stobs_stop(adev, "STOBS_BASELINE_OR_PUBLICATION_GUARD", -EIO,
			&sample, false, false, 0, pd_addr, cache_vmid,
			fault_base, reset_base, false);
	dev_info(adev->dev,
		"PS4_UVD_STOBS ENABLE_BEGIN held_baselines=data:%08x/context:%08x; empty ring only, next write clears NO_FETCH\n",
		sample.data, sample.core.context);
	started = ktime_get_ns();
	WREG32(mmUVD_RBC_RB_CNTL, PS4_TOKEN_RBC_FETCH);
	valid = ps4_data_sample(adev, &sample, PS4_TOKEN_EMPTY, pd_addr,
				cache_vmid, fault_base, reset_base);
	elapsed = ktime_get_ns() - started;
	if (elapsed >= PS4_STOBS_LIMIT_NS)
		ps4_stobs_stop(adev, "STOBS_ENABLE_TIMEOUT", -ETIMEDOUT,
			&sample, true, false, elapsed, pd_addr, cache_vmid,
			fault_base, reset_base, false);
	if (!valid && sample.core.bad_reg == mmUVD_STATUS &&
	    (sample.core.bad_value & ~(u32)UVD_STATUS__RBC_BUSY_MASK) ==
	    (PS4_READY_BIT | PS4_STOBS_BIT16))
		ps4_stobs_stop(adev, "STOBS_PREPUBLICATION_BIT16", -EIO,
			&sample, true, false, elapsed, pd_addr, cache_vmid,
			fault_base, reset_base, false);
	if (!valid || !ps4_data_baselines(&sample))
		ps4_stobs_stop(adev, "STOBS_ENABLE_GUARD", -EIO, &sample,
			true, false, elapsed, pd_addr, cache_vmid, fault_base,
			reset_base, false);
	/* Same enabled-dwell print family as EXP005. The PUBLICATION_BEGIN
	 * line is longer than EXP005's counters (review B7); the resulting
	 * dwell is recorded by publish_ns below rather than assumed.
	 */
	dev_info(adev->dev,
		"PS4_UVD_STOBS PUBLICATION_BEGIN empty_baselines=data:%08x/context:%08x elapsed_ns=%llu; next write sole WPTR16 after deadline check; SUBMITTED evidence carried by the record log\n",
		sample.data, sample.core.context, (unsigned long long)elapsed);
	mb();
	elapsed = ktime_get_ns() - started;
	if (elapsed >= PS4_STOBS_LIMIT_NS)
		ps4_stobs_stop(adev, "STOBS_BEFORE_SUBMIT_TIMEOUT", -ETIMEDOUT,
			&sample, true, false, elapsed, pd_addr, cache_vmid,
			fault_base, reset_base, false);
	/* Immediate pre-publication read (review B4): if bit16 is already
	 * set, stop without publishing. The strict EMPTY sampler performs
	 * direct reads only (F1); indexed values were last checked at ENABLE.
	 * No printk occurs between this read, the final deadline recheck and
	 * WPTR. publish_ns is a post-write timestamp, not a two-sided bracket.
	 */
	valid = ps4_stobs_core_sample(adev, &sample.core, PS4_TOKEN_EMPTY,
		pd_addr, cache_vmid, fault_base, reset_base);
	sample.data = RREG32(mmUVD_GPCOM_VCPU_DATA0);
	elapsed = ktime_get_ns() - started;
	if (!valid && sample.core.bad_reg == mmUVD_STATUS &&
	    (sample.core.bad_value & ~(u32)UVD_STATUS__RBC_BUSY_MASK) ==
	    (PS4_READY_BIT | PS4_STOBS_BIT16))
		ps4_stobs_stop(adev, "STOBS_PREPUBLICATION_BIT16", -EIO,
			&sample, true, false, elapsed, pd_addr, cache_vmid,
			fault_base, reset_base, false);
	if (!valid || !ps4_data_baselines(&sample))
		ps4_stobs_stop(adev, "STOBS_PREPUBLICATION_GUARD", -EIO,
			&sample, true, false, elapsed, pd_addr, cache_vmid,
			fault_base, reset_base, false);
	elapsed = ktime_get_ns() - started;
	if (elapsed >= PS4_STOBS_LIMIT_NS)
		ps4_stobs_stop(adev, "STOBS_BEFORE_SUBMIT_TIMEOUT", -ETIMEDOUT,
			&sample, true, false, elapsed, pd_addr, cache_vmid,
			fault_base, reset_base, false);
	WREG32(mmUVD_RBC_RB_WPTR, plan.publish_wptr_raw);
	ps4_stobs_publish_ns = ktime_get_ns() - started;
	last_rptr = 0;
	for (;;) {
		u64 t_begin, t_end;

		t_begin = ktime_get_ns() - started;
		/* Unlike EXP005, check the deadline before starting a sample.
		 * A sample spanning the deadline retains its own guard verdict.
		 */
		if (t_begin >= PS4_STOBS_LIMIT_NS)
			ps4_stobs_stop(adev, "STOBS_OBSERVATION_COMPLETED", 0,
				NULL, true, true, t_begin, pd_addr, cache_vmid,
				fault_base, reset_base, true);
		ok = ps4_stobs_monitor(adev, &sample, pd_addr, cache_vmid,
			fault_base, reset_base, &bit16);
		t_end = ktime_get_ns() - started;
		if (!ok) {
			const char *guard;

			if (sample.core.bad_reg == mmUVD_GPCOM_VCPU_DATA0 &&
			    sample.core.bad_mask == ~0U &&
			    sample.core.bad_expected == PS4_DATA_VALUE)
				guard = "STOBS_UNEXPECTED_VALUE";
			else if (sample.core.bad_reg == mmUVD_CONTEXT_ID &&
				 sample.core.bad_mask == ~0U &&
				 sample.core.bad_expected ==
				 PS4_DATA_CONTEXT_VALUE)
				guard = "STOBS_UNEXPECTED_CONTEXT";
			else if (sample.core.bad_reg == mmUVD_STATUS &&
				 sample.core.bad_mask ==
				 ~(u32)UVD_STATUS__RBC_BUSY_MASK)
				guard = "STOBS_STATUS_UNEXPECTED";
			else
				guard = "STOBS_CORE_GUARD";
			ps4_stobs_stop(adev, guard, -EIO, &sample, true, true,
				t_end, pd_addr, cache_vmid, fault_base,
				reset_base, false);
		}
		if (ps4_stobs_record_count >= PS4_STOBS_RECORDS)
			ps4_stobs_stop(adev, "STOBS_RECORD_OVERFLOW", -EINVAL,
				NULL, true, true, t_end, pd_addr, cache_vmid,
				fault_base, reset_base, false);
		ps4_stobs_log[ps4_stobs_record_count++] =
			(struct ps4_stobs_record) { .elapsed_ns = t_begin,
				.elapsed_end_ns = t_end, .sample = sample,
				.bit16 = bit16 };
		if (sample.core.rptr < last_rptr)
			ps4_stobs_stop(adev, "STOBS_POINTER_REGRESSION", -EIO,
				&sample, true, true, t_end, pd_addr,
				cache_vmid, fault_base, reset_base, false);
		last_rptr = sample.core.rptr;
		if (ps4_stobs_record_count == PS4_STOBS_RECORDS)
			ps4_stobs_stop(adev, "STOBS_OBSERVATION_COMPLETED", 0,
				NULL, true, true, t_end, pd_addr, cache_vmid,
				fault_base, reset_base, true);
		if (ps4_stobs_record_count < PS4_STOBS_FINE_SAMPLES)
			usleep_range(PS4_STOBS_FINE_SLEEP_LOW,
				     PS4_STOBS_FINE_SLEEP_HIGH);
		else
			usleep_range(PS4_STOBS_COARSE_SLEEP_LOW,
				     PS4_STOBS_COARSE_SLEEP_HIGH);
	}
}
/* STATUS_OBS_FLOW_END */
/* IB_DATA_FLOW_BEGIN: extracted verbatim by the host fixture. */
/*
 * Original Linux psX diagnostic additions, MIT, 2026.
 * The direct sampler is adapted from the preserved MIT readiness sampler;
 * the unchanged old flows and their notices remain in the containing file.
 * One DATA0 marker exists only in the owned IB, never in the main ring or
 * in a CPU register write. This is a boot-only diagnostic, not a decoder.
 * After three full prepublication samples, all observation-window reads
 * are direct. No GPU/UVD write or print occurs in the record loop. A valid
 * terminal direct sample may be followed by one endpoint indexed sweep;
 * all such accesses finish before reporting. UART reporting may use MMIO.
 */
#define PS4_IBDATA_BASELINE 0x43504442U
#define PS4_IBDATA_VALUE 0x55564442U
#define PS4_IBDATA_CONTEXT_BASELINE 0x43504342U
#define PS4_IBDATA_LIMIT_NS (250ULL * NSEC_PER_MSEC)
#define PS4_IBDATA_FINE_SAMPLES 24U
#define PS4_IBDATA_COARSE_SAMPLES 16U
#define PS4_IBDATA_RECORDS (PS4_IBDATA_FINE_SAMPLES + PS4_IBDATA_COARSE_SAMPLES)
#define PS4_IBDATA_FINE_SLEEP_LOW 100U
#define PS4_IBDATA_FINE_SLEEP_HIGH 200U
#define PS4_IBDATA_COARSE_SLEEP_LOW 12000U
#define PS4_IBDATA_COARSE_SLEEP_HIGH 12500U

struct ps4_ib_data_record {
	u64 elapsed_ns, elapsed_end_ns;
	struct ps4_data_sample sample;
	bool valid, predeadline, bit16;
};

struct ps4_ib_data_progress {
	u32 valid_samples, consecutive, joint_samples, last_rptr;
	bool data_seen, transport_seen, confirmed, observed_data_seen, bit16_seen;
	u64 first_data_ns, first_data_end_ns, first_transport_ns;
	u64 first_joint_ns, confirmed_ns;
};

static struct ps4_ib_data_record ps4_ib_data_log[PS4_IBDATA_RECORDS];
static unsigned int ps4_ib_data_record_count;
static u64 ps4_ib_data_publish_ns;

/* Numeric validation complements the caller's retained-owner checks. Both
 * exact private VAs and the full CPU page ranges must be distinct. No CPU
 * pointer or native GART alias is used to derive the IB address.
 */
static bool ps4_ib_data_descriptors_valid(const struct amdgpu_ps4_uvd_ring *rb,
	const struct amdgpu_ps4_uvd_ring *ib)
{
	unsigned long rb_start, ib_start;

	if (!ps4_token_descriptor_valid(rb) || !ib || !ib->cpu ||
	    ((unsigned long)ib->cpu & 3U) ||
	    (unsigned long)ib->cpu > ~0UL - (PS4_UVD_IB_DATA_PAGE_BYTES - 1U) ||
	    ib->bytes != PS4_UVD_IB_DATA_PAGE_BYTES ||
	    ib->private_va != PS4_READY_IB_VA)
		return false;
	rb_start = (unsigned long)rb->cpu;
	ib_start = (unsigned long)ib->cpu;
	return rb_start > ib_start + ib->bytes - 1U ||
		ib_start > rb_start + rb->bytes - 1U;
}

static bool ps4_ib_data_inputs_valid(const struct amdgpu_ps4_uvd_ring *rb,
	const struct amdgpu_ps4_uvd_ring *ib, u64 pd_addr)
{
	return ps4_uvd_ib_data && ps4_uvd_token && ps4_uvd_ready &&
		ps4_uvd_poll_state && !ps4_uvd_data_control &&
		!ps4_uvd_status_observation &&
		ps4_ib_data_descriptors_valid(rb, ib) && pd_addr &&
		!(pd_addr & 0xfff) && (pd_addr >> 12) <= U32_MAX;
}

/* IB_DATA_CORE_SAMPLE_BEGIN: same Revision C direct sampler except that
 * IB_SIZE is required to be zero only before publication. Submitted IB_SIZE
 * is recorded raw: no countdown, consumption or completion rule is assumed.
 */
static bool ps4_ib_data_core_sample(struct amdgpu_device *adev,
			    struct ps4_token_sample *s, enum ps4_token_phase phase,
			    u64 pd_addr, u32 cache_vmid, u32 fault_base, int reset_base)
{
	*s = (struct ps4_token_sample) { 0 };
	/* Every field printed by CORE is sampled, even on an early rejection. */
	s->status = RREG32(mmUVD_STATUS);
	s->mastint = RREG32(mmUVD_MASTINT_EN);
	s->rbc = RREG32(mmUVD_RBC_RB_CNTL);
	s->ib_size = RREG32(mmUVD_RBC_IB_SIZE);
	s->wptr = RREG32(mmUVD_RBC_RB_WPTR);
	s->rptr = RREG32(mmUVD_RBC_RB_RPTR);
	s->context = RREG32(mmUVD_CONTEXT_ID);
	s->wptr_cntl = RREG32(mmUVD_RBC_RB_WPTR_CNTL);
	s->rptr_addr = RREG32(mmUVD_RBC_RB_RPTR_ADDR);
	s->fault = RREG32(mmVM_CONTEXT1_PROTECTION_FAULT_STATUS);
	s->reset_count = atomic_read(&adev->gpu_reset_counter);
	s->in_reset = amdgpu_in_reset(adev);
	s->pd = RREG32(mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR + 4);
#define TOKEN_SAVED(reg, got, want) \
	if (!ps4_token_expect(s, 0, reg, got, ~0U, want)) return false
	/* STOBS: submitted-phase STATUS additionally tolerates exactly bit16.
	 * The comparison observes bit16; it does not prove busy semantics,
	 * GPCOM naming, DMA quiescence or any Liverpool field specification.
	 */
	if (!ps4_stobs_status_expect(s, phase))
		return false;
	TOKEN_SAVED(mmUVD_MASTINT_EN, s->mastint, UVD_MASTINT_EN__VCPU_EN_MASK);
	TOKEN_SAVED(mmUVD_RBC_RB_CNTL, s->rbc,
		phase == PS4_TOKEN_HELD ? PS4_TOKEN_RBC_HELD : PS4_TOKEN_RBC_FETCH);
	if (phase != PS4_TOKEN_SUBMITTED)
		TOKEN_SAVED(mmUVD_RBC_IB_SIZE, s->ib_size, 0);
	TOKEN_SAVED(mmUVD_RBC_RB_WPTR_CNTL, s->wptr_cntl, 0);
	TOKEN_SAVED(mmUVD_RBC_RB_RPTR_ADDR, s->rptr_addr, 0);
	TOKEN_SAVED(mmUVD_RBC_RB_WPTR, s->wptr,
		phase == PS4_TOKEN_SUBMITTED ? PS4_UVD_SUBMIT_DWORDS : 0);
	if (phase != PS4_TOKEN_SUBMITTED) {
		TOKEN_SAVED(mmUVD_RBC_RB_RPTR, s->rptr, 0);
	} else if (s->rptr > PS4_UVD_SUBMIT_DWORDS) {
		return ps4_token_expect(s, 3, mmUVD_RBC_RB_RPTR,
					s->rptr, ~0U, PS4_UVD_SUBMIT_DWORDS);
	}
	TOKEN_SAVED(mmVM_CONTEXT1_PROTECTION_FAULT_STATUS, s->fault, fault_base);
	TOKEN_SAVED(mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR + 4, s->pd, pd_addr >> 12);
	if (!ps4_token_expect(s, 2, 1, s->reset_count, ~0U, reset_base) ||
	    !ps4_token_expect(s, 2, 2, s->in_reset, ~0U, 0) ||
	    !ps4_token_expect(s, 2, 3, ps4_boot_buffer_funcs(adev), ~0U, 0) ||
	    !ps4_token_expect(s, 2, 4, ps4_boot_accel(adev), ~0U, 0))
		return false;
#define TOKEN_REG(reg, mask, want) \
	if (!ps4_token_expect(s, 0, reg, RREG32(reg), mask, want)) return false
	TOKEN_REG(PS4_READY_UVD_VCPU_CACHE_VMID, ~0U, cache_vmid);
	TOKEN_REG(mmUVD_LMI_RBC_RB_VMID, ~0U, 4);
	TOKEN_REG(mmUVD_LMI_RBC_IB_VMID, ~0U, 4);
	TOKEN_REG(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_LOW, ~0U, lower_32_bits(PS4_READY_VCPU_VA));
	TOKEN_REG(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_HIGH, ~0U, upper_32_bits(PS4_READY_VCPU_VA));
	TOKEN_REG(mmUVD_LMI_RBC_RB_64BIT_BAR_LOW, ~0U, lower_32_bits(PS4_READY_RB_VA));
	TOKEN_REG(mmUVD_LMI_RBC_RB_64BIT_BAR_HIGH, ~0U, upper_32_bits(PS4_READY_RB_VA));
	TOKEN_REG(mmUVD_LMI_RBC_IB_64BIT_BAR_LOW, ~0U, lower_32_bits(PS4_READY_IB_VA));
	TOKEN_REG(mmUVD_LMI_RBC_IB_64BIT_BAR_HIGH, ~0U, upper_32_bits(PS4_READY_IB_VA));
	TOKEN_REG(mmUVD_VCPU_CACHE_OFFSET0, ~0U, 0);
	TOKEN_REG(mmUVD_VCPU_CACHE_SIZE0, ~0U, 0x7d000);
	TOKEN_REG(mmUVD_VCPU_CACHE_OFFSET1, ~0U, 0xfa00);
	TOKEN_REG(mmUVD_VCPU_CACHE_SIZE1, ~0U, 0x40000);
	TOKEN_REG(mmUVD_VCPU_CACHE_OFFSET2, ~0U, 0x17a00);
	TOKEN_REG(mmUVD_VCPU_CACHE_SIZE2, ~0U, 0x120800);
	TOKEN_REG(mmUVD_LMI_SWAP_CNTL, ~0U, 0);
	TOKEN_REG(mmUVD_MP_SWAP_CNTL, ~0U, 0);
	TOKEN_REG(mmUVD_LMI_ADDR_EXT, ~0U, 0);
	TOKEN_REG(mmUVD_LMI_EXT40_ADDR, ~0U, 0);
	TOKEN_REG(mmUVD_SOFT_RESET, PS4_READY_HOLD, 0);
	TOKEN_REG(mmUVD_LMI_CTRL2, UVD_LMI_CTRL2__STALL_ARB_UMC_MASK, 0);
	/* Indexed context reads moved after the window (STOBS review B1);
	 * ps4_stobs_ctx_sweep performs the identical frozen block.
	 */
#undef TOKEN_REG
#undef TOKEN_SAVED
	return true;
}
/* IB_DATA_CORE_SAMPLE_END */

static bool ps4_ib_data_baselines(struct ps4_data_sample *sample)
{
	return ps4_token_expect(&sample->core, 0, mmUVD_GPCOM_VCPU_DATA0,
		sample->data, ~0U, PS4_IBDATA_BASELINE) &&
		ps4_token_expect(&sample->core, 0, mmUVD_CONTEXT_ID,
			sample->core.context, ~0U, PS4_IBDATA_CONTEXT_BASELINE);
}

/* The exact direct core sequence, DATA0 last, then the marker allowances.
 * Public UVD5 bit0 and the previously observed bit16 are recorded under
 * the frozen submitted STATUS predicate. No Liverpool semantics follow.
 */
static bool ps4_ib_data_monitor(struct amdgpu_device *adev,
	struct ps4_data_sample *sample, u64 pd_addr, u32 cache_vmid,
	u32 fault_base, int reset_base, bool *bit16)
{
	bool valid = ps4_ib_data_core_sample(adev, &sample->core,
		PS4_TOKEN_SUBMITTED, pd_addr, cache_vmid, fault_base, reset_base);

	sample->data = RREG32(mmUVD_GPCOM_VCPU_DATA0);
	*bit16 = !!(sample->core.status & PS4_STOBS_BIT16);
	if (!valid)
		return false;
	if (sample->data != PS4_IBDATA_BASELINE &&
	    sample->data != PS4_IBDATA_VALUE)
		return ps4_token_expect(&sample->core, 0,
			mmUVD_GPCOM_VCPU_DATA0, sample->data, ~0U,
			PS4_IBDATA_VALUE);
	return ps4_token_expect(&sample->core, 0, mmUVD_CONTEXT_ID,
		sample->core.context, ~0U, PS4_IBDATA_CONTEXT_BASELINE);
}

static const char *ps4_ib_data_guard_result(const struct ps4_data_sample *s)
{
	if (s->core.bad_kind == 0 &&
	    s->core.bad_reg == mmUVD_GPCOM_VCPU_DATA0)
		return "IBDATA_UNEXPECTED_VALUE";
	if (s->core.bad_kind == 0 && s->core.bad_reg == mmUVD_CONTEXT_ID)
		return "IBDATA_UNEXPECTED_CONTEXT";
	if (s->core.bad_kind == 0 && s->core.bad_reg == mmUVD_STATUS)
		return "IBDATA_STATUS_UNEXPECTED";
	return "IBDATA_CORE_GUARD";
}

/* This classification uses qualifying in-window samples only. Endpoint
 * reads never create data_seen, transport_seen or confirmation evidence.
 */
static const char *ps4_ib_data_evidence_class(
	const struct ps4_ib_data_progress *progress)
{
	if (progress->confirmed)
		return "IBDATA_MARKER_OBSERVED";
	if (progress->data_seen)
		return "IBDATA_MARKER_UNCONFIRMED";
	if (progress->bit16_seen)
		return "IBDATA_STATUS_WITHOUT_MARKER";
	if (progress->transport_seen)
		return "IBDATA_DRAINED_NO_MARKER";
	return "IBDATA_NO_TRANSPORT";
}

static void ps4_ib_data_print_sample(struct amdgpu_device *adev,
	const char *tag, const struct ps4_data_sample *sample, bool valid)
{
	const struct ps4_token_sample *s = &sample->core;

	dev_info(adev->dev,
		"PS4_UVD_IBDATA %s sampled=all_then_data0 status=%08x int=%08x rbc=%08x ib=%08x wp=%08x rp=%08x ctx=%08x data=%08x wpc=%08x rpa=%08x fault=%08x reset=%u in_reset=%u pd=%08x valid=%d\n",
		tag, s->status, s->mastint, s->rbc, s->ib_size, s->wptr,
		s->rptr, s->context, sample->data, s->wptr_cntl, s->rptr_addr,
		s->fault, s->reset_count, s->in_reset, s->pd, valid);
}

static void ps4_ib_data_print_guard(struct amdgpu_device *adev,
	const char *tag, const struct ps4_token_sample *s)
{
	if (s->failed)
		dev_err(adev->dev,
			"PS4_UVD_IBDATA %s kind=%u reg=%08x value=%08x mask=%08x expected=%08x; saved deciding read\n",
			tag, s->bad_kind, s->bad_reg, s->bad_value,
			s->bad_mask, s->bad_expected);
}

static __noreturn void ps4_ib_data_stop(struct amdgpu_device *adev,
	const char *result, int error, const struct ps4_data_sample *failing,
	const struct ps4_ib_data_progress *progress, bool enabled, bool submitted,
	u64 elapsed, u64 pd_addr, u32 cache_vmid, u32 fault_base, int reset_base,
	bool with_final, const char *end_reason)
{
	struct ps4_data_sample final = { 0 };
	struct ps4_token_sample sweep = { 0 };
	const char *evidence_class = ps4_ib_data_evidence_class(progress);
	bool final_valid = false, sweep_ran = false, sweep_valid = false;
	bool final_bit16 = false;
	u32 i, predeadline_records = 0;

	/* Only a completed bounded window permits further GPU/UVD reads.
	 * All final accesses precede the first print. Invalid final direct
	 * state or a later observation regression prohibits the indexed sweep.
	 * A failed sweep is terminal, not a successful marker outcome. Its
	 * endpoint check does not establish indexed validity during the window.
	 */
	if (with_final) {
		final_valid = ps4_ib_data_monitor(adev, &final, pd_addr,
			cache_vmid, fault_base, reset_base, &final_bit16);
		if (!final_valid) {
			result = "IBDATA_FINAL_GUARD";
			error = -EIO;
		} else if (final.core.rptr < progress->last_rptr) {
			result = "IBDATA_POINTER_REGRESSION";
			error = -EIO;
		} else if (progress->observed_data_seen &&
			   final.data == PS4_IBDATA_BASELINE) {
			result = "IBDATA_MARKER_REGRESSION";
			error = -EIO;
		} else {
			sweep_ran = true;
			sweep_valid = ps4_stobs_ctx_sweep(adev, &sweep);
			if (!sweep_valid) {
				result = "IBDATA_CTX_SWEEP_GUARD";
				error = -EIO;
			} else {
				result = evidence_class;
				error = progress->confirmed ? 0 :
					(!progress->data_seen && progress->bit16_seen ?
					 -EIO : -ETIMEDOUT);
			}
		}
	}
	if (with_final) {
		ps4_ib_data_print_sample(adev, "FINAL_CORE", &final, final_valid);
		ps4_ib_data_print_guard(adev, "FINAL_GUARD", &final.core);
		if (sweep_ran) {
			dev_info(adev->dev,
				"PS4_UVD_IBDATA CTX_SWEEP valid=%d kind=%u reg=%08x value=%08x mask=%08x expected=%08x\n",
				sweep_valid, sweep.bad_kind, sweep.bad_reg,
				sweep.bad_value, sweep.bad_mask, sweep.bad_expected);
		}
	}
	if (failing) {
		ps4_ib_data_print_sample(adev, "SAVED", failing,
			!failing->core.failed);
		ps4_ib_data_print_guard(adev, "GUARD", &failing->core);
	}
	for (i = 0; i < ps4_ib_data_record_count; ++i) {
		const struct ps4_ib_data_record *r = &ps4_ib_data_log[i];

		if (r->valid && r->predeadline)
			++predeadline_records;
		dev_info(adev->dev,
			"PS4_UVD_IBDATA REC i=%u elapsed_ns=%llu t_end_ns=%llu valid=%d predeadline=%d status=%08x int=%08x rbc=%08x ib=%08x wp=%08x rp=%08x ctx=%08x data=%08x wpc=%08x rpa=%08x fault=%08x reset=%u in_reset=%u pd=%08x bit16=%d\n",
			i, (unsigned long long)r->elapsed_ns,
			(unsigned long long)r->elapsed_end_ns,
			r->valid, r->predeadline, r->sample.core.status,
			r->sample.core.mastint, r->sample.core.rbc,
			r->sample.core.ib_size, r->sample.core.wptr,
			r->sample.core.rptr, r->sample.core.context, r->sample.data,
			r->sample.core.wptr_cntl, r->sample.core.rptr_addr,
			r->sample.core.fault, r->sample.core.reset_count,
			r->sample.core.in_reset, r->sample.core.pd, r->bit16);
	}
	dev_info(adev->dev,
		"PS4_UVD_IBDATA EVIDENCE class=%s valid_samples=%u data_seen=%d transport_seen=%d consecutive=%u joint_samples=%u confirmed=%d first_data_ns=%llu first_data_end_ns=%llu first_transport_ns=%llu first_joint_ns=%llu confirmed_ns=%llu; complete valid predeadline sequential reads only, endpoint cannot create evidence\n",
		evidence_class, progress->valid_samples, progress->data_seen,
		progress->transport_seen, progress->consecutive,
		progress->joint_samples, progress->confirmed,
		(unsigned long long)progress->first_data_ns,
		(unsigned long long)progress->first_data_end_ns,
		(unsigned long long)progress->first_transport_ns,
		(unsigned long long)progress->first_joint_ns,
		(unsigned long long)progress->confirmed_ns);
	dev_info(adev->dev,
		"PS4_UVD_IBDATA END result=%s error=%d end_reason=%s enabled=%d submitted=%d elapsed_ns=%llu publish_ns=%llu records=%u predeadline_records=%u observed_data_seen=%d last_rp=%u bit16_seen=%d final_sampled=%d final_ib=%08x final_valid=%d sweep_ran=%d sweep_valid=%d marker_observed=%d accepted=0; one publication, retained, no message/decode/containment/quiescence claim\n",
		result, error, end_reason, enabled, submitted,
		(unsigned long long)elapsed,
		(unsigned long long)ps4_ib_data_publish_ns,
		ps4_ib_data_record_count, predeadline_records,
		progress->observed_data_seen, progress->last_rptr,
		progress->bit16_seen, with_final, final.core.ib_size,
		final_valid, sweep_ran, sweep_valid,
		with_final && !error && progress->confirmed);
	ps4_ready_park(adev, result, error);
}

/* One publication; four direct stores in this flow. The main ring contains
 * only IB LOW/HIGH/SIZE and NOP. DATA0 result exists only in the IB page.
 * CPU register stores plant baselines, enable empty fetch and publish WPTR.
 */
static __noreturn void ps4_ib_data_run(struct amdgpu_device *adev,
	const struct amdgpu_ps4_uvd_ring *rb,
	const struct amdgpu_ps4_uvd_ring *ib, u64 pd_addr, u32 cache_vmid,
	u32 fault_base, int reset_base)
{
	struct ps4_uvd_ib_data_plan plan;
	struct ps4_uvd_ib_data_request request;
	struct ps4_data_sample sample;
	struct ps4_ib_data_progress progress = { 0 };
	u64 started, elapsed;
	u32 readback;
	bool valid, bit16;

	ps4_ib_data_record_count = 0;
	ps4_ib_data_publish_ns = 0;
	if (!ps4_ib_data_inputs_valid(rb, ib, pd_addr))
		ps4_ib_data_stop(adev, "IBDATA_DESCRIPTOR_OR_GATES", -EINVAL,
			NULL, &progress, false, false, 0, pd_addr, cache_vmid,
			fault_base, reset_base, false, "prepublication");
	if (!ps4_data_sample(adev, &sample, PS4_TOKEN_HELD, pd_addr,
			     cache_vmid, fault_base, reset_base))
		ps4_ib_data_stop(adev, "IBDATA_PRECONDITION", -EIO,
			&sample, &progress, false, false, 0, pd_addr, cache_vmid,
			fault_base, reset_base, false, "prepublication");
	if (sample.data == PS4_IBDATA_VALUE)
		ps4_ib_data_stop(adev, "IBDATA_STALE_RESULT", -EBUSY,
			&sample, &progress, false, false, 0, pd_addr, cache_vmid,
			fault_base, reset_base, false, "prepublication");
	request = (struct ps4_uvd_ib_data_request) {
		.ring_gpu_base = rb->private_va, .ib_gpu_base = ib->private_va,
		.baseline = PS4_IBDATA_BASELINE, .token = PS4_IBDATA_VALUE,
		.data_before_baseline = sample.data,
		.initial_rptr_raw = sample.core.rptr,
		.initial_wptr_raw = sample.core.wptr,
	};
	if (ps4_uvd_ib_data_build(rb->cpu, rb->bytes, ib->cpu, ib->bytes,
				 request, &plan) != PS4_UVD_IB_DATA_OK)
		ps4_ib_data_stop(adev, "IBDATA_PLAN_REJECTED", -EINVAL,
			&sample, &progress, false, false, 0, pd_addr, cache_vmid,
			fault_base, reset_base, false, "prepublication");
	dev_info(adev->dev,
		"PS4_UVD_IBDATA PREPARED ring_bytes=%u ib_bytes=%u submit_dw=%u ib_length_dw=%u rb_va=%llx ib_va=%llx data_baseline=%08x data_value=%08x context_baseline=%08x ring_crc=%08x ib_crc=%08x; DATA0 result exists only in IB, UVD5 addressing remains a hypothesis\n",
		plan.ring_bytes, plan.ib_bytes, plan.submitted_dwords,
		plan.ib_length_dw_raw, rb->private_va, ib->private_va,
		PS4_IBDATA_BASELINE, PS4_IBDATA_VALUE,
		PS4_IBDATA_CONTEXT_BASELINE,
		crc32_le(~0U, rb->cpu, rb->bytes) ^ ~0U,
		crc32_le(~0U, ib->cpu, ib->bytes) ^ ~0U);
	WREG32(mmUVD_GPCOM_VCPU_DATA0, PS4_IBDATA_BASELINE);
	readback = RREG32(mmUVD_GPCOM_VCPU_DATA0);
	if (readback != PS4_IBDATA_BASELINE) {
		dev_err(adev->dev,
			"PS4_UVD_IBDATA BASELINE_DIRECT reg=%08x value=%08x expected=%08x; no CORE resample\n",
			mmUVD_GPCOM_VCPU_DATA0, readback, PS4_IBDATA_BASELINE);
		ps4_ib_data_stop(adev, "IBDATA_BASELINE_READBACK", -EIO,
			NULL, &progress, false, false, 0, pd_addr, cache_vmid,
			fault_base, reset_base, false, "prepublication");
	}
	WREG32(mmUVD_CONTEXT_ID, PS4_IBDATA_CONTEXT_BASELINE);
	readback = RREG32(mmUVD_CONTEXT_ID);
	if (readback != PS4_IBDATA_CONTEXT_BASELINE) {
		dev_err(adev->dev,
			"PS4_UVD_IBDATA BASELINE_DIRECT reg=%08x value=%08x expected=%08x; no CORE resample\n",
			mmUVD_CONTEXT_ID, readback, PS4_IBDATA_CONTEXT_BASELINE);
		ps4_ib_data_stop(adev, "IBDATA_CONTEXT_BASELINE_READBACK", -EIO,
			NULL, &progress, false, false, 0, pd_addr, cache_vmid,
			fault_base, reset_base, false, "prepublication");
	}
	dev_info(adev->dev,
		"PS4_UVD_IBDATA CPU_BASELINES observed data=%08x context=%08x; fetch remains inhibited\n",
		PS4_IBDATA_BASELINE, readback);
	mb();
	amdgpu_device_flush_hdp(adev, NULL);
	if (!ps4_data_sample(adev, &sample, PS4_TOKEN_HELD, pd_addr,
			     cache_vmid, fault_base, reset_base) ||
	    !ps4_ib_data_baselines(&sample))
		ps4_ib_data_stop(adev, "IBDATA_BASELINE_OR_PUBLICATION_GUARD",
			-EIO, &sample, &progress, false, false, 0, pd_addr,
			cache_vmid, fault_base, reset_base, false, "prepublication");
	dev_info(adev->dev,
		"PS4_UVD_IBDATA ENABLE_BEGIN held_baselines=data:%08x/context:%08x; empty ring only, next write clears NO_FETCH\n",
		sample.data, sample.core.context);
	started = ktime_get_ns();
	WREG32(mmUVD_RBC_RB_CNTL, PS4_TOKEN_RBC_FETCH);
	valid = ps4_data_sample(adev, &sample, PS4_TOKEN_EMPTY, pd_addr,
				cache_vmid, fault_base, reset_base);
	elapsed = ktime_get_ns() - started;
	if (elapsed >= PS4_IBDATA_LIMIT_NS)
		ps4_ib_data_stop(adev, "IBDATA_ENABLE_TIMEOUT", -ETIMEDOUT,
			&sample, &progress, true, false, elapsed, pd_addr,
			cache_vmid, fault_base, reset_base, false, "prepublication");
	if (!valid || !ps4_ib_data_baselines(&sample))
		ps4_ib_data_stop(adev, "IBDATA_ENABLE_GUARD", -EIO,
			&sample, &progress, true, false, elapsed, pd_addr,
			cache_vmid, fault_base, reset_base, false, "prepublication");
	dev_info(adev->dev,
		"PS4_UVD_IBDATA PUBLICATION_BEGIN empty_baselines=data:%08x/context:%08x elapsed_ns=%llu; next write sole WPTR16 after direct baseline and deadline recheck; no SUBMITTED print\n",
		sample.data, sample.core.context, (unsigned long long)elapsed);
	mb();
	elapsed = ktime_get_ns() - started;
	if (elapsed >= PS4_IBDATA_LIMIT_NS)
		ps4_ib_data_stop(adev, "IBDATA_BEFORE_SUBMIT_TIMEOUT", -ETIMEDOUT,
			&sample, &progress, true, false, elapsed, pd_addr,
			cache_vmid, fault_base, reset_base, false, "prepublication");
	/* Direct-only strict EMPTY guard; no print between this read and WPTR. */
	valid = ps4_ib_data_core_sample(adev, &sample.core, PS4_TOKEN_EMPTY,
		pd_addr, cache_vmid, fault_base, reset_base);
	sample.data = RREG32(mmUVD_GPCOM_VCPU_DATA0);
	elapsed = ktime_get_ns() - started;
	if (!valid || !ps4_ib_data_baselines(&sample))
		ps4_ib_data_stop(adev, "IBDATA_PREPUBLICATION_GUARD", -EIO,
			&sample, &progress, true, false, elapsed, pd_addr,
			cache_vmid, fault_base, reset_base, false, "prepublication");
	elapsed = ktime_get_ns() - started;
	if (elapsed >= PS4_IBDATA_LIMIT_NS)
		ps4_ib_data_stop(adev, "IBDATA_BEFORE_SUBMIT_TIMEOUT", -ETIMEDOUT,
			&sample, &progress, true, false, elapsed, pd_addr,
			cache_vmid, fault_base, reset_base, false, "prepublication");
	WREG32(mmUVD_RBC_RB_WPTR, plan.publish_wptr_raw);
	ps4_ib_data_publish_ns = ktime_get_ns() - started;
	for (;;) {
		u64 t_begin, t_end;
		bool joint;

		t_begin = ktime_get_ns() - started;
		if (t_begin >= PS4_IBDATA_LIMIT_NS)
			ps4_ib_data_stop(adev, "IBDATA_WINDOW_COMPLETED", 0,
				NULL, &progress, true, true, t_begin, pd_addr,
				cache_vmid, fault_base, reset_base, true, "deadline");
		if (ps4_ib_data_record_count >= PS4_IBDATA_RECORDS)
			ps4_ib_data_stop(adev, "IBDATA_RECORD_OVERFLOW", -EINVAL,
				NULL, &progress, true, true, t_begin, pd_addr,
				cache_vmid, fault_base, reset_base, false, "fault");
		valid = ps4_ib_data_monitor(adev, &sample, pd_addr, cache_vmid,
			fault_base, reset_base, &bit16);
		t_end = ktime_get_ns() - started;
		ps4_ib_data_log[ps4_ib_data_record_count++] =
			(struct ps4_ib_data_record) { .elapsed_ns = t_begin,
				.elapsed_end_ns = t_end, .sample = sample,
				.valid = valid, .predeadline = t_end < PS4_IBDATA_LIMIT_NS,
				.bit16 = bit16 };
		if (!valid)
			ps4_ib_data_stop(adev, ps4_ib_data_guard_result(&sample),
				-EIO, &sample, &progress, true, true, t_end, pd_addr,
				cache_vmid, fault_base, reset_base, false, "fault");
		/* Even a late sample can expose a regression. It cannot create
		 * qualifying evidence. These observations remain sequential.
		 */
		if (sample.core.rptr < progress.last_rptr)
			ps4_ib_data_stop(adev, "IBDATA_POINTER_REGRESSION", -EIO,
				&sample, &progress, true, true, t_end, pd_addr,
				cache_vmid, fault_base, reset_base, false, "fault");
		if (progress.observed_data_seen && sample.data == PS4_IBDATA_BASELINE)
			ps4_ib_data_stop(adev, "IBDATA_MARKER_REGRESSION", -EIO,
				&sample, &progress, true, true, t_end, pd_addr,
				cache_vmid, fault_base, reset_base, false, "fault");
		progress.last_rptr = sample.core.rptr;
		progress.observed_data_seen |= sample.data == PS4_IBDATA_VALUE;
		if (t_end >= PS4_IBDATA_LIMIT_NS)
			ps4_ib_data_stop(adev, "IBDATA_WINDOW_COMPLETED", 0,
				&sample, &progress, true, true, t_end, pd_addr,
				cache_vmid, fault_base, reset_base, true, "deadline");
		++progress.valid_samples;
		progress.bit16_seen |= bit16;
		if (!progress.data_seen && sample.data == PS4_IBDATA_VALUE) {
			progress.data_seen = true;
			progress.first_data_ns = t_begin;
			progress.first_data_end_ns = t_end;
		}
		if (!progress.transport_seen &&
		    sample.core.rptr == PS4_UVD_IB_DATA_SUBMIT_DWORDS &&
		    sample.core.wptr == PS4_UVD_IB_DATA_SUBMIT_DWORDS) {
			progress.transport_seen = true;
			progress.first_transport_ns = t_begin;
		}
		joint = sample.data == PS4_IBDATA_VALUE &&
			sample.core.rptr == PS4_UVD_IB_DATA_SUBMIT_DWORDS &&
			sample.core.wptr == PS4_UVD_IB_DATA_SUBMIT_DWORDS;
		if (joint) {
			if (!progress.joint_samples)
				progress.first_joint_ns = t_begin;
			++progress.joint_samples;
			++progress.consecutive;
			if (progress.consecutive >= 2 && !progress.confirmed) {
				progress.confirmed = true;
				progress.confirmed_ns = t_end;
			}
		} else {
			progress.consecutive = 0;
		}
		if (ps4_ib_data_record_count == PS4_IBDATA_RECORDS)
			ps4_ib_data_stop(adev, "IBDATA_WINDOW_COMPLETED", 0,
				NULL, &progress, true, true, t_end, pd_addr,
				cache_vmid, fault_base, reset_base, true, "record_budget");
		if (ps4_ib_data_record_count < PS4_IBDATA_FINE_SAMPLES)
			usleep_range(PS4_IBDATA_FINE_SLEEP_LOW,
				     PS4_IBDATA_FINE_SLEEP_HIGH);
		else
			usleep_range(PS4_IBDATA_COARSE_SLEEP_LOW,
				     PS4_IBDATA_COARSE_SLEEP_HIGH);
	}
}
/* IB_DATA_FLOW_END */

/* MESSAGE_CREATE_FLOW_BEGIN */
/*
 * Original Linux psX boot-only CREATE/fence controller, MIT, 2026.
 * Packet and message source adaptations retain their own complete notices.
 * A returned result leaves firmware, mappings and the engine retained.
 * Two observations qualify only this sequence, not message parsing or decode.
 */
#define PS4_CREATE_SEQUENCE 0x55564343U
#define PS4_CREATE_CONTEXT_BASELINE 0x43435443U
#define PS4_CREATE_FENCE_BASELINE 0x43465243U
#define PS4_CREATE_GUARD 0xc3e7a16dU
#define PS4_CREATE_LIMIT_NS (250ULL * NSEC_PER_MSEC)
#define PS4_CREATE_SLEEP_LOW 1000U
#define PS4_CREATE_SLEEP_HIGH 2000U

static const char *ps4_create_name(enum ps4_create_terminal terminal)
{
	switch (terminal) {
#define CREATE_NAME(s) case PS4_CREATE_##s: return "CREATE_" #s
	CREATE_NAME(NONE);
	CREATE_NAME(NOT_AUTHORIZED);
	CREATE_NAME(INPUTS);
	CREATE_NAME(PLAN);
	CREATE_NAME(HISTORY_BASELINE);
	CREATE_NAME(HELD_GUARD);
	CREATE_NAME(STALE);
	CREATE_NAME(BASELINE);
	CREATE_NAME(MEMORY);
	CREATE_NAME(ENABLE_TIMEOUT);
	CREATE_NAME(ENABLE_GUARD);
	CREATE_NAME(PREPUBLICATION_TIMEOUT);
	CREATE_NAME(PREPUBLICATION_GUARD);
	CREATE_NAME(HISTORY_CHANGED);
	CREATE_NAME(SUBMITTED_GUARD);
	CREATE_NAME(FENCE_UNEXPECTED);
	CREATE_NAME(CONTEXT_UNEXPECTED);
	CREATE_NAME(POINTER_REGRESSION);
	CREATE_NAME(FENCE_REGRESSION);
	CREATE_NAME(CONTEXT_REGRESSION);
	CREATE_NAME(TIMEOUT);
	CREATE_NAME(SAMPLE_LIMIT);
	CREATE_NAME(FINAL_GUARD);
	CREATE_NAME(FINAL_VALUES);
	CREATE_NAME(FINAL_HISTORY);
	CREATE_NAME(CTX_SWEEP);
	CREATE_NAME(FENCE_OBSERVED);
#undef CREATE_NAME
	}
	return "CREATE_INVALID";
}

static bool ps4_create_descriptors_valid(const struct amdgpu_ps4_uvd_ring *rb,
					const struct amdgpu_ps4_uvd_ring *backing,
					u64 pd_addr)
{
	unsigned long ring_start, backing_start;

	if (!ps4_token_descriptor_valid(rb) || !backing || !backing->cpu ||
	    ((unsigned long)backing->cpu & 3U) ||
	    backing->bytes != PS4_UVD_JOB_BACKING_BYTES ||
	    (unsigned long)backing->cpu > ~0UL - (backing->bytes - 1) ||
	    backing->private_va != PS4_READY_IB_VA || !pd_addr ||
	    (pd_addr & 0xfffU) || (pd_addr >> 12) > U32_MAX)
		return false;
	ring_start = (unsigned long)rb->cpu;
	backing_start = (unsigned long)backing->cpu;
	return ring_start > backing_start + backing->bytes - 1 ||
		backing_start > ring_start + rb->bytes - 1;
}

static void ps4_create_save_core(struct ps4_create_saved_core *out,
				 const struct ps4_token_sample *in)
{
	*out = (struct ps4_create_saved_core) {
		.status = in->status, .mastint = in->mastint, .rbc = in->rbc,
		.ib_size = in->ib_size, .wptr = in->wptr, .rptr = in->rptr,
		.context = in->context, .wptr_cntl = in->wptr_cntl,
		.rptr_addr = in->rptr_addr, .fault = in->fault,
		.reset_count = in->reset_count, .in_reset = in->in_reset,
		.pd = in->pd, .bad_kind = in->bad_kind, .bad_reg = in->bad_reg,
		.bad_value = in->bad_value, .bad_mask = in->bad_mask,
		.bad_expected = in->bad_expected, .sampled = true, .failed = in->failed,
	};
}

/*
 * Captured history is additional evidence, never a claim of fault absence.
 * Baseline must be empty: acknowledged readiness faults are not hidden.
 * A changed arm, inactive recorder, saturation or any captured arrival fails.
 * Both snapshots live in adev; no ~1KiB snapshot on the kernel stack.
 */
static bool ps4_create_history(struct amdgpu_device *adev,
			       struct amdgpu_ps4_uvd_create_operation *op,
			       bool baseline)
{
	struct ps4_uvd_fault_snapshot *s = baseline ?
		&op->fault_baseline : &op->fault_latest;
	unsigned int i;

	amdgpu_ps4_uvd_irq_fault_snapshot(adev, s);
	++op->history_snapshots;
	if (baseline)
		op->baseline_history_collected = true;
	else
		op->latest_history_collected = true;
	op->history_reason = 0;
	if (!s->active || !s->arm_ns)
		op->history_reason = 1;
	else if (!baseline && s->arm_ns != op->fault_baseline.arm_ns)
		op->history_reason = 2;
	else if (s->history.total.saturated ||
		 s->history.unclassified_status.saturated)
		op->history_reason = 3;
	else if (s->history.total.arrivals ||
		 s->history.unclassified_status.arrivals)
		op->history_reason = 4;
	for (i = 0; !op->history_reason && i < PS4_UVD_FAULT_VMIDS; ++i) {
		if (s->history.vmid[i].saturated)
			op->history_reason = 3;
		else if (s->history.vmid[i].arrivals)
			op->history_reason = 4;
	}
	/* A copied baseline is labelled explicitly; no later snapshot is implied. */
	if (baseline)
		op->fault_latest = *s;
	if (op->history_reason && !op->first_history_reason) {
		op->first_history_reason = op->history_reason;
		op->fault_deciding = *s;
	}
	return !op->history_reason;
}

static u32 ps4_create_word(const void *cpu, u32 offset)
{
	/* Owner guarantees DWORD alignment. Volatile CPU sampling, no flush. */
	return le32_to_cpu(READ_ONCE(*(__le32 *)((u8 *)cpu + offset)));
}

static void ps4_create_put(void *cpu, u32 offset, u32 value)
{
	WRITE_ONCE(*(__le32 *)((u8 *)cpu + offset), cpu_to_le32(value));
}

static void ps4_create_initialize(struct amdgpu_ps4_uvd_create_operation *op)
{
	u32 offset;

	/* Preserve the already observed NOP padding for fetchable ring/IB pages.
	 * The remaining owned pages get a non-packet sentinel, never published.
	 */
	for (offset = 0; offset < PS4_UVD_JOB_MAIN_BYTES; offset += 4)
		ps4_create_put(op->ring_cpu, offset, (offset & 4U) ? 0 : 0x3bffU);
	for (offset = 0; offset < PS4_UVD_JOB_BACKING_BYTES; offset += 4)
		ps4_create_put(op->backing_cpu, offset, offset < PS4_UVD_MSG_PAGE_BYTES ?
			((offset & 4U) ? 0 : 0x3bffU) : PS4_CREATE_GUARD);
	memcpy(op->ring_cpu, op->plan.main_le, sizeof(op->plan.main_le));
	memcpy(op->backing_cpu, op->plan.ib_le, sizeof(op->plan.ib_le));
	memcpy((u8 *)op->backing_cpu + PS4_UVD_JOB_CREATE_OFFSET,
	       op->plan.create_le, sizeof(op->plan.create_le));
	ps4_create_put(op->backing_cpu,
		PS4_UVD_JOB_FENCE_OFFSET + PS4_UVD_JOB_FENCE_TARGET_OFFSET,
		PS4_CREATE_FENCE_BASELINE);
	op->ring_crc = crc32_le(~0U, op->ring_cpu, PS4_UVD_JOB_MAIN_BYTES) ^ ~0U;
	op->ib_crc = crc32_le(~0U, op->backing_cpu, PS4_UVD_MSG_PAGE_BYTES) ^ ~0U;
	op->message_before_crc = crc32_le(~0U, op->plan.create_le,
					 PS4_UVD_MSG_PAGE_BYTES) ^ ~0U;
}

static bool ps4_create_memory_bad(struct amdgpu_ps4_uvd_create_operation *op,
				  u32 region, u32 offset, u32 value, u32 expected)
{
	if (value == expected)
		return false;
	if (!op->memory_bad_region) {
		op->memory_bad_region = region;
		op->memory_bad_offset = offset;
		op->memory_bad_value = value;
		op->memory_bad_expected = expected;
	}
	return true;
}

/*
 * Sequential CPU observations of the complete owned ring/backing ranges.
 * Message-page mutations after submission are recorded separately; the ABI
 * does not establish that page as immutable. No claim covers other mappings.
 * Target fence is sampled once per poll/endpoint; scans skip its changing word.
 */
static bool ps4_create_memory(struct amdgpu_ps4_uvd_create_operation *op,
			      bool before_publication)
{
	u32 offset, value, expected;
	bool bad = false;

	for (offset = 0; offset < PS4_UVD_JOB_MAIN_BYTES; offset += 4) {
		expected = offset < sizeof(op->plan.main_le) ?
			get_unaligned_le32(op->plan.main_le + offset) :
			((offset & 4U) ? 0 : 0x3bffU);
		bad |= ps4_create_memory_bad(op, 1, offset,
			ps4_create_word(op->ring_cpu, offset), expected);
	}
	op->message_changed_words = 0;
	for (offset = 0; offset < PS4_UVD_JOB_BACKING_BYTES; offset += 4) {
		if (offset == PS4_UVD_JOB_FENCE_OFFSET + PS4_UVD_JOB_FENCE_TARGET_OFFSET)
			continue;
		value = ps4_create_word(op->backing_cpu, offset);
		if (offset >= PS4_UVD_JOB_CREATE_OFFSET &&
		    offset < PS4_UVD_JOB_CREATE_OFFSET + PS4_UVD_MSG_PAGE_BYTES) {
			expected = get_unaligned_le32(op->plan.create_le +
						      offset - PS4_UVD_JOB_CREATE_OFFSET);
			if (value != expected) {
				if (!op->message_changed_words) {
					op->message_first_offset = offset - PS4_UVD_JOB_CREATE_OFFSET;
					op->message_first_before = expected;
					op->message_first_after = value;
				}
				++op->message_changed_words;
				if (before_publication)
					bad |= ps4_create_memory_bad(op, 3, offset, value, expected);
			}
			continue;
		}
		expected = offset < sizeof(op->plan.ib_le) ?
			get_unaligned_le32(op->plan.ib_le + offset) :
			(offset < PS4_UVD_MSG_PAGE_BYTES ?
			 ((offset & 4U) ? 0 : 0x3bffU) : PS4_CREATE_GUARD);
		bad |= ps4_create_memory_bad(op, 2, offset, value, expected);
	}
	op->message_after_crc = crc32_le(~0U,
		(u8 *)op->backing_cpu + PS4_UVD_JOB_CREATE_OFFSET,
		PS4_UVD_MSG_PAGE_BYTES) ^ ~0U;
	op->memory_scanned = true;
	return !bad;
}

static u32 ps4_create_fence(struct amdgpu_ps4_uvd_create_operation *op)
{
	return ps4_create_word(op->backing_cpu,
		PS4_UVD_JOB_FENCE_OFFSET + PS4_UVD_JOB_FENCE_TARGET_OFFSET);
}

static struct ps4_create_result
ps4_create_finish(struct amdgpu_ps4_uvd_create_operation *op,
		  enum ps4_create_terminal terminal, int error)
{
	op->result = (struct ps4_create_result) { terminal, error };
	if (op->enable_entered && !op->end_ns)
		op->end_ns = ktime_get_ns() - op->started_ns;
	op->completed = true;
	return op->result;
}

/*
 * Private finite controller. Its wrapper has already claimed the global boot
 * latch and readiness has returned the convention observation. Deadline starts
 * before fetch enable. Readiness/firmware I/O and terminal reporting are outside
 * that bound; sequential samples ending at/after the deadline never qualify.
 */
static struct ps4_create_result
ps4_create_run(struct amdgpu_device *adev,
	       const struct amdgpu_ps4_uvd_ring *rb,
	       const struct amdgpu_ps4_uvd_ring *backing,
	       u64 pd_addr, u32 cache_vmid, u32 fault_base, int reset_base)
{
	struct amdgpu_ps4_uvd_create_operation *op = &adev->ps4_uvd_create_operation;
	struct amdgpu_ps4_uvd_ready_operation *ready = &adev->ps4_uvd_ready_operation;
	struct ps4_uvd_message_job_input input;
	struct ps4_token_sample sample;
	enum ps4_create_terminal terminal;
	u64 elapsed, begin;
	bool valid, history_valid, joint;
	int error = -EIO;

	/* Preserve the first operation on denied entry/reentry. */
	if (op->entered || !ready->boot_claimed || !ready->completed ||
	    ready->result.terminal != PS4_READY_CORE_READY_CONVENTION_OBSERVED ||
	    ready->result.error)
		return (struct ps4_create_result) { PS4_CREATE_NOT_AUTHORIZED, -EPERM };
	op->entered = true;
	if (!ps4_uvd_message_create ||
	    !amdgpu_ps4_uvd_message_create_options_valid(adev) ||
	    !ps4_create_descriptors_valid(rb, backing, pd_addr))
		return ps4_create_finish(op, PS4_CREATE_INPUTS, -EINVAL);
	op->ring_cpu = rb->cpu;
	op->backing_cpu = backing->cpu;
	op->ring_va = rb->private_va;
	op->backing_va = backing->private_va;
	op->pd_addr = pd_addr;
	input = (struct ps4_uvd_message_job_input) {
		.vcpu_segment_base = PS4_READY_VCPU_VA,
		.main_va = rb->private_va, .backing_va = backing->private_va,
		.main_bytes = rb->bytes, .backing_bytes = backing->bytes,
		.handle = 1, .sequence = PS4_CREATE_SEQUENCE,
	};
	if (ps4_uvd_message_job_build(&op->plan, &input))
		return ps4_create_finish(op, PS4_CREATE_PLAN, -EINVAL);
	if (!ps4_create_history(adev, op, true))
		return ps4_create_finish(op, PS4_CREATE_HISTORY_BASELINE, -EBUSY);
	valid = ps4_ib_data_core_sample(adev, &sample, PS4_TOKEN_HELD,
		pd_addr, cache_vmid, fault_base, reset_base);
	ps4_create_save_core(&op->core, &sample);
	if (valid) {
		op->initial_sweep_attempted = true;
		op->initial_sweep_valid = ps4_stobs_ctx_sweep(adev, &sample);
		ps4_create_save_core(&op->sweep, &sample);
	}
	if (!valid || !op->initial_sweep_valid) {
		return ps4_create_finish(op, PS4_CREATE_HELD_GUARD, -EIO);
	}
	op->fence = ps4_create_fence(op);
	if (sample.context == PS4_CREATE_SEQUENCE || op->fence == PS4_CREATE_SEQUENCE)
		return ps4_create_finish(op, PS4_CREATE_STALE, -ESTALE);
	op->memory_write_entered = true;
	ps4_create_initialize(op);
	op->memory_initialized = true;
	WREG32(mmUVD_CONTEXT_ID, PS4_CREATE_CONTEXT_BASELINE);
	op->baseline_readback = RREG32(mmUVD_CONTEXT_ID);
	op->fence = ps4_create_fence(op);
	if (op->baseline_readback != PS4_CREATE_CONTEXT_BASELINE ||
	    op->fence != PS4_CREATE_FENCE_BASELINE)
		return ps4_create_finish(op, PS4_CREATE_BASELINE, -EIO);
	mb();
	amdgpu_device_flush_hdp(adev, NULL);
	valid = ps4_ib_data_core_sample(adev, &sample, PS4_TOKEN_HELD,
		pd_addr, cache_vmid, fault_base, reset_base);
	ps4_create_save_core(&op->core, &sample);
	if (!valid || sample.context != PS4_CREATE_CONTEXT_BASELINE)
		return ps4_create_finish(op, PS4_CREATE_HELD_GUARD, -EIO);
	if (!ps4_create_memory(op, true))
		return ps4_create_finish(op, PS4_CREATE_MEMORY, -EIO);
	if (!ps4_create_history(adev, op, false))
		return ps4_create_finish(op, PS4_CREATE_HISTORY_CHANGED, -EIO);
	dev_info(adev->dev,
		"PS4_UVD_CREATE PREPARED ring=%llx ib=%llx message=%llx fence=%llx ring_crc=%08x ib_crc=%08x message_crc=%08x handle=1 sequence=%08x deadline_ns=%llu samples=%u; one CREATE and prefix fence, parsing unproved\n",
		op->ring_va, op->plan.layout.ib_va, op->plan.layout.create_va,
		op->plan.layout.fence_target_va, op->ring_crc, op->ib_crc,
		op->message_before_crc, PS4_CREATE_SEQUENCE,
		(unsigned long long)PS4_CREATE_LIMIT_NS, PS4_CREATE_RECORDS);
	op->started_ns = ktime_get_ns();
	op->enable_entered = true;
	WREG32(mmUVD_RBC_RB_CNTL, PS4_TOKEN_RBC_FETCH);
	valid = ps4_ib_data_core_sample(adev, &sample, PS4_TOKEN_EMPTY,
		pd_addr, cache_vmid, fault_base, reset_base);
	ps4_create_save_core(&op->core, &sample);
	elapsed = ktime_get_ns() - op->started_ns;
	if (!valid || sample.context != PS4_CREATE_CONTEXT_BASELINE)
		return ps4_create_finish(op, PS4_CREATE_ENABLE_GUARD, -EIO);
	if (elapsed >= PS4_CREATE_LIMIT_NS)
		return ps4_create_finish(op, PS4_CREATE_ENABLE_TIMEOUT, -ETIMEDOUT);
	if (!ps4_create_history(adev, op, false))
		return ps4_create_finish(op, PS4_CREATE_HISTORY_CHANGED, -EIO);
	mb();
	if (ktime_get_ns() - op->started_ns >= PS4_CREATE_LIMIT_NS)
		return ps4_create_finish(op, PS4_CREATE_PREPUBLICATION_TIMEOUT, -ETIMEDOUT);
	/* Final direct guard, no indexed store or print before sole publication. */
	valid = ps4_ib_data_core_sample(adev, &sample, PS4_TOKEN_EMPTY,
		pd_addr, cache_vmid, fault_base, reset_base);
	ps4_create_save_core(&op->core, &sample);
	op->fence = ps4_create_fence(op);
	if (!valid || sample.context != PS4_CREATE_CONTEXT_BASELINE ||
	    op->fence != PS4_CREATE_FENCE_BASELINE)
		return ps4_create_finish(op, PS4_CREATE_PREPUBLICATION_GUARD, -EIO);
	if (!ps4_create_history(adev, op, false))
		return ps4_create_finish(op, PS4_CREATE_HISTORY_CHANGED, -EIO);
	op->publish_before_ns = ktime_get_ns() - op->started_ns;
	if (op->publish_before_ns >= PS4_CREATE_LIMIT_NS)
		return ps4_create_finish(op, PS4_CREATE_PREPUBLICATION_TIMEOUT, -ETIMEDOUT);
	op->submitted = true;
	++op->publication_count;
	WREG32(mmUVD_RBC_RB_WPTR, PS4_UVD_JOB_MAIN_DW);
	op->publish_after_ns = ktime_get_ns() - op->started_ns;
	terminal = PS4_CREATE_TIMEOUT;
	error = -ETIMEDOUT;
	for (;;) {
		struct ps4_create_record *record;

		begin = ktime_get_ns() - op->started_ns;
		if (begin >= PS4_CREATE_LIMIT_NS)
			break;
		if (op->records >= PS4_CREATE_RECORDS) {
			terminal = PS4_CREATE_SAMPLE_LIMIT;
			error = -ENOSPC;
			break;
		}
		valid = ps4_ib_data_core_sample(adev, &sample, PS4_TOKEN_SUBMITTED,
			pd_addr, cache_vmid, fault_base, reset_base);
		ps4_create_save_core(&op->core, &sample);
		op->fence = ps4_create_fence(op);
		history_valid = ps4_create_history(adev, op, false);
		elapsed = ktime_get_ns() - op->started_ns;
		joint = op->fence == PS4_CREATE_SEQUENCE &&
			sample.context == PS4_CREATE_SEQUENCE &&
			sample.rptr == PS4_UVD_JOB_MAIN_DW &&
			sample.wptr == PS4_UVD_JOB_MAIN_DW;
		record = &op->log[op->records++];
		*record = (struct ps4_create_record) {
			.begin_ns = begin, .end_ns = elapsed,
			.fault_arrivals = op->fault_latest.history.total.arrivals,
			.status = sample.status, .rptr = sample.rptr, .wptr = sample.wptr,
			.ib_size = sample.ib_size, .context = sample.context,
			.fence = op->fence, .core_valid = valid, .history_valid = history_valid,
			.predeadline = elapsed < PS4_CREATE_LIMIT_NS, .joint = joint,
		};
		/* Even late observations retain explicit faults/regressions. */
		if (!valid) {
			terminal = PS4_CREATE_SUBMITTED_GUARD;
			error = -EIO;
			break;
		}
		if (!history_valid) {
			terminal = PS4_CREATE_HISTORY_CHANGED;
			error = -EIO;
			break;
		}
		if (op->fence != PS4_CREATE_FENCE_BASELINE &&
		    op->fence != PS4_CREATE_SEQUENCE) {
			terminal = PS4_CREATE_FENCE_UNEXPECTED;
			error = -EIO;
			break;
		}
		if (sample.context != PS4_CREATE_CONTEXT_BASELINE &&
		    sample.context != PS4_CREATE_SEQUENCE) {
			terminal = PS4_CREATE_CONTEXT_UNEXPECTED;
			error = -EIO;
			break;
		}
		if (sample.rptr < op->last_rptr) {
			terminal = PS4_CREATE_POINTER_REGRESSION;
			error = -EIO;
			break;
		}
		if (op->fence_seen && op->fence == PS4_CREATE_FENCE_BASELINE) {
			terminal = PS4_CREATE_FENCE_REGRESSION;
			error = -EIO;
			break;
		}
		if (op->context_seen && sample.context == PS4_CREATE_CONTEXT_BASELINE) {
			terminal = PS4_CREATE_CONTEXT_REGRESSION;
			error = -EIO;
			break;
		}
		op->last_rptr = sample.rptr;
		op->fence_seen |= op->fence == PS4_CREATE_SEQUENCE;
		op->context_seen |= sample.context == PS4_CREATE_SEQUENCE;
		if (elapsed >= PS4_CREATE_LIMIT_NS)
			break;
		++op->valid_samples;
		if (joint) {
			++op->joint_samples;
			++op->consecutive;
		} else {
			op->consecutive = 0;
		}
		if (op->consecutive == 2) {
			op->confirmed_ns = elapsed;
			terminal = PS4_CREATE_FENCE_OBSERVED;
			error = 0;
			break;
		}
		usleep_range(PS4_CREATE_SLEEP_LOW, PS4_CREATE_SLEEP_HIGH);
	}
	/*
	 * Endpoint checks are outside the two-observation qualification window.
	 * Preserve the first fault; a clean observation/timeout gets endpoint
	 * direct reads, then at most one indexed sweep only on valid direct reads.
	 * No further GPU/UVD access occurs after this controller returns.
	 */
	if (terminal == PS4_CREATE_FENCE_OBSERVED || terminal == PS4_CREATE_TIMEOUT ||
	    terminal == PS4_CREATE_SAMPLE_LIMIT) {
		op->endpoint_valid = ps4_ib_data_core_sample(adev, &sample,
			PS4_TOKEN_SUBMITTED, pd_addr, cache_vmid, fault_base, reset_base);
		ps4_create_save_core(&op->core, &sample);
		op->fence = ps4_create_fence(op);
		if (!op->endpoint_valid) {
			terminal = PS4_CREATE_FINAL_GUARD;
			error = -EIO;
		} else if (op->fence != PS4_CREATE_FENCE_BASELINE &&
			   op->fence != PS4_CREATE_SEQUENCE) {
			terminal = PS4_CREATE_FENCE_UNEXPECTED;
			error = -EIO;
		} else if (sample.context != PS4_CREATE_CONTEXT_BASELINE &&
			   sample.context != PS4_CREATE_SEQUENCE) {
			terminal = PS4_CREATE_CONTEXT_UNEXPECTED;
			error = -EIO;
		} else if (sample.rptr < op->last_rptr) {
			terminal = PS4_CREATE_POINTER_REGRESSION;
			error = -EIO;
		} else if (op->fence_seen && op->fence == PS4_CREATE_FENCE_BASELINE) {
			terminal = PS4_CREATE_FENCE_REGRESSION;
			error = -EIO;
		} else if (op->context_seen && sample.context == PS4_CREATE_CONTEXT_BASELINE) {
			terminal = PS4_CREATE_CONTEXT_REGRESSION;
			error = -EIO;
		} else {
			op->sweep_attempted = true;
			op->sweep_valid = ps4_stobs_ctx_sweep(adev, &sample);
			ps4_create_save_core(&op->sweep, &sample);
			if (!op->sweep_valid) {
				terminal = PS4_CREATE_CTX_SWEEP;
				error = -EIO;
			}
		}
		if (!error &&
		    (op->fence != PS4_CREATE_SEQUENCE || sample.context != PS4_CREATE_SEQUENCE ||
		     sample.rptr != PS4_UVD_JOB_MAIN_DW || sample.wptr != PS4_UVD_JOB_MAIN_DW)) {
			terminal = PS4_CREATE_FINAL_VALUES;
			error = -EIO;
		}
	}
	/* Guard scan and final software history snapshot also precede reporting. */
	if (!ps4_create_memory(op, false) && (!error || terminal == PS4_CREATE_TIMEOUT ||
					     terminal == PS4_CREATE_SAMPLE_LIMIT)) {
		terminal = PS4_CREATE_MEMORY;
		error = -EIO;
	}
	history_valid = ps4_create_history(adev, op, false);
	if (!history_valid && (!error || terminal == PS4_CREATE_TIMEOUT ||
			       terminal == PS4_CREATE_SAMPLE_LIMIT)) {
		terminal = PS4_CREATE_FINAL_HISTORY;
		error = -EIO;
	}
	op->end_ns = ktime_get_ns() - op->started_ns;
	return ps4_create_finish(op, terminal, error);
}

static void ps4_create_report_deciding_history(struct amdgpu_device *adev,
					       const struct ps4_uvd_fault_snapshot *s)
{
	const struct ps4_uvd_fault_bucket *b = &s->history.total;
	unsigned int i;

	dev_info(adev->dev,
		"PS4_UVD_CREATE FAULT_DECIDING active=%u arm=%llu total=%llu saturated=%u first=%08x/%08x/%08x last=%08x/%08x/%08x\n",
		s->active, (unsigned long long)s->arm_ns,
		(unsigned long long)b->arrivals, b->saturated,
		b->first.addr, b->first.status, b->first.mc_client,
		b->last.addr, b->last.status, b->last.mc_client);
	for (i = 0; i <= PS4_UVD_FAULT_VMIDS; ++i) {
		b = i < PS4_UVD_FAULT_VMIDS ?
			&s->history.vmid[i] : &s->history.unclassified_status;
		if (b->arrivals || b->saturated)
			dev_info(adev->dev,
				"PS4_UVD_CREATE FAULT_DECIDING_BUCKET index=%u unknown_index=16 total=%llu saturated=%u first=%08x/%08x/%08x last=%08x/%08x/%08x\n",
				i, (unsigned long long)b->arrivals, b->saturated,
				b->first.addr, b->first.status, b->first.mc_client,
				b->last.addr, b->last.status, b->last.mc_client);
	}
}

static void ps4_create_report(struct amdgpu_device *adev)
{
	const struct amdgpu_ps4_uvd_create_operation *op = &adev->ps4_uvd_create_operation;
	const struct ps4_create_saved_core *s = &op->core;
	unsigned int i;

	/* Saved CPU data only. No UVD/GPU register access after reporting starts. */
	dev_info(adev->dev,
		"PS4_UVD_CREATE CORE sampled=%u status=%08x int=%08x rbc=%08x ib=%08x rp=%u wp=%u context=%08x fault=%08x reset_count=%u reset=%u pd=%08x\n",
		s->sampled, s->status, s->mastint, s->rbc, s->ib_size, s->rptr, s->wptr,
		s->context, s->fault, s->reset_count, s->in_reset, s->pd);
	if (s->failed)
		dev_err(adev->dev, "PS4_UVD_CREATE GUARD kind=%u reg=%08x value=%08x mask=%08x expected=%08x\n",
			s->bad_kind, s->bad_reg, s->bad_value, s->bad_mask, s->bad_expected);
	if (op->sweep.failed)
		dev_err(adev->dev, "PS4_UVD_CREATE CTX_GUARD initial_attempted=%u endpoint_attempted=%u kind=%u reg=%08x value=%08x mask=%08x expected=%08x\n",
			op->initial_sweep_attempted, op->sweep_attempted, op->sweep.bad_kind, op->sweep.bad_reg,
			op->sweep.bad_value, op->sweep.bad_mask, op->sweep.bad_expected);
	dev_info(adev->dev,
		"PS4_UVD_CREATE MEMORY write_entered=%u initialized=%u scanned=%u bad_region=%u offset=%08x expected=%08x value=%08x message_changed_words=%u first_offset=%08x before=%08x after=%08x message_crc_before=%08x after=%08x; message mutation is raw evidence\n",
		op->memory_write_entered, op->memory_initialized, op->memory_scanned,
		op->memory_bad_region, op->memory_bad_offset, op->memory_bad_expected,
		op->memory_bad_value, op->message_changed_words, op->message_first_offset,
		op->message_first_before, op->message_first_after,
		op->message_before_crc, op->message_after_crc);
	dev_info(adev->dev,
		"PS4_UVD_CREATE HISTORY snapshots=%u baseline_collected=%u latest_collected=%u first_reason=%u latest_reason=%u baseline_active=%u arm=%llu total=%llu latest_active=%u arm=%llu total=%llu saturated=%u unknown=%llu; latest is baseline copy until collected, zero is not fault absence\n",
		op->history_snapshots, op->baseline_history_collected, op->latest_history_collected,
		op->first_history_reason, op->history_reason, op->fault_baseline.active,
		(unsigned long long)op->fault_baseline.arm_ns,
		(unsigned long long)op->fault_baseline.history.total.arrivals,
		op->fault_latest.active, (unsigned long long)op->fault_latest.arm_ns,
		(unsigned long long)op->fault_latest.history.total.arrivals,
		op->fault_latest.history.total.saturated,
		(unsigned long long)op->fault_latest.history.unclassified_status.arrivals);
	if (op->first_history_reason)
		ps4_create_report_deciding_history(adev, &op->fault_deciding);
	if (op->fault_latest.history.total.arrivals ||
	    op->fault_latest.history.total.saturated) {
		const struct ps4_uvd_fault_bucket *b = &op->fault_latest.history.total;

		dev_info(adev->dev,
			"PS4_UVD_CREATE FAULT_TOTAL first=%08x/%08x/%08x last=%08x/%08x/%08x\n",
			b->first.addr, b->first.status, b->first.mc_client,
			b->last.addr, b->last.status, b->last.mc_client);
	}
	if (op->fault_latest.history.unclassified_status.arrivals ||
	    op->fault_latest.history.unclassified_status.saturated) {
		const struct ps4_uvd_fault_bucket *b = &op->fault_latest.history.unclassified_status;

		dev_info(adev->dev,
			"PS4_UVD_CREATE FAULT_UNKNOWN total=%llu saturated=%u first=%08x/%08x/%08x last=%08x/%08x/%08x\n",
			(unsigned long long)b->arrivals, b->saturated,
			b->first.addr, b->first.status, b->first.mc_client,
			b->last.addr, b->last.status, b->last.mc_client);
	}
	for (i = 0; i < PS4_UVD_FAULT_VMIDS; ++i) {
		const struct ps4_uvd_fault_bucket *b = &op->fault_latest.history.vmid[i];

		if (b->arrivals || b->saturated)
			dev_info(adev->dev,
				"PS4_UVD_CREATE FAULT_VMID vmid=%u total=%llu saturated=%u first=%08x/%08x/%08x last=%08x/%08x/%08x\n",
				i, (unsigned long long)b->arrivals, b->saturated,
				b->first.addr, b->first.status, b->first.mc_client,
				b->last.addr, b->last.status, b->last.mc_client);
	}
	for (i = 0; i < op->records; ++i) {
		const struct ps4_create_record *r = &op->log[i];

		dev_info(adev->dev,
			"PS4_UVD_CREATE REC n=%u begin_ns=%llu end_ns=%llu status=%08x rp=%u wp=%u ib=%u context=%08x fence=%08x fault_total=%llu core_valid=%u history_valid=%u predeadline=%u joint=%u\n",
			i, (unsigned long long)r->begin_ns, (unsigned long long)r->end_ns,
			r->status, r->rptr, r->wptr, r->ib_size, r->context, r->fence,
			(unsigned long long)r->fault_arrivals, r->core_valid,
			r->history_valid, r->predeadline, r->joint);
	}
	dev_info(adev->dev,
		"PS4_UVD_CREATE END result=%s error=%d entered=%u enabled=%u submitted=%u publications=%u records=%u valid=%u joint=%u consecutive=%u publish_before_ns=%llu publish_after_ns=%llu confirmed_ns=%llu end_ns=%llu endpoint=%u sweep_attempted=%u sweep_valid=%u baseline_readback=%08x fence=%08x; retained, no parse/session/decode/quiescence claim\n",
		ps4_create_name(op->result.terminal), op->result.error, op->entered,
		op->enable_entered, op->submitted, op->publication_count, op->records,
		op->valid_samples, op->joint_samples, op->consecutive,
		(unsigned long long)op->publish_before_ns,
		(unsigned long long)op->publish_after_ns,
		(unsigned long long)op->confirmed_ns, (unsigned long long)op->end_ns,
		op->endpoint_valid, op->sweep_attempted, op->sweep_valid,
		op->baseline_readback, op->fence);
}
/* MESSAGE_CREATE_FLOW_END */

/* FRAME_CORE_SAMPLE_BEGIN: same Revision C direct sampler except that
 * IB_SIZE is required to be zero only before publication. Submitted IB_SIZE
 * is recorded raw: no countdown, consumption or completion rule is assumed.
 */
static bool ps4_frame_core_sample(struct amdgpu_device *adev,
			    struct ps4_token_sample *s, enum ps4_token_phase phase,
			    u64 pd_addr, u32 cache_vmid, u32 fault_base, int reset_base, u32 published_dw)
{
	u32 ib_low, expected_ib_low = lower_32_bits(PS4_READY_IB_VA);
	u32 previous_ib_low = expected_ib_low;

	/* Main PACKET0 IB_LOW/HIGH writes change the same BARs sampled
	 * below. Each append owns its distinct IB. While in flight the
	 * previous/current low is admissible; a consumed whole portion
	 * must expose the current address. All addresses share high3.
	 */
	if (phase == PS4_TOKEN_SUBMITTED && published_dw >= 32) {
		expected_ib_low += published_dw == 32 ? 0x80U : 0x100U;
		previous_ib_low = expected_ib_low - 0x80U;
	}
	*s = (struct ps4_token_sample) { 0 };
	/* Every field printed by CORE is sampled, even on an early rejection. */
	s->status = RREG32(mmUVD_STATUS);
	s->mastint = RREG32(mmUVD_MASTINT_EN);
	s->rbc = RREG32(mmUVD_RBC_RB_CNTL);
	s->ib_size = RREG32(mmUVD_RBC_IB_SIZE);
	s->wptr = RREG32(mmUVD_RBC_RB_WPTR);
	s->rptr = RREG32(mmUVD_RBC_RB_RPTR);
	s->context = RREG32(mmUVD_CONTEXT_ID);
	s->wptr_cntl = RREG32(mmUVD_RBC_RB_WPTR_CNTL);
	s->rptr_addr = RREG32(mmUVD_RBC_RB_RPTR_ADDR);
	s->fault = RREG32(mmVM_CONTEXT1_PROTECTION_FAULT_STATUS);
	s->reset_count = atomic_read(&adev->gpu_reset_counter);
	s->in_reset = amdgpu_in_reset(adev);
	s->pd = RREG32(mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR + 4);
#define TOKEN_SAVED(reg, got, want) \
	if (!ps4_token_expect(s, 0, reg, got, ~0U, want)) return false
	/* STOBS: submitted-phase STATUS additionally tolerates exactly bit16.
	 * The comparison observes bit16; it does not prove busy semantics,
	 * GPCOM naming, DMA quiescence or any Liverpool field specification.
	 */
	if (!ps4_stobs_status_expect(s, phase))
		return false;
	TOKEN_SAVED(mmUVD_MASTINT_EN, s->mastint, UVD_MASTINT_EN__VCPU_EN_MASK);
	TOKEN_SAVED(mmUVD_RBC_RB_CNTL, s->rbc,
		phase == PS4_TOKEN_HELD ? PS4_TOKEN_RBC_HELD : PS4_TOKEN_RBC_FETCH);
	if (phase != PS4_TOKEN_SUBMITTED)
		TOKEN_SAVED(mmUVD_RBC_IB_SIZE, s->ib_size, 0);
	TOKEN_SAVED(mmUVD_RBC_RB_WPTR_CNTL, s->wptr_cntl, 0);
	TOKEN_SAVED(mmUVD_RBC_RB_RPTR_ADDR, s->rptr_addr, 0);
	TOKEN_SAVED(mmUVD_RBC_RB_WPTR, s->wptr,
		phase == PS4_TOKEN_SUBMITTED ? published_dw : 0);
	if (phase != PS4_TOKEN_SUBMITTED) {
		TOKEN_SAVED(mmUVD_RBC_RB_RPTR, s->rptr, 0);
	} else if (s->rptr > published_dw) {
		return ps4_token_expect(s, 3, mmUVD_RBC_RB_RPTR,
					s->rptr, ~0U, published_dw);
	}
	TOKEN_SAVED(mmVM_CONTEXT1_PROTECTION_FAULT_STATUS, s->fault, fault_base);
	TOKEN_SAVED(mmVM_CONTEXT0_PAGE_TABLE_BASE_ADDR + 4, s->pd, pd_addr >> 12);
	if (!ps4_token_expect(s, 2, 1, s->reset_count, ~0U, reset_base) ||
	    !ps4_token_expect(s, 2, 2, s->in_reset, ~0U, 0) ||
	    !ps4_token_expect(s, 2, 3, ps4_boot_buffer_funcs(adev), ~0U, 0) ||
	    !ps4_token_expect(s, 2, 4, ps4_boot_accel(adev), ~0U, 0))
		return false;
#define TOKEN_REG(reg, mask, want) \
	if (!ps4_token_expect(s, 0, reg, RREG32(reg), mask, want)) return false
	TOKEN_REG(PS4_READY_UVD_VCPU_CACHE_VMID, ~0U, cache_vmid);
	TOKEN_REG(mmUVD_LMI_RBC_RB_VMID, ~0U, 4);
	TOKEN_REG(mmUVD_LMI_RBC_IB_VMID, ~0U, 4);
	TOKEN_REG(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_LOW, ~0U, lower_32_bits(PS4_READY_VCPU_VA));
	TOKEN_REG(mmUVD_LMI_VCPU_CACHE_64BIT_BAR_HIGH, ~0U, upper_32_bits(PS4_READY_VCPU_VA));
	TOKEN_REG(mmUVD_LMI_RBC_RB_64BIT_BAR_LOW, ~0U, lower_32_bits(PS4_READY_RB_VA));
	TOKEN_REG(mmUVD_LMI_RBC_RB_64BIT_BAR_HIGH, ~0U, upper_32_bits(PS4_READY_RB_VA));
	ib_low = RREG32(mmUVD_LMI_RBC_IB_64BIT_BAR_LOW);
	if (ib_low != expected_ib_low &&
	    (phase != PS4_TOKEN_SUBMITTED || s->rptr == published_dw ||
	     ib_low != previous_ib_low))
		return ps4_token_expect(s, 0, mmUVD_LMI_RBC_IB_64BIT_BAR_LOW,
			ib_low, ~0U, expected_ib_low);
	TOKEN_REG(mmUVD_LMI_RBC_IB_64BIT_BAR_HIGH, ~0U, upper_32_bits(PS4_READY_IB_VA));
	TOKEN_REG(mmUVD_VCPU_CACHE_OFFSET0, ~0U, 0);
	TOKEN_REG(mmUVD_VCPU_CACHE_SIZE0, ~0U, 0x7d000);
	TOKEN_REG(mmUVD_VCPU_CACHE_OFFSET1, ~0U, 0xfa00);
	TOKEN_REG(mmUVD_VCPU_CACHE_SIZE1, ~0U, 0x40000);
	TOKEN_REG(mmUVD_VCPU_CACHE_OFFSET2, ~0U, 0x17a00);
	TOKEN_REG(mmUVD_VCPU_CACHE_SIZE2, ~0U, 0x120800);
	TOKEN_REG(mmUVD_LMI_SWAP_CNTL, ~0U, 0);
	TOKEN_REG(mmUVD_MP_SWAP_CNTL, ~0U, 0);
	TOKEN_REG(mmUVD_LMI_ADDR_EXT, ~0U, 0);
	TOKEN_REG(mmUVD_LMI_EXT40_ADDR, ~0U, 0);
	TOKEN_REG(mmUVD_SOFT_RESET, PS4_READY_HOLD, 0);
	TOKEN_REG(mmUVD_LMI_CTRL2, UVD_LMI_CTRL2__STALL_ARB_UMC_MASK, 0);
	/* Indexed context reads moved after the window (STOBS review B1);
	 * ps4_stobs_ctx_sweep performs the identical frozen block.
	 */
#undef TOKEN_REG
#undef TOKEN_SAVED
	return true;
}
/* FRAME_CORE_SAMPLE_END */
static bool ps4_frame_history(struct amdgpu_device *adev,
			       struct amdgpu_ps4_uvd_frame_operation *op,
			       bool baseline)
{
	struct ps4_uvd_fault_snapshot *s = baseline ?
		&op->fault_baseline : &op->fault_latest;
	unsigned int i;

	amdgpu_ps4_uvd_irq_fault_snapshot(adev, s);
	++op->history_snapshots;
	if (baseline)
		op->baseline_history_collected = true;
	else
		op->latest_history_collected = true;
	op->history_reason = 0;
	if (!s->active || !s->arm_ns)
		op->history_reason = 1;
	else if (!baseline && s->arm_ns != op->fault_baseline.arm_ns)
		op->history_reason = 2;
	else if (s->history.total.saturated ||
		 s->history.unclassified_status.saturated)
		op->history_reason = 3;
	else if (s->history.total.arrivals ||
		 s->history.unclassified_status.arrivals)
		op->history_reason = 4;
	for (i = 0; !op->history_reason && i < PS4_UVD_FAULT_VMIDS; ++i) {
		if (s->history.vmid[i].saturated)
			op->history_reason = 3;
		else if (s->history.vmid[i].arrivals)
			op->history_reason = 4;
	}
	/* A copied baseline is labelled explicitly; no later snapshot is implied. */
	if (baseline)
		op->fault_latest = *s;
	if (op->history_reason && !op->first_history_reason) {
		op->first_history_reason = op->history_reason;
		op->fault_deciding = *s;
	}
	return !op->history_reason;
}

/* DECODE_FRAME_FLOW_BEGIN */
/* SPDX-License-Identifier: MIT
 * Linux psX, 2026. One fixed-reference picture through the public legacy UVD
 * ABI. Startup and transport remain explicit Liverpool working assumptions.
 * No normal DRM submission, DMA drain/free, reset, retry or rearm is added.
 * All three main-ring portions are prepared once, then appended 16/32/48.
 */
#define PS4_FRAME_GUARD 0xd4c3b2a1U
#define PS4_FRAME_BASE_CONTEXT 0x46524230U
#define PS4_FRAME_LIMIT_NS (2ULL * NSEC_PER_SEC)
#define PS4_FRAME_MAX_POLLS 2048U

static bool ps4_frame_descriptors_valid(const struct amdgpu_ps4_uvd_ring *rb,
					const struct amdgpu_ps4_uvd_ring *work,
					u64 pd_addr)
{
	unsigned long a, b;

	if (!ps4_token_descriptor_valid(rb) || !work || !work->cpu ||
	    ((unsigned long)work->cpu & 3U) || work->bytes != PS4_FRAME_STORAGE_BYTES ||
	    (unsigned long)work->cpu > ~0UL - (work->bytes - 1) ||
	    work->private_va != PS4_READY_IB_VA || !pd_addr ||
	    (pd_addr & 0xfffU) || (pd_addr >> 12) > U32_MAX)
		return false;
	a = (unsigned long)rb->cpu;
	b = (unsigned long)work->cpu;
	return a > b + work->bytes - 1 || b > a + rb->bytes - 1;
}

/* Public UVD5 packet adaptation uses the unchanged packet builder's notice.
 * MSG IB: DATA0/1, CMD=0, NOPs. Main: IB address/size, context, memory fence
 * prefix, NOP. The interrupt/trap suffix is deliberately omitted.
 */
static void ps4_frame_pair(u8 *bytes, u32 dw, u32 reg, u32 value)
{
	put_unaligned_le32(reg & 0xffffU, bytes + dw * 4);
	put_unaligned_le32(value, bytes + (dw + 1) * 4);
}

static void ps4_frame_message_packets(u8 *main, u8 *ib, u64 ib_va,
				      u64 message_va, u64 fence_va, u32 sequence)
{
	u32 dw;

	ps4_frame_pair(ib, 0, 0x3bc4, lower_32_bits(message_va));
	ps4_frame_pair(ib, 2, 0x3bc5, upper_32_bits(message_va));
	ps4_frame_pair(ib, 4, 0x3bc3, 0);
	for (dw = 6; dw < 16; dw += 2)
		ps4_frame_pair(ib, dw, 0x3bff, 0);
	ps4_frame_pair(main, 0, 0x3c67, lower_32_bits(ib_va));
	ps4_frame_pair(main, 2, 0x3c66, upper_32_bits(ib_va));
	ps4_frame_pair(main, 4, 0x3da2, 16);
	ps4_frame_pair(main, 6, 0x3dbd, sequence);
	ps4_frame_pair(main, 8, 0x3bc4, lower_32_bits(fence_va));
	ps4_frame_pair(main, 10, 0x3bc5, upper_32_bits(fence_va) & 0xffU);
	ps4_frame_pair(main, 12, 0x3bc3, 0);
	ps4_frame_pair(main, 14, 0x3bff, 0);
}

static int ps4_frame_plan(struct amdgpu_ps4_uvd_frame_operation *op)
{
	struct ps4_uvd_decode_input in = {
		.vcpu_segment_base = PS4_READY_VCPU_VA,
		.main_va = op->ring_va, .work_va = op->backing_va,
		.main_bytes = 4096, .work_bytes = PS4_FRAME_STORAGE_BYTES,
		.handle = 1, .fence_initial = 0x46444930U,
		.fence_sequence = 0x46524431U,
		.fixture = ps4_frame_fixture, .fixture_bytes = sizeof(ps4_frame_fixture),
	};
	u32 i;
	int r;

	sha256(in.fixture, in.fixture_bytes, in.verified_fixture_sha256);
	r = ps4_uvd_decode_reference_build(&op->plan, sizeof(op->plan), &in);
	if (r)
		return r;
	r = ps4_uvd_msg_create_avc(op->create_le, sizeof(op->create_le), 1,
				  &op->plan.create_params);
	if (r)
		return r;
	r = ps4_uvd_msg_destroy(op->destroy_le, sizeof(op->destroy_le), 1);
	if (r)
		return r;
	for (i = 0; i < PS4_FRAME_PHASES; ++i) {
		struct ps4_frame_phase *p = &op->phases[i];

		p->initial = 0x46434930U + i * 0x100U;
		p->cell = 0x40U + i * 0x40U;
		p->end_dw = 16U * (i + 1);
	}
	op->phases[0].sequence = 0x46524331U;
	op->phases[1].sequence = in.fence_sequence;
	op->phases[2].sequence = 0x46525831U;
	op->phases[1].initial = in.fence_initial;
	op->phases[0].previous_context = PS4_FRAME_BASE_CONTEXT;
	op->phases[1].previous_context = op->phases[0].sequence;
	op->phases[2].previous_context = op->phases[1].sequence;
	ps4_frame_message_packets(op->main_le, op->create_ib_le, op->backing_va,
		op->backing_va + PS4_UVD_DEC_CREATE_OFFSET,
		op->backing_va + PS4_UVD_DEC_FENCE_OFFSET + 0x40,
		op->phases[0].sequence);
	memcpy(op->main_le + 64, op->plan.main_le, 64);
	ps4_frame_message_packets(op->main_le + 128, op->destroy_ib_le,
		op->backing_va + PS4_FRAME_DESTROY_IB_OFFSET,
		op->backing_va + PS4_FRAME_DESTROY_OFFSET,
		op->backing_va + PS4_UVD_DEC_FENCE_OFFSET + 0xc0,
		op->phases[2].sequence);
	return 0;
}

static void ps4_frame_initialize(struct amdgpu_ps4_uvd_frame_operation *op)
{
	u32 off, i;
	u8 *work = op->backing_cpu;

	for (off = 0; off < 4096; off += 4)
		ps4_create_put(op->ring_cpu, off, (off & 4U) ? 0 : 0x3bffU);
	for (off = 0; off < PS4_FRAME_STORAGE_BYTES; off += 4)
		ps4_create_put(work, off, PS4_FRAME_GUARD);
	/* A full page of valid NOP pairs around the three disjoint IBs. */
	for (off = 0; off < 4096; off += 4)
		ps4_create_put(work, off, (off & 4U) ? 0 : 0x3bffU);
	memcpy(op->ring_cpu, op->main_le, sizeof(op->main_le));
	memcpy(work, op->create_ib_le, sizeof(op->create_ib_le));
	memcpy(work + PS4_UVD_DEC_IB_OFFSET, op->plan.ib_le, sizeof(op->plan.ib_le));
	memcpy(work + PS4_FRAME_DESTROY_IB_OFFSET, op->destroy_ib_le, sizeof(op->destroy_ib_le));
	memcpy(work + PS4_UVD_DEC_CREATE_OFFSET, op->create_le, 4096);
	memcpy(work + PS4_UVD_DEC_FENCE_OFFSET, op->plan.fence_page_le, 4096);
	for (i = 0; i < PS4_FRAME_PHASES; ++i)
		ps4_create_put(work, PS4_UVD_DEC_FENCE_OFFSET + op->phases[i].cell,
			       op->phases[i].initial);
	memcpy(work + PS4_UVD_DEC_MESSAGE_OFFSET, op->plan.message_le, 4096);
	memcpy(work + PS4_UVD_DEC_FEEDBACK_OFFSET, op->plan.feedback_le, 2048);
	memcpy(work + PS4_UVD_DEC_BITSTREAM_OFFSET, op->plan.bitstream_le, 4096);
	/* Device output/reference storage has a distinct deterministic baseline. */
	memset(work + PS4_UVD_DEC_TARGET_OFFSET, 0xa7, PS4_UVD_DEC_TARGET_BYTES);
	memset(work + PS4_UVD_DEC_DPB_OFFSET, 0, PS4_UVD_DEC_DPB_MAPPED_BYTES);
	memcpy(work + PS4_FRAME_DESTROY_OFFSET, op->destroy_le, 4096);
	op->initialized = true;
}

static bool ps4_frame_bad(struct amdgpu_ps4_uvd_frame_operation *op,
			  u32 region, u32 off, u32 actual, u32 expected)
{
	if (actual == expected)
		return false;
	if (!op->memory_bad_region) {
		op->memory_bad_region = region;
		op->memory_bad_offset = off;
		op->memory_bad_value = actual;
		op->memory_bad_expected = expected;
	}
	return true;
}

/* Each unsubmitted message must still match. Submitted messages are mutable
 * ABI storage; preserve CRC/delta counts. Output, DPB and feedback become
 * writable only after DECODE publication. All other DWORDs remain guarded.
 */
static bool ps4_frame_memory(struct amdgpu_ps4_uvd_frame_operation *op)
{
	u32 off, actual, expected, i;
	bool bad = false;
	u8 *work = op->backing_cpu;
	const u8 *messages[] = { op->create_le, op->plan.message_le, op->destroy_le };
	const u32 offsets[] = { 0x1000, 0x3000, PS4_FRAME_DESTROY_OFFSET };

	for (i = 0; i < 3; ++i) {
		op->message_changed[i] = 0;
		op->message_crc[i] = crc32_le(~0U, work + offsets[i], 4096) ^ ~0U;
	}
	for (off = 0; off < 4096; off += 4) {
		expected = off < sizeof(op->main_le) ? get_unaligned_le32(op->main_le + off) :
			((off & 4U) ? 0 : 0x3bffU);
		bad |= ps4_frame_bad(op, 1, off, ps4_create_word(op->ring_cpu, off), expected);
	}
	for (off = 0; off < PS4_FRAME_STORAGE_BYTES; off += 4) {
		actual = ps4_create_word(work, off);
		for (i = 0; i < 3; ++i)
			if (off >= offsets[i] && off < offsets[i] + 4096)
				break;
		if (i < 3) {
			expected = get_unaligned_le32(messages[i] + (off - offsets[i]));
			op->message_changed[i] += actual != expected;
			if (!op->phases[i].published)
				bad |= ps4_frame_bad(op, 2, off, actual, expected);
			continue;
		}
		if (off >= 0x2000 && off < 0x3000) {
			for (i = 0; i < 3; ++i)
				if (off == 0x2000 + op->phases[i].cell)
					break;
			if (i < 3) {
				/* Active fence sampled once with direct core, prior cells
				 * must stay completed; future cells must stay initial. */
				if (op->phases[i].published && !op->phases[i].completed)
					continue;
				expected = op->phases[i].completed ? op->phases[i].sequence : op->phases[i].initial;
			} else {
				expected = PS4_UVD_DEC_FENCE_GUARD;
			}
		} else if (off < 64) {
			expected = get_unaligned_le32(op->create_ib_le + off);
		} else if (off >= 0x80 && off < 0x100) {
			expected = get_unaligned_le32(op->plan.ib_le + (off - 0x80));
		} else if (off >= 0x100 && off < 0x140) {
			expected = get_unaligned_le32(op->destroy_ib_le + (off - 0x100));
		} else if (off < 4096) {
			expected = (off & 4U) ? 0 : 0x3bffU;
		} else if (off >= 0x4000 && off < 0x4800) {
			if (op->phases[1].published)
				continue;
			expected = get_unaligned_le32(op->plan.feedback_le + (off - 0x4000));
		} else if (off >= 0x5000 && off < 0x6000) {
			expected = get_unaligned_le32(op->plan.bitstream_le + (off - 0x5000));
		} else if (off >= 0x6000 && off < 0xc000) {
			if (op->phases[1].published)
				continue;
			expected = 0xa7a7a7a7U;
		} else if (off >= 0xc000 && off < PS4_FRAME_DESTROY_OFFSET) {
			if (op->phases[1].published && off < 0xc000 + PS4_UVD_DEC_DPB_BYTES)
				continue;
			/* The sub-page DPB tail remains outside declared DPB bytes. */
			expected = 0;
		} else {
			expected = PS4_FRAME_GUARD;
		}
		bad |= ps4_frame_bad(op, 2, off, actual, expected);
	}
	return !bad;
}

static struct ps4_frame_result
ps4_frame_finish(struct amdgpu_ps4_uvd_frame_operation *op, const char *name, int error)
{
	op->completed = true;
	op->result = (struct ps4_frame_result) { name, error };
	return op->result;
}

static int ps4_frame_submit(struct amdgpu_device *adev,
			    struct amdgpu_ps4_uvd_frame_operation *op,
			    u32 cache_vmid, u32 fault_base, int reset_base)
{
	struct ps4_frame_phase *p = &op->phases[op->phase];
	struct ps4_token_sample s;
	u32 previous_dw = op->phase ? op->phases[op->phase - 1].end_dw : 0;
	bool valid, history, joint;
	u64 begin, elapsed;

	if (!ps4_frame_memory(op) || !ps4_frame_history(adev, op, false))
		return -EIO;
	valid = ps4_frame_core_sample(adev, &s, op->phase ? PS4_TOKEN_SUBMITTED : PS4_TOKEN_EMPTY,
		op->pd_addr, cache_vmid, fault_base, reset_base, previous_dw);
	ps4_create_save_core(&op->core, &s);
	p->fence = ps4_create_word(op->backing_cpu, 0x2000 + p->cell);
	if (!valid || s.rptr != previous_dw || s.context != p->previous_context || p->fence != p->initial)
		return -EIO;
	if (!ps4_frame_history(adev, op, false))
		return -EIO;
	mb();
	/* One cumulative WPTR store per phase. No rewriting consumed ring bytes. */
	p->start_ns = ktime_get_ns();
	p->published = true;
	++op->publications;
	WREG32(mmUVD_RBC_RB_WPTR, p->end_dw);
	p->publish_ns = ktime_get_ns() - p->start_ns;
	p->last_rptr = previous_dw;
	for (;;) {
		struct ps4_create_record *r;

		begin = ktime_get_ns() - p->start_ns;
		if (begin >= PS4_FRAME_LIMIT_NS || p->polls >= PS4_FRAME_MAX_POLLS)
			return -ETIMEDOUT;
		valid = ps4_frame_core_sample(adev, &s, PS4_TOKEN_SUBMITTED,
			op->pd_addr, cache_vmid, fault_base, reset_base, p->end_dw);
		ps4_create_save_core(&op->core, &s);
		p->fence = ps4_create_word(op->backing_cpu, 0x2000 + p->cell);
		history = ps4_frame_history(adev, op, false);
		elapsed = ktime_get_ns() - p->start_ns;
		joint = p->fence == p->sequence && s.context == p->sequence &&
			s.rptr == p->end_dw && s.wptr == p->end_dw;
		r = &p->last[p->polls++ & 1U];
		*r = (struct ps4_create_record) {
			.begin_ns = begin, .end_ns = elapsed, .status = s.status,
			.rptr = s.rptr, .wptr = s.wptr, .ib_size = s.ib_size,
			.context = s.context, .fence = p->fence, .core_valid = valid,
			.history_valid = history, .predeadline = elapsed < PS4_FRAME_LIMIT_NS,
			.joint = joint, .fault_arrivals = op->fault_latest.history.total.arrivals,
		};
		p->end_ns = elapsed;
		if (!valid || !history || s.rptr < p->last_rptr ||
		    (p->fence != p->initial && p->fence != p->sequence) ||
		    (s.context != p->previous_context && s.context != p->sequence) ||
		    (p->fence_seen && p->fence != p->sequence) ||
		    (p->context_seen && s.context != p->sequence))
			return -EIO;
		p->last_rptr = s.rptr;
		p->fence_seen |= p->fence == p->sequence;
		p->context_seen |= s.context == p->sequence;
		if (elapsed >= PS4_FRAME_LIMIT_NS)
			return -ETIMEDOUT;
		p->joint += joint;
		p->consecutive = joint ? p->consecutive + 1 : 0;
		if (p->consecutive == 2) {
			p->confirmed_ns = elapsed;
			p->completed = true;
			/* Final guards are outside the deadline and cannot turn a
			 * timeout into completion. No next publication on a failure. */
			return ps4_frame_memory(op) && ps4_frame_history(adev, op, false) ? 0 : -EIO;
		}
		usleep_range(1000, 2000);
	}
}

/* CPU snapshot after a completed DECODE fence; 64x64 visible NV12 is gathered
 * from the public linear target with pitch256 and UV at byte16384. Padding
 * never enters the image digest. Device data is copied before reporting.
 */
static void ps4_frame_capture(struct amdgpu_ps4_uvd_frame_operation *op)
{
	u8 *device_target = (u8 *)op->backing_cpu + PS4_UVD_DEC_TARGET_OFFSET;
	u8 *device_feedback = (u8 *)op->backing_cpu + PS4_UVD_DEC_FEEDBACK_OFFSET;
	u8 *target = op->pitched;
	u32 row, x, out = 0;

	rmb();
	for (x = 0; x < sizeof(op->pitched); ++x)
		op->pitched[x] = READ_ONCE(device_target[x]);
	for (x = 0; x < sizeof(op->feedback); ++x)
		op->feedback[x] = READ_ONCE(device_feedback[x]);
	for (row = 0; row < 64; ++row)
		for (x = 0; x < 64; ++x)
			op->visible[out++] = target[row * 256 + x];
	for (row = 0; row < 32; ++row)
		for (x = 0; x < 64; ++x)
			op->visible[out++] = target[0x4000 + row * 256 + x];
	op->target_crc = crc32_le(~0U, target, PS4_UVD_DEC_TARGET_BYTES) ^ ~0U;
	op->feedback_crc = crc32_le(~0U, op->feedback, sizeof(op->feedback)) ^ ~0U;
	sha256(op->visible, sizeof(op->visible), op->visible_sha256);
	op->pixels_captured = true;
	op->pixels_match = !memcmp(op->visible_sha256, ps4_uvd_decode_expected_nv12_sha256, 32);
}

static struct ps4_frame_result
ps4_frame_run(struct amdgpu_device *adev, const struct amdgpu_ps4_uvd_ring *rb,
	      const struct amdgpu_ps4_uvd_ring *work, u64 pd_addr,
	      u32 cache_vmid, u32 fault_base, int reset_base)
{
	struct amdgpu_ps4_uvd_frame_operation *op = &adev->ps4_uvd_frame_operation;
	struct amdgpu_ps4_uvd_ready_operation *ready = &adev->ps4_uvd_ready_operation;
	struct ps4_token_sample sample;
	int r;

	if (op->entered || !ready->boot_claimed || !ready->completed ||
	    ready->result.terminal != PS4_READY_CORE_READY_CONVENTION_OBSERVED || ready->result.error)
		return (struct ps4_frame_result) { "FRAME_NOT_AUTHORIZED", -EPERM };
	op->entered = true;
	if (!ps4_uvd_decode_frame || !amdgpu_ps4_uvd_decode_frame_options_valid(adev) ||
	    !ps4_frame_descriptors_valid(rb, work, pd_addr))
		return ps4_frame_finish(op, "FRAME_INPUTS", -EINVAL);
	op->ring_cpu = rb->cpu;
	op->backing_cpu = work->cpu;
	op->ring_va = rb->private_va;
	op->backing_va = work->private_va;
	op->pd_addr = pd_addr;
	r = ps4_frame_plan(op);
	if (r)
		return ps4_frame_finish(op, "FRAME_PLAN", r);
	if (!ps4_frame_history(adev, op, true))
		return ps4_frame_finish(op, "FRAME_HISTORY_BASELINE", -EBUSY);
	if (!ps4_frame_core_sample(adev, &sample, PS4_TOKEN_HELD,
		pd_addr, cache_vmid, fault_base, reset_base, 0)) {
		ps4_create_save_core(&op->core, &sample);
		return ps4_frame_finish(op, "FRAME_HELD_GUARD", -EIO);
	}
	if (!ps4_stobs_ctx_sweep(adev, &sample)) {
		ps4_create_save_core(&op->sweep, &sample);
		return ps4_frame_finish(op, "FRAME_CONTEXT_GUARD", -EIO);
	}
	ps4_frame_initialize(op);
	WREG32(mmUVD_CONTEXT_ID, PS4_FRAME_BASE_CONTEXT);
	mb();
	amdgpu_device_flush_hdp(adev, NULL);
	if (!ps4_frame_memory(op) || !ps4_frame_history(adev, op, false))
		return ps4_frame_finish(op, "FRAME_PREPARED_GUARD", -EIO);
	if (!ps4_frame_core_sample(adev, &sample, PS4_TOKEN_HELD,
		pd_addr, cache_vmid, fault_base, reset_base, 0) || sample.context != PS4_FRAME_BASE_CONTEXT) {
		ps4_create_save_core(&op->core, &sample);
		return ps4_frame_finish(op, "FRAME_BASELINE", -EIO);
	}
	dev_info(adev->dev, "PS4_UVD_FRAME PREPARED fixture=h264-cb-idr-64x64-v1 handle=1 width=64 height=64 pitch=256 uv=16384 ring=%llx work=%llx bytes=%u phase_deadline_ns=%llu; CREATE DECODE DESTROY cumulative_wptr=16,32,48\n",
		op->ring_va, op->backing_va, PS4_FRAME_STORAGE_BYTES, (unsigned long long)PS4_FRAME_LIMIT_NS);
	op->enabled = true;
	WREG32(mmUVD_RBC_RB_CNTL, PS4_TOKEN_RBC_FETCH);
	for (op->phase = 0; op->phase < PS4_FRAME_PHASES; ++op->phase) {
		r = ps4_frame_submit(adev, op, cache_vmid, fault_base, reset_base);
		if (r) {
			/* Raw failed-run output can diagnose firmware progression.
			 * It never replaces the failed completion result. */
			if (op->phases[1].published)
				ps4_frame_capture(op);
			return ps4_frame_finish(op, r == -ETIMEDOUT ? "FRAME_PHASE_TIMEOUT" : "FRAME_PHASE_GUARD", r);
		}
		if (op->phase == 1) {
			ps4_frame_capture(op);
			if (!op->pixels_match)
				return ps4_frame_finish(op, "FRAME_PIXELS_MISMATCH", -EBADMSG);
		}
	}
	if (!ps4_frame_core_sample(adev, &sample, PS4_TOKEN_SUBMITTED,
		pd_addr, cache_vmid, fault_base, reset_base, 48) ||
	    sample.rptr != 48 || sample.context != op->phases[2].sequence) {
		ps4_create_save_core(&op->core, &sample);
		return ps4_frame_finish(op, "FRAME_FINAL_CORE", -EIO);
	}
	ps4_create_save_core(&op->core, &sample);
	if (!ps4_stobs_ctx_sweep(adev, &sample)) {
		ps4_create_save_core(&op->sweep, &sample);
		return ps4_frame_finish(op, "FRAME_FINAL_CONTEXT", -EIO);
	}
	ps4_create_save_core(&op->sweep, &sample);
	if (!ps4_frame_memory(op) || !ps4_frame_history(adev, op, false))
		return ps4_frame_finish(op, "FRAME_FINAL_MEMORY", -EIO);
	return ps4_frame_finish(op, "FRAME_REFERENCE_MATCH", 0);
}

static void ps4_frame_report(struct amdgpu_device *adev)
{
	const struct amdgpu_ps4_uvd_frame_operation *op = &adev->ps4_uvd_frame_operation;
	const struct ps4_create_saved_core *s = &op->core;
	u32 i, j;

	/* Saved CPU state only. Every GPU access ends before this report. */
	dev_info(adev->dev, "PS4_UVD_FRAME CORE status=%08x rbc=%08x ib=%u rp=%u wp=%u context=%08x fault=%08x reset_count=%u reset=%u guard=%u/%08x/%08x/%08x\n",
		s->status, s->rbc, s->ib_size, s->rptr, s->wptr, s->context, s->fault,
		s->reset_count, s->in_reset, s->bad_kind, s->bad_reg, s->bad_value, s->bad_expected);
	for (i = 0; i < 3; ++i) {
		const struct ps4_frame_phase *p = &op->phases[i];

		dev_info(adev->dev, "PS4_UVD_FRAME PHASE index=%u published=%u completed=%u end_dw=%u seq=%08x initial=%08x polls=%u joint=%u consecutive=%u publish_ns=%llu confirmed_ns=%llu end_ns=%llu message_crc=%08x changed_words=%u\n",
			i, p->published, p->completed, p->end_dw, p->sequence, p->initial,
			p->polls, p->joint, p->consecutive, p->publish_ns, p->confirmed_ns, p->end_ns,
			op->message_crc[i], op->message_changed[i]);
		for (j = 0; j < 2 && j < p->polls; ++j) {
			const struct ps4_create_record *r = &p->last[(p->polls - (p->polls > 1 ? 2 : 1) + j) & 1U];

			dev_info(adev->dev, "PS4_UVD_FRAME REC phase=%u last=%u begin_ns=%llu end_ns=%llu status=%08x rp=%u wp=%u ib=%u context=%08x fence=%08x core=%u history=%u predeadline=%u joint=%u\n",
				i, j, r->begin_ns, r->end_ns, r->status, r->rptr, r->wptr, r->ib_size,
				r->context, r->fence, r->core_valid, r->history_valid, r->predeadline, r->joint);
		}
	}
	dev_info(adev->dev, "PS4_UVD_FRAME MEMORY bad_region=%u offset=%08x expected=%08x actual=%08x feedback_crc=%08x target_crc=%08x history_snapshots=%u history_reason=%u first_history_reason=%u fault_arm=%llu fault_total=%llu\n",
		op->memory_bad_region, op->memory_bad_offset, op->memory_bad_expected, op->memory_bad_value,
		op->feedback_crc, op->target_crc, op->history_snapshots, op->history_reason,
		op->first_history_reason, op->fault_latest.arm_ns, op->fault_latest.history.total.arrivals);
	if (op->first_history_reason)
		ps4_create_report_deciding_history(adev, &op->fault_deciding);
	if (op->pixels_captured) {
		dev_info(adev->dev, "PS4_UVD_FRAME PIXELS bytes=%u sha256=%*phN expected=%*phN match=%u\n",
			PS4_FRAME_VISIBLE_BYTES, 32, op->visible_sha256, 32,
			ps4_uvd_decode_expected_nv12_sha256, op->pixels_match);
		for (i = 0; i < sizeof(op->feedback); i += 32)
			dev_info(adev->dev, "PS4_UVD_FRAME FEEDBACK offset=%u hex=%*phN\n", i, 32, op->feedback + i);
		for (i = 0; i < sizeof(op->pitched); i += 32)
			dev_info(adev->dev, "PS4_UVD_FRAME PITCHED offset=%u hex=%*phN\n", i, 32, op->pitched + i);
	}
	dev_info(adev->dev, "PS4_UVD_FRAME END result=%s error=%d entered=%u initialized=%u enabled=%u phase=%u publications=%u pixels=%u match=%u; mappings retained, no DMA quiescence/free/rearm\n",
		op->result.name ? op->result.name : "FRAME_NONE", op->result.error, op->entered,
		op->initialized, op->enabled, op->phase, op->publications, op->pixels_captured, op->pixels_match);
}
/* DECODE_FRAME_FLOW_END */

/* READY_CORE_FUNCTIONS_BEGIN */
static const char *ps4_ready_core_name(enum ps4_ready_core_terminal terminal)
{
	switch (terminal) {
	case PS4_READY_CORE_NONE: return "CORE_NONE";
	case PS4_READY_CORE_NOT_AUTHORIZED: return "CORE_NOT_AUTHORIZED";
	case PS4_READY_CORE_PREFLIGHT: return "PREFLIGHT";
	case PS4_READY_CORE_VCPU_CACHE_VMID_PREFLIGHT: return "VCPU_CACHE_VMID_PREFLIGHT";
	case PS4_READY_CORE_ATOM_PREFLIGHT: return "ATOM_PREFLIGHT";
	case PS4_READY_CORE_FIRMWARE_REQUEST: return "FIRMWARE_REQUEST";
	case PS4_READY_CORE_FIRMWARE_HEADER_CRC: return "FIRMWARE_HEADER_CRC";
	case PS4_READY_CORE_BASELINE_NOT_CLEAN: return "BASELINE_NOT_CLEAN";
	case PS4_READY_CORE_INITIAL_SETUP_PARK: return "INITIAL_SETUP_PARK";
	case PS4_READY_CORE_HELD_BASELINE: return "HELD_BASELINE";
	case PS4_READY_CORE_RBC_RELEASE_GUARD: return "RBC_RELEASE_GUARD";
	case PS4_READY_CORE_FAULT_OR_RESET: return "FAULT_OR_RESET";
	case PS4_READY_CORE_VCPU_CACHE_VMID_CHANGED: return "VCPU_CACHE_VMID_CHANGED";
	case PS4_READY_CORE_FETCH_GUARD_CHANGED: return "FETCH_GUARD_CHANGED";
	case PS4_READY_CORE_POLL_STATE_REGRESSION: return "POLL_STATE_REGRESSION";
	case PS4_READY_CORE_READY_TIMEOUT: return "READY_TIMEOUT";
	case PS4_READY_CORE_READY_CONVENTION_OBSERVED: return "READY_CONVENTION_OBSERVED";
	case PS4_READY_CORE_READY_OBSERVED: return "READY_OBSERVED";
	}
	return "CORE_INVALID_TERMINAL";
}

static struct ps4_ready_core_result
ps4_ready_core_finish(struct amdgpu_ps4_uvd_ready_operation *op,
		      enum ps4_ready_core_terminal terminal, int error)
{
	op->result = (struct ps4_ready_core_result) { terminal, error };
	op->completed = true;
	return op->result;
}

/*
 * Private returning controller, reachable only from the legacy boot wrapper.
 * A result never grants cleanup, retry, live producer coexistence or rearm.
 * The existing pre-client exclusion remains mandatory; no new caller exists.
 * The original poll deadline bounds that poll, not firmware I/O, clock helpers
 * or lock wait duration. No claim of a whole-worker wall-clock bound is made.
 */
static struct ps4_ready_core_result
ps4_ready_core_run(struct amdgpu_device *adev, void *r1_cpu,
		   size_t backing_size, u64 pd_addr)
{
	struct amdgpu_ps4_uvd_ready_operation *op = &adev->ps4_uvd_ready_operation;
	const u32 remaining_hold = PS4_READY_HOLD &
		~UVD_SOFT_RESET__RBC_SOFT_RESET_MASK;
	int r;

	/* A denied private reentry cannot erase the first retained operation. */
	if (!op->boot_claimed || op->entered)
		return (struct ps4_ready_core_result) {
			PS4_READY_CORE_NOT_AUTHORIZED, -EPERM };
	op->entered = true;
	op->retained_cpu = r1_cpu;
	op->retained_pd = pd_addr;
	op->backing_size = backing_size;
	if (!r1_cpu || backing_size != PS4_READY_BACKING_BYTES ||
	    !pd_addr || (pd_addr & (AMDGPU_GPU_PAGE_SIZE - 1)) ||
	    adev->gfx.config.gb_addr_config != 0x02011003 ||
	    ps4_boot_buffer_funcs(adev) || ps4_boot_accel(adev) ||
	    amdgpu_in_reset(adev)) {
		dev_err(adev->dev,
			"PS4_UVD_READY PREFLIGHT backing_present=%d size=%zx pd=%llx gb_addr_config=%08x expected=02011003 buffer_funcs=%d accel=%d reset=%d\n",
			!!r1_cpu, backing_size, pd_addr, adev->gfx.config.gb_addr_config,
			ps4_boot_buffer_funcs(adev), ps4_boot_accel(adev),
			amdgpu_in_reset(adev));
		return ps4_ready_core_finish(op, PS4_READY_CORE_PREFLIGHT, -EINVAL);
	}
	op->first_mmio_entered = true;
	r = ps4_ready_cache_vmid_preflight(adev, &op->cache_vmid_original);
	if (r)
		return ps4_ready_core_finish(op, PS4_READY_CORE_VCPU_CACHE_VMID_PREFLIGHT, r);
	op->cache_vmid_expected = ps4_ready_cache_vmid_owned(op->cache_vmid_original);
	r = ps4_ready_clock_preflight(adev);
	if (r)
		return ps4_ready_core_finish(op, PS4_READY_CORE_ATOM_PREFLIGHT, r);
	/* No userspace helper or alternate filename; this must be in initramfs. */
	r = request_firmware_direct(&op->firmware, PS4_READY_FW, adev->dev);
	if (r)
		return ps4_ready_core_finish(op, PS4_READY_CORE_FIRMWARE_REQUEST, r);
	r = ps4_ready_validate_firmware(op->firmware->data,
					op->firmware->size, &op->crc);
	if (r)
		return ps4_ready_core_finish(op, PS4_READY_CORE_FIRMWARE_HEADER_CRC, r);
	op->backing_write_entered = true;
	memset(r1_cpu, 0, backing_size);
	memcpy(r1_cpu, op->firmware->data + PS4_READY_PAYLOAD_OFFSET,
	       PS4_READY_PAYLOAD_BYTES);
	mb();
	op->hdp_flush_entered = true;
	amdgpu_device_flush_hdp(adev, NULL);

	dev_info(adev->dev,
		"PS4_UVD_READY BEGIN hypothesis=public5/6 vmid=4 pd=%llx backing=%zx payload=%u crc=%08x clocks=10000/10000 poll_state=%d; SDMA precheck is not UVD evidence\n",
		pd_addr, backing_size, PS4_READY_PAYLOAD_BYTES, op->crc, ps4_uvd_poll_state);
	ps4_uvd_led_mark(adev, 7);
	/* GMC7 has no global monotonic fault counter for this PASID0/vm=NULL
	 * probe: its cached fault_info is updated only for registered VMs. Reading
	 * status cannot detect an IRQ-acknowledged transient. UART remains needed.
	 */
	dev_warn(adev->dev,
		"PS4_UVD_READY FAULT_COVERAGE no usable global VM-fault counter; read-only status samples may miss IRQ-acknowledged faults\n");
	op->baseline_fault = RREG32(mmVM_CONTEXT1_PROTECTION_FAULT_STATUS);
	op->reset_count = atomic_read(&adev->gpu_reset_counter);
	dev_info(adev->dev, "PS4_UVD_READY FAULT_BASE status=%08x addr=%08x reset_count=%d\n",
		op->baseline_fault, RREG32(mmVM_CONTEXT1_PROTECTION_FAULT_ADDR), op->reset_count);
	if (op->baseline_fault || op->reset_count || (RREG32(mmUVD_STATUS) & PS4_READY_BIT))
		return ps4_ready_core_finish(op, PS4_READY_CORE_BASELINE_NOT_CLEAN, -EBUSY);
	/* Default-off recorder is armed once before any UVD setup writes. */
	op->irq_arm_entered = true;
	amdgpu_ps4_uvd_irq_arm(adev);
	op->indexed_snapshot_entered = true;
	ps4_ready_snapshot(adev, "before");
	op->setup_entered = true;
	r = ps4_ready_setup_held(adev, op->cache_vmid_original);
	if (r) {
		ps4_ready_snapshot(adev, "initial_setup_failure");
		return ps4_ready_core_finish(op, PS4_READY_CORE_INITIAL_SETUP_PARK, r);
	}
	ps4_ready_snapshot(adev, "held");
	op->status = RREG32(mmUVD_STATUS);
	if (!ps4_ready_programmed(adev, op->cache_vmid_expected) || !ps4_ready_fetch_guard_sample(adev, &op->guard_sample, false) ||
	    RREG32(mmVM_CONTEXT1_PROTECTION_FAULT_STATUS) != op->baseline_fault ||
	    atomic_read(&adev->gpu_reset_counter) != op->reset_count ||
	    amdgpu_in_reset(adev) || (op->status & PS4_READY_BIT) ||
	    (RREG32(mmUVD_SOFT_RESET) & PS4_READY_HOLD) != PS4_READY_HOLD ||
	    !(RREG32(mmUVD_LMI_CTRL2) & UVD_LMI_CTRL2__STALL_ARB_UMC_MASK) ||
	    !(RREG32(mmUVD_RBC_RB_CNTL) & UVD_RBC_RB_CNTL__RB_NO_FETCH_MASK) ||
	    (RREG32(mmUVD_MASTINT_EN) &
	     (UVD_MASTINT_EN__VCPU_EN_MASK | UVD_MASTINT_EN__SYS_EN_MASK))) {
		ps4_ready_guard_log(adev, "held", &op->guard_sample);
		return ps4_ready_core_finish(op, PS4_READY_CORE_HELD_BASELINE, -EINVAL);
	}

	/* Last CPU publication before the earliest potential memory fetch.
	 * No reset, register reinitialization or cleanup occurs after this point.
	 * LMI/VCPU/UMC release order is the public historical initial sequence;
	 * RBC is released once while the remaining blocks stay held, matching the
	 * public initial-start dependency. NO_FETCH/NO_UPDATE remain set, IB size
	 * and pointers remain zero; no packet or pointer advance is submitted.
	 */
	mb();
	amdgpu_device_flush_hdp(adev, NULL);
	op->started = ktime_get_ns();
	op->release_entered = true;
	WREG32(mmUVD_SOFT_RESET, RREG32(mmUVD_SOFT_RESET) &
		~UVD_SOFT_RESET__RBC_SOFT_RESET_MASK);
	/* RBC release can expose a different latched register contract. Stop
	 * here while VCPU/LMI/UMC remain held if ANY owned config/guard changed.
	 * Do not unstall, rewrite the registers, or retry this initial release.
	 */
	op->guard_sample = (struct ps4_ready_guard_sample) { 0 };
	if ((RREG32(mmUVD_SOFT_RESET) & PS4_READY_HOLD) != remaining_hold ||
	    !(RREG32(mmUVD_LMI_CTRL2) & UVD_LMI_CTRL2__STALL_ARB_UMC_MASK) ||
	    !ps4_ready_programmed(adev, op->cache_vmid_expected) || !ps4_ready_fetch_guard_sample(adev, &op->guard_sample, false) ||
	    (RREG32(mmUVD_STATUS) & PS4_READY_BIT) ||
	    RREG32(mmVM_CONTEXT1_PROTECTION_FAULT_STATUS) != op->baseline_fault ||
	    atomic_read(&adev->gpu_reset_counter) != op->reset_count || amdgpu_in_reset(adev)) {
		ps4_ready_snapshot(adev, "rbc_release_guard");
		ps4_ready_guard_log(adev, "rbc_release", &op->guard_sample);
		return ps4_ready_core_finish(op, PS4_READY_CORE_RBC_RELEASE_GUARD, -EIO);
	}
	dev_info(adev->dev, "PS4_UVD_READY RBC_RELEASE verified remaining blocks held, fetch guards unchanged\n");
	ps4_uvd_led_mark(adev, 8);
	WREG32(mmUVD_LMI_CTRL2, RREG32(mmUVD_LMI_CTRL2) &
		~UVD_LMI_CTRL2__STALL_ARB_UMC_MASK);
	WREG32(mmUVD_SOFT_RESET, RREG32(mmUVD_SOFT_RESET) &
		~UVD_SOFT_RESET__LMI_SOFT_RESET_MASK);
	WREG32(mmUVD_SOFT_RESET, RREG32(mmUVD_SOFT_RESET) &
		~UVD_SOFT_RESET__VCPU_SOFT_RESET_MASK);
	WREG32(mmUVD_SOFT_RESET, RREG32(mmUVD_SOFT_RESET) &
		~UVD_SOFT_RESET__LMI_UMC_SOFT_RESET_MASK);
	msleep(16);
	for (;;) {
		op->fault = RREG32(mmVM_CONTEXT1_PROTECTION_FAULT_STATUS);
		if (op->fault != op->baseline_fault || amdgpu_in_reset(adev) ||
		    atomic_read(&adev->gpu_reset_counter) != op->reset_count) {
			ps4_ready_snapshot(adev, "fault");
			return ps4_ready_core_finish(op, PS4_READY_CORE_FAULT_OR_RESET, -EIO);
		}
		if (RREG32(PS4_READY_UVD_VCPU_CACHE_VMID) != op->cache_vmid_expected) {
			ps4_ready_snapshot(adev, "cache_vmid_changed");
			return ps4_ready_core_finish(op, PS4_READY_CORE_VCPU_CACHE_VMID_CHANGED, -EIO);
		}
		if (!ps4_ready_fetch_guard_sample(adev, &op->guard_sample, ps4_uvd_poll_state)) {
			ps4_ready_snapshot(adev, "fetch_guard_changed");
			ps4_ready_guard_log(adev, "poll", &op->guard_sample);
			return ps4_ready_core_finish(op, PS4_READY_CORE_FETCH_GUARD_CHANGED, -EIO);
		}
		if (ps4_uvd_poll_state) {
			/* A sampled 2->0 regression is outside this one hypothesis. */
			if (op->vcpu_seen && !op->guard_sample.mastint) {
				op->guard_sample.failed |= PS4_GUARD_INT_REGRESSION;
				ps4_ready_snapshot(adev, "poll_state_regression");
				ps4_ready_guard_log(adev, "poll", &op->guard_sample);
				return ps4_ready_core_finish(op, PS4_READY_CORE_POLL_STATE_REGRESSION, -EIO);
			}
			op->vcpu_seen |= op->guard_sample.mastint == UVD_MASTINT_EN__VCPU_EN_MASK;
		}
		op->status = RREG32(mmUVD_STATUS);
		op->elapsed = ktime_get_ns() - op->started;
		if (op->elapsed >= PS4_READY_LIMIT_NS) {
			ps4_ready_snapshot(adev, "timeout");
			return ps4_ready_core_finish(op, PS4_READY_CORE_READY_TIMEOUT, -ETIMEDOUT);
		}
		if (op->status & PS4_READY_BIT) {
			if (ps4_uvd_poll_state) {
				/* Saved sequential samples, not an atomic state or decode proof. */
				dev_info(adev->dev,
					"PS4_UVD_READY CONVENTION_OBSERVED status=%08x mastint=%08x elapsed_us=%llu; fetch inhibited, IRQ semantics and execution unproved\n",
					op->status, op->guard_sample.mastint, div_u64(op->elapsed, 1000));
				ps4_ready_snapshot(adev, "ready_convention");
				return ps4_ready_core_finish(op, PS4_READY_CORE_READY_CONVENTION_OBSERVED, 0);
			}
			ps4_ready_snapshot(adev, "ready");
			dev_info(adev->dev,
				"PS4_UVD_READY OBSERVED fresh_ready=1 elapsed_us=%llu; firmware-fetch/decode not established, all resources retained\n",
				div_u64(op->elapsed, 1000));
			return ps4_ready_core_finish(op, PS4_READY_CORE_READY_OBSERVED, 0);
		}
		usleep_range(1000, 2000);
	}
}
/* READY_CORE_FUNCTIONS_END */

/* READY_CORE_LEGACY_WRAPPER_BEGIN */
__noreturn void amdgpu_ps4_uvd_ready_run(struct amdgpu_device *adev,
				      void *r1_cpu, size_t backing_size,
				      u64 pd_addr,
				      const struct amdgpu_ps4_uvd_ring *rb,
				      const struct amdgpu_ps4_uvd_ring *ib)
{
	struct amdgpu_ps4_uvd_ready_operation *op = &adev->ps4_uvd_ready_operation;
	struct ps4_ready_core_result result;
	u32 cache_vmid_expected, baseline_fault;
	int reset_count;

	if (!amdgpu_ps4_uvd_ready_enabled(adev) ||
	    atomic_xchg(&ps4_ready_attempted, 1))
		ps4_ready_park(adev, "GATE_OR_REENTRY", -EPERM);
	op->boot_claimed = true;
	/* DECODE_FRAME_EARLY_BEGIN */
	if (ps4_uvd_decode_frame &&
	    (!amdgpu_ps4_uvd_decode_frame_options_valid(adev) ||
	     !ps4_frame_descriptors_valid(rb, ib, pd_addr)))
		ps4_ready_park(adev, "FRAME_DESCRIPTOR_OR_GATES", -EINVAL);
	/* DECODE_FRAME_EARLY_END */
	/* MESSAGE_CREATE_EARLY_BEGIN */
	if (ps4_uvd_message_create &&
	    (!amdgpu_ps4_uvd_message_create_options_valid(adev) ||
	     !ps4_create_descriptors_valid(rb, ib, pd_addr)))
		ps4_ready_park(adev, "CREATE_DESCRIPTOR_OR_GATES", -EINVAL);
	/* MESSAGE_CREATE_EARLY_END */
	/* IB_DATA_EARLY_BEGIN: before firmware and all readiness setup. */
	if (ps4_uvd_ib_data &&
	    (ps4_uvd_data_control || ps4_uvd_status_observation))
		ps4_ready_park(adev, "IBDATA_OPTIONS_EXCLUSIVE", -EINVAL);
	if (ps4_uvd_ib_data && !ps4_ib_data_inputs_valid(rb, ib, pd_addr))
		ps4_ready_park(adev, "IBDATA_DESCRIPTOR_OR_GATES", -EINVAL);
	/* IB_DATA_EARLY_END */
	/* DATA_CONTROL_EARLY_BEGIN: before firmware and all readiness setup. */
	if (ps4_uvd_data_control && !ps4_data_control_inputs_valid(rb, pd_addr))
		ps4_ready_park(adev, "DATA_DESCRIPTOR_OR_GATES", -EINVAL);
	/* DATA_CONTROL_EARLY_END */
	/* STATUS_OBS_EARLY_BEGIN: before firmware and all readiness setup. */
	if (ps4_uvd_status_observation && ps4_uvd_data_control)
		ps4_ready_park(adev, "STOBS_OPTIONS_EXCLUSIVE", -EINVAL);
	if (ps4_uvd_status_observation && !ps4_stobs_inputs_valid(rb, pd_addr))
		ps4_ready_park(adev, "STOBS_DESCRIPTOR_OR_GATES", -EINVAL);
	/* STATUS_OBS_EARLY_END */
	/* Receiver validation precedes all readiness setup and firmware access. */
	if (ps4_uvd_token && (!ps4_uvd_poll_state || !ps4_token_descriptor_valid(rb)))
		ps4_ready_park(adev, "TOKEN_DESCRIPTOR_OR_GATES", -EINVAL);

	result = ps4_ready_core_run(adev, r1_cpu, backing_size, pd_addr);
	if (result.terminal == PS4_READY_CORE_READY_CONVENTION_OBSERVED) {
		cache_vmid_expected = op->cache_vmid_expected;
		baseline_fault = op->baseline_fault;
		reset_count = op->reset_count;
		/* DECODE_FRAME_DISPATCH_BEGIN */
		if (ps4_uvd_decode_frame) {
			struct ps4_frame_result frame_result;

			frame_result = ps4_frame_run(adev, rb, ib, pd_addr,
				cache_vmid_expected, baseline_fault, reset_count);
			ps4_frame_report(adev);
			ps4_ready_park(adev, frame_result.name, frame_result.error);
		}
		/* DECODE_FRAME_DISPATCH_END */
		/* MESSAGE_CREATE_DISPATCH_BEGIN */
		if (ps4_uvd_message_create) {
			struct ps4_create_result message_result;

			message_result = ps4_create_run(adev, rb, ib, pd_addr,
				cache_vmid_expected, baseline_fault, reset_count);
			ps4_create_report(adev);
			ps4_ready_park(adev, ps4_create_name(message_result.terminal),
				message_result.error);
		}
		/* MESSAGE_CREATE_DISPATCH_END */
		/* Original diagnostic blocks below are retained verbatim. */
				/* IB_DATA_DISPATCH_BEGIN */
				if (ps4_uvd_ib_data)
					ps4_ib_data_run(adev, rb, ib, pd_addr,
						cache_vmid_expected, baseline_fault,
						reset_count);
				/* IB_DATA_DISPATCH_END */
				/* DATA_CONTROL_DISPATCH_BEGIN */
				if (ps4_uvd_data_control)
					ps4_data_control_run(adev, rb, pd_addr, cache_vmid_expected,
							     baseline_fault, reset_count);
				/* DATA_CONTROL_DISPATCH_END */
				/* STATUS_OBS_DISPATCH_BEGIN */
				if (ps4_uvd_status_observation)
					ps4_stobs_run(adev, rb, pd_addr, cache_vmid_expected,
						      baseline_fault, reset_count);
				/* STATUS_OBS_DISPATCH_END */
				if (ps4_uvd_token)
					ps4_token_run(adev, rb, pd_addr, cache_vmid_expected,
						      baseline_fault, reset_count);

	}
	ps4_ready_park(adev, ps4_ready_core_name(result.terminal), result.error);
}
/* READY_CORE_LEGACY_WRAPPER_END */

/* Appended beside the existing static readiness core by build_candidate.py. */
bool amdgpu_ps4_uvd_runtime_options_valid(struct amdgpu_device *adev)
{
	return amdgpu_ps4_uvd_runtime_enabled(adev) && ps4_uvd_ready &&
		ps4_uvd_poll_state && !ps4_uvd_token && !ps4_uvd_data_control &&
		!ps4_uvd_status_observation && !ps4_uvd_ib_data &&
		!ps4_uvd_message_create && !ps4_uvd_decode_frame &&
		!amdgpu_ps4_uvd_runtime_legacy_conflict() &&
		!amdgpu_ps4_live_prepare_enabled(adev);
}

int amdgpu_ps4_uvd_runtime_startup(struct amdgpu_device *adev,
	void *backing, size_t bytes, u64 pd_addr)
{
	struct amdgpu_ps4_uvd_ready_operation *op = &adev->ps4_uvd_ready_operation;
	struct ps4_ready_core_result result;
	struct ps4_token_sample sample;

	if (!amdgpu_ps4_uvd_runtime_options_valid(adev) ||
	    atomic_xchg(&ps4_ready_attempted, 1))
		return -EPERM;

	op->boot_claimed = true;
	result = ps4_ready_core_run(adev, backing, bytes, pd_addr);
	if (result.terminal != PS4_READY_CORE_READY_CONVENTION_OBSERVED || result.error)
		return result.error ? result.error : -EIO;

	if (!ps4_token_sample(adev, &sample, PS4_TOKEN_HELD, pd_addr,
		op->cache_vmid_expected, op->baseline_fault, op->reset_count) ||
	    !ps4_stobs_ctx_sweep(adev, &sample))
		return -EIO;

	/* The caller has initialized and published the entire owned ring. No
	 * command or WPTR is emitted here; subsequent jobs use the normal ring.
	 */
	mb();
	amdgpu_device_flush_hdp(adev, NULL);
	WREG32(mmUVD_RBC_RB_CNTL, PS4_TOKEN_RBC_FETCH);
	if (!ps4_token_sample(adev, &sample, PS4_TOKEN_EMPTY, pd_addr,
		op->cache_vmid_expected, op->baseline_fault, op->reset_count))
		return -EIO;

	dev_info(adev->dev,
		"PS4_UVD_RUNTIME STARTED vmid=4 native_alias=1 polled_fences=1; normal producers follow, no PM/reset/rearm\n");
	return 0;
}
