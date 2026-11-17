/* SPDX-License-Identifier: MIT */
#ifndef AMDGPU_PS4_MAP_CANARY_H
#define AMDGPU_PS4_MAP_CANARY_H

#include <linux/types.h>

struct amdgpu_device;

bool amdgpu_ps4_map_canary_enabled(struct amdgpu_device *adev);
bool amdgpu_ps4_map_canary_completed(struct amdgpu_device *adev);
bool amdgpu_ps4_map_canary_reserve(struct amdgpu_device *adev,
				 unsigned int vmhub, unsigned int vmid);
/* Returns for gate-off, original copy-only PASS or preparation-only PASS.
 * The separate readiness mode retains the complete mapping and never returns.
 */
void amdgpu_ps4_map_canary_run(struct amdgpu_device *adev);

#endif
