// SPDX-License-Identifier: MIT

#include "microcode.h"

#include "cpu.h"
#include "intel-ucode.h"
#include "shout.h"
#include "x86.h"
#include <stdbool.h>
#include <stdint.h>

void microcode_load(void) {
    // Note that in case if Hyperthreading is enabled then microcode is shared between logical processors at the same core.
    // So we can either add tracking for updated cores OR simple let each logical core update the microcode.
    // Intel maual 8.7.11 states that core provides synchronization if multiple logical cores try to update the microcode.

    // find microcode
    uint32_t signature, unused;
    x86_cpuid(CPUID_FEATURES, &signature, &unused, &unused, &unused);

    if (bootstrap_cpu_id == current_cpu_id)
        IFVV printf("CPU signature is 0x%x\n", signature);

    uint64_t platform_id = x86_rdmsr(MSR_PLATFORM_ID);
    uint32_t processor_flags = 1 << ((platform_id >> 50) & 7); // extract flags [52:50]

    // iterate over all microcode files
    for (size_t j = 0; j < ARRAY_SIZE(BLOB_INTEL_UCODE); j++) {
        struct blob_record blob = BLOB_INTEL_UCODE[j];

        // table 9-8
        struct PACKED ucode {
            uint32_t header_version;
            uint32_t update_revision;
            uint32_t date;
            uint32_t processor_signature;
            uint32_t checksum;
            uint32_t loader_revision;
            uint32_t processor_flags;
            uint32_t data_size;
            uint32_t total_size;
            uint8_t reserved1[12];
            uint8_t data[0]; // actual ucode data
        } ALIGNED(16);
        BUILD_PANIC_IF(offsetof(struct ucode, data) != 48);

        const struct ucode *ucode = blob.data;
        PANIC_IF(!IS_ROUNDED((uintptr_t)ucode, 16)); // microcode data need to be aligned to 16 bytes

        // printf("ucode signature=%08x s=%08lx\n", ucode->processor_signature, signature);

        if (ucode->header_version != 1)
            continue; // we know how to handle ucode v1 only

        bool matches = false;
        if (ucode->processor_signature == signature && (ucode->processor_flags & processor_flags)) {
            matches = true;
        } else {
            // check if extended signature matches
            if (ucode->total_size > (ucode->data_size + 48)) {
                // XXX verify extended checksum

                uint32_t ext_signature_count = *(uint32_t *)((void *)ucode + ucode->data_size + 48);

                struct PACKED ext_signature {
                    uint32_t processor_signature;
                    uint32_t processor_flags;
                    uint32_t checksum;
                };

                struct ext_signature *ext = ((void *)ucode + ucode->data_size + 68);
                for (uint32_t i = 0; i < ext_signature_count; i++, ext++) {
                    if (ext->processor_signature == signature && (ext->processor_flags & processor_flags)) {
                        matches = true;
                        break;
                    }
                }
            }
        }

        if (matches) {
            if (bootstrap_cpu_id == current_cpu_id)
                IFVV printf("Updating processor microcode, signature 0x%x revision %d date %08x\n", signature, ucode->update_revision,
                            ucode->date);

            // verify ucode checksum
            int words = 512;
            if (ucode->data_size)
                words = ucode->total_size / 4;
            uint32_t checksum = 0;
            uint32_t *ptr = (uint32_t *)ucode;
            for (int i = 0; i < words; i++, ptr++)
                checksum += *ptr;
            SHOUT_IF(checksum != 0, "ucode checksum does not match");

            // Yay we've found ucode for our processor. Load microcode, see Intel manual section 9.11.1
            x86_wrmsr(MSR_BIOS_UPDT_TRIG, (uintptr_t)&ucode->data);

            // now verify that we loaded the microcode
            x86_wrmsr(MSR_BIOS_SIGN_ID, 0);
            x86_cpuid(CPUID_FEATURES, &unused, &unused, &unused, &unused);
            uint32_t new_revision = (x86_rdmsr(MSR_BIOS_SIGN_ID) >> 32);
            if (new_revision == ucode->update_revision) {
                IFVV printf("Microcode successfully updated\n");
                break;
            } else {
                printf("Failed to load microcode, new revision (%d) does not match expected value (%d)\n", new_revision,
                       ucode->update_revision);
                continue;
            }
        }
    }
}
