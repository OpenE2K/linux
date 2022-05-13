
#ifndef _ASM_L_ACENV_H_
#define _ASM_L_ACENV_H_

int __acpi_acquire_global_lock(unsigned int *lock);
int __acpi_release_global_lock(unsigned int *lock);

#define ACPI_ACQUIRE_GLOBAL_LOCK(facs, Acq) \
        ((Acq) = __acpi_acquire_global_lock(&facs->global_lock))

#define ACPI_RELEASE_GLOBAL_LOCK(facs, Acq) \
        ((Acq) = __acpi_release_global_lock(&facs->global_lock))

#endif /* _ASM_L_ACENV_H_ */
