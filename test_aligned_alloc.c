/* test_aligned_alloc.c
 * Test case, demonstrating libbionic on Android 11 enforces
 *  size being a multiple of the requested alignment.
 * (c) Kurt Garloff <kurt@garloff.de>, 5/2021
 * License: BSD 3-clause
 */

#if defined(__ANDROID_MIN_SDK_VERSION__) && __ANDROID_MIN_SDK_VERSION__ < 28
#warning Compile with -target linux-aarch64-android28 or -target linux-arm-android28
#endif

#include <stdlib.h>
#include <stdio.h>

int main() {
    void *ptr1 = aligned_alloc(64, 448);
    void *ptr2 = aligned_alloc(64, 464);
    printf("aligned_alloc(%02x,%04x)=%p\n", 64, 448, ptr1);
    printf("aligned_alloc(%02x,%04x)=%p\n", 64, 464, ptr2);
    if (ptr1 && ptr2 && !((unsigned long)ptr1%64) && !((unsigned long)ptr2%64)) {
	free(ptr2);
	free(ptr1);
	return 0;
    } else {
	if (ptr2)
		free(ptr2);
	if (ptr1)
		free(ptr1);
	return 1;
    }
}

