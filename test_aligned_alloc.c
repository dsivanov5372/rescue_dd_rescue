/* test_aligned_alloc.c
 * Test case, demonstrating broken libbionic on Android 11
 * (c) Kurt Garloff <kurt@garloff.de>, 5/2021
 * License: BSD 3-clause
 */

#ifdef __ANDROID_MIN_SDK_VERSION__
#undef __ANDROID_MIN_SDK_VERSION__
#define __ANDROID_MIN_SDK_VERSION__ 28
#endif

#include <stdlib.h>
#include <stdio.h>

int main() {
    void *ptr1 = aligned_alloc(64, 448);
    void *ptr2 = aligned_alloc(64, 464);
    printf("%p %p\n", ptr1, ptr2);
    if (ptr1 && ptr2 && !((unsigned long)ptr1%64) && !((unsigned long)ptr2%64)) {
	free(ptr2);
	free(ptr1);
	return 0;
    } else {
	if (ptr1)
		free(ptr1);
	return 1;
    }
}

