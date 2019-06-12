/**
 * Quick sort symbolic execution demo.
 * Code taken from http://en.wikibooks.org/wiki/Algorithm_Implementation/Sorting/Quicksort#C
 */

#include <s2e/s2e.h>

static void swap(int *a, int *b) {
    int t = *a;
    *a = *b;
    *b = t;
}

static void sort(int arr[], int beg, int end) {
    if (end > beg + 1) {
        int piv = arr[beg], l = beg + 1, r = end;
        while (l < r) {
            if (arr[l] <= piv)
                l++;
            else
                swap(&arr[l], &arr[--r]);
        }
        swap(&arr[--l], &arr[beg]);
        sort(arr, beg, l);
        sort(arr, r, end);
    }
}

int main(void) {
    int num_list[] = {5, 4, 5, 6, 7};

    s2e_make_symbolic(&num_list, sizeof(num_list), "array");

    int len = sizeof(num_list) / sizeof(num_list[0]);
    sort(num_list, 0, len);

    for (int i = 0; i < len; i++) {
        printf("%d ", s2e_get_example_uint(num_list[i]));
    }
    printf("\n");

    s2e_kill_state(0, "Sort completed");

    return 0;
}
