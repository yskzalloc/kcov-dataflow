#include <string.h>

struct simple_data {
    int id;
    char buf[16];
    int size;
};

__attribute__((noinline))
struct simple_data *mutate_data(struct simple_data *data, int new_id) {
    data->id = new_id;
    data->size = 0x41414141; // simulate corruption
    memcpy(data->buf, "AAAAAAAAAAAAAAAA", 16); // OOB-like pattern
    return data;
}

int main(void) {
    struct simple_data d = {.id = 1, .buf = "hello", .size = 5};
    struct simple_data *result = mutate_data(&d, 42);
    return result->id;
}
