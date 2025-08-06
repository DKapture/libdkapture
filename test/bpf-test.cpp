#include "gtest/gtest.h"
#include "bpf.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#define TEST_PIN_PATH "/sys/fs/bpf/test_dkapture"

class BPFTest : public ::testing::Test {
protected:
    BPF* bpf_instance;

    void SetUp() override {
        // Ensure the test environment is clean
        mkdir(TEST_PIN_PATH, 0755);
        bpf_instance = new BPF();
    }

    void TearDown() override {
        delete bpf_instance;

        // Clean up test environment
        DIR* dir = opendir(TEST_PIN_PATH);
        if (dir) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != nullptr) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                    continue;
                std::string path(TEST_PIN_PATH);
                path += "/";
                path += entry->d_name;
                unlink(path.c_str());
            }
            closedir(dir);
        }
        rmdir(TEST_PIN_PATH);
    }
};

TEST_F(BPFTest, ConstructorAndDestructor) {
    // Verify that the BPF instance is created and destroyed without errors
    ASSERT_NE(bpf_instance, nullptr);
}

TEST_F(BPFTest, PinLinks) {
    // Test the bpf_pin_links method
    int ret = bpf_instance->bpf_pin_links(TEST_PIN_PATH);
    ASSERT_EQ(ret, 0) << "Failed to pin BPF links";
}

TEST_F(BPFTest, PinPrograms) {
    // Test the bpf_pin_programs method
    struct bpf_object* obj = nullptr; // Mock object
    int ret = bpf_instance->bpf_pin_programs(TEST_PIN_PATH);
    ASSERT_EQ(ret, 0) << "Failed to pin BPF programs";
}

TEST_F(BPFTest, RetreatBpfMap) {
    // Test the retreat_bpf_map method
    const char* map_name = "test_map";
    int ret = bpf_instance->retreat_bpf_map(map_name);
    ASSERT_EQ(ret, 0) << "Failed to retreat BPF map";
}

TEST_F(BPFTest, RetreatBpfIter) {
    // Test the retreat_bpf_iter method
    std::string result = bpf_instance->retreat_bpf_iter("dump_task");
    ASSERT_FALSE(result.empty()) << "Failed to retreat BPF iterator";
}
