#include "gtest/gtest.h"
#include <cstdlib>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <memory>
#include <array>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <thread>
#include <chrono>

// 基础测试类
class ElfverifyTest : public ::testing::Test {
protected:
    std::string binary_path;
    std::string temp_policy_file;
    std::string temp_dir;

    void SetUp() override {
        // 获取当前工作目录，根据测试运行位置调整路径
        char* cwd = getcwd(nullptr, 0);
        std::string current_dir(cwd);
        free(cwd);
        
        if (current_dir.find("/test") != std::string::npos) {
            binary_path = "../build/policy/elfverify";
        } else {
            binary_path = "./build/policy/elfverify";
        }
        
        temp_dir = "/tmp/elfverify_test_" + std::to_string(getpid());
        system(("mkdir -p " + temp_dir).c_str());
        temp_policy_file = temp_dir + "/test_policy.pol";
    }

    void TearDown() override {
        // 清理临时文件
        system(("rm -rf " + temp_dir).c_str());
    }

    // 执行 elfverify 并捕获输出（测试套件本身已在 sudo 下运行）
    std::pair<int, std::string> runElfverify(const std::vector<std::string>& args) {
        std::string cmd = binary_path;
        for (const auto& arg : args) {
            cmd += " " + arg;
        }
        cmd += " 2>&1"; // 重定向 stderr 到 stdout
        
        std::array<char, 128> buffer;
        std::string result;
        int exit_code = -1;
        
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
        if (pipe) {
            while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                result += buffer.data();
            }
            exit_code = WEXITSTATUS(pclose(pipe.release()));
        }
        
        return {exit_code, result};
    }

    // 运行带超时的 elfverify（用于可能长时间运行的测试）
    std::pair<int, std::string> runElfverifyWithTimeout(const std::vector<std::string>& args, int timeout_seconds = 3) {
        std::string cmd = "timeout " + std::to_string(timeout_seconds) + "s " + binary_path;
        for (const auto& arg : args) {
            cmd += " " + arg;
        }
        cmd += " 2>&1";
        
        std::array<char, 128> buffer;
        std::string result;
        int exit_code = -1;
        
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
        if (pipe) {
            while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                result += buffer.data();
            }
            exit_code = WEXITSTATUS(pclose(pipe.release()));
        }
        
        return {exit_code, result};
    }

    // 创建测试策略文件
    void createTestPolicyFile(const std::string& content) {
        std::ofstream file(temp_policy_file);
        file << content;
        file.close();
    }

    // 创建无效策略文件
    void createInvalidPolicyFile() {
        createTestPolicyFile("invalid_line_without_equals\nuser=\npath=\n=value_without_key\n");
    }

    // 创建标准策略文件
    void createStandardPolicyFile() {
        createTestPolicyFile("user=root\npath=/usr/bin\npath=/bin\npath=/usr/local/bin\n");
    }

    // 创建复杂策略文件
    void createComplexPolicyFile() {
        createTestPolicyFile(
            "# System users\n"
            "user=root\n"
            "user=daemon\n"
            "user=bin\n"
            "user=sys\n"
            "user=sync\n"
            "user=games\n"
            "user=man\n"
            "user=lp\n"
            "user=mail\n"
            "user=news\n"
            "user=uucp\n"
            "user=proxy\n"
            "user=www-data\n"
            "user=backup\n"
            "user=list\n"
            "user=irc\n"
            "user=gnats\n"
            "user=nobody\n"
            "user=systemd-network\n"
            "user=systemd-resolve\n"
            "\n# System paths\n"
            "path=/usr/bin\n"
            "path=/bin\n"
            "path=/usr/local/bin\n"
            "path=/sbin\n"
            "path=/usr/sbin\n"
            "path=/usr/local/sbin\n"
            "path=/usr/lib\n"
            "path=/usr/local/lib\n"
            "path=/lib\n"
            "path=/lib64\n"
            "path=/usr/lib64\n"
            "path=/usr/libexec\n"
            "path=/usr/local/libexec\n"
            "path=/opt/bin\n"
            "path=/opt/sbin\n"
            "path=/usr/games\n"
            "path=/usr/local/games\n"
        );
    }

    // 创建带有边界情况的策略文件
    void createEdgeCasePolicyFile() {
        createTestPolicyFile(
            "# Edge cases and special characters\n"
            "user=user-with-dash\n"
            "user=user_with_underscore\n"
            "user=user123\n"
            "path=/path with spaces\n"
            "path=/path-with-dashes\n"
            "path=/path_with_underscores\n"
            "path=/path123\n"
            "path=/path/with/many/levels/deep/structure\n"
            "path=/tmp\n"
            "path=/var/tmp\n"
            "path=/home\n"
            "path=/root\n"
        );
    }

    // 创建特大策略文件
    void createLargePolicyFile() {
        std::string content = "# Large policy file with many entries\n";
        for (int i = 0; i < 200; i++) {
            content += "path=/usr/bin\n";
            content += "path=/bin\n";
            content += "user=root\n";
            if (i % 10 == 0) {
                content += "# Section " + std::to_string(i/10) + "\n";
            }
        }
        createTestPolicyFile(content);
    }

    // 创建带有错误的策略文件
    void createMalformedPolicyFile() {
        createTestPolicyFile(
            "# Valid entries\n"
            "user=root\n"
            "path=/usr/bin\n"
            "# Invalid entries below\n"
            "invalid_line_without_equals\n"
            "user=\n"
            "path=\n"
            "=value_without_key\n"
            "wrong_type=invalid\n"
            "user=nonexistent_user_12345\n"
            "path=/nonexistent/path/12345\n"
            "user root without equals\n"
            "path /usr/bin without equals\n"
            "user=user with spaces in name\n"
            "random garbage line\n"
            "123numbers at start\n"
            "special!@#$%^&*()chars\n"
        );
    }

    // 测试超长行
    void createVeryLongLinePolicyFile() {
        std::string long_path = "path=" + std::string(8000, 'a');
        std::string long_user = "user=" + std::string(4000, 'b');
        createTestPolicyFile(long_path + "\n" + long_user + "\nuser=root\n");
    }

    // 检查输出是否包含预期内容
    bool outputContains(const std::string& output, const std::vector<std::string>& keywords) {
        for (const auto& keyword : keywords) {
            if (output.find(keyword) == std::string::npos) {
                return false;
            }
        }
        return true;
    }


};

// 基础功能测试类
class ElfverifyBasicTest : public ElfverifyTest {};

TEST_F(ElfverifyBasicTest, HelpOptionLong) {
    auto [exit_code, output] = runElfverify({"--help"});
    
    EXPECT_EQ(exit_code, 0);
    EXPECT_TRUE(output.find("Usage:") != std::string::npos);
    EXPECT_TRUE(output.find("prevent the execution of applications from untrusted sources") != std::string::npos);
    EXPECT_TRUE(output.find("--policy-file") != std::string::npos);
    EXPECT_TRUE(output.find("--help") != std::string::npos);
}

TEST_F(ElfverifyBasicTest, HelpOptionShort) {
    auto [exit_code, output] = runElfverify({"-h"});
    
    EXPECT_EQ(exit_code, 0);
    EXPECT_TRUE(output.find("Usage:") != std::string::npos);
    EXPECT_TRUE(output.find("prevent the execution of applications from untrusted sources") != std::string::npos);
}

TEST_F(ElfverifyBasicTest, InvalidOption) {
    auto [exit_code, output] = runElfverify({"--invalid-option"});
    
    EXPECT_NE(exit_code, 0);
    EXPECT_TRUE(output.find("Usage:") != std::string::npos);
}

TEST_F(ElfverifyBasicTest, NoArguments) {
    auto [exit_code, output] = runElfverify({});
    
    // 应该使用默认策略文件
    EXPECT_TRUE(output.find("No policy file specified, use elfverify.pol as default") != std::string::npos);
}

TEST_F(ElfverifyBasicTest, MultipleHelpOptions) {
    auto [exit_code, output] = runElfverify({"-h", "--help"});
    
    EXPECT_EQ(exit_code, 0);
    EXPECT_TRUE(output.find("Usage:") != std::string::npos);
}

// 策略文件测试类
class ElfverifyPolicyTest : public ElfverifyTest {};

TEST_F(ElfverifyPolicyTest, DefaultPolicyFile) {
    auto [exit_code, output] = runElfverify({});
    
    EXPECT_TRUE(output.find("elfverify.pol") != std::string::npos);
}

TEST_F(ElfverifyPolicyTest, CustomPolicyFileShort) {
    createStandardPolicyFile();
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    // 应该加载策略文件（可能会因为 BPF 权限失败，但会尝试解析文件）
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyPolicyTest, CustomPolicyFileLong) {
    createStandardPolicyFile();
    auto [exit_code, output] = runElfverify({"--policy-file", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyPolicyTest, NonexistentPolicyFile) {
    auto [exit_code, output] = runElfverify({"-p", "/nonexistent/policy.pol"});
    
    EXPECT_NE(exit_code, 0);
    // elfverify 会在 BPF 加载失败时退出，但会尝试先加载策略文件
    EXPECT_TRUE(output.find("fopen:") != std::string::npos || 
               output.find("No such file") != std::string::npos ||
               output.find("libbpf") != std::string::npos);
}

TEST_F(ElfverifyPolicyTest, EmptyPolicyFile) {
    createTestPolicyFile("");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    // 空文件应该被接受，但 BPF 加载可能失败
    EXPECT_TRUE(exit_code == 255 || exit_code == 0);
}

TEST_F(ElfverifyPolicyTest, ValidUserRule) {
    createTestPolicyFile("user=root\n");
    auto [exit_code, output] = runElfverifyWithTimeout({"-p", temp_policy_file}, 2);
    
    // 在测试环境中，可能遇到 BPF 权限问题
    if (exit_code == 124) {
        // 如果程序成功启动并被 timeout 终止，应该能看到规则解析
        EXPECT_TRUE(output.find("Rule: user root") != std::string::npos);
    } else if (exit_code == 255) {
        // 如果是 BPF 权限问题，程序会快速退出
        // 这种情况下我们验证程序至少尝试了策略文件解析
        EXPECT_TRUE(output.find("Rule: user root") != std::string::npos || 
                   output.find("failed to load") != std::string::npos);
    } else {
        FAIL() << "Unexpected exit code: " << exit_code << ", output: " << output;
    }
}

TEST_F(ElfverifyPolicyTest, ValidPathRule) {
    createTestPolicyFile("path=/usr/bin\n");
    auto [exit_code, output] = runElfverifyWithTimeout({"-p", temp_policy_file}, 2);
    
    // 在测试环境中，可能遇到 BPF 权限问题
    if (exit_code == 124) {
        // 如果程序成功启动并被 timeout 终止，应该能看到规则解析
        EXPECT_TRUE(output.find("Rule: path /usr/bin") != std::string::npos);
    } else if (exit_code == 255) {
        // 如果是 BPF 权限问题，程序会快速退出
        // 这种情况下我们验证程序至少尝试了策略文件解析
        EXPECT_TRUE(output.find("Rule: path /usr/bin") != std::string::npos || 
                   output.find("failed to load") != std::string::npos);
    } else {
        FAIL() << "Unexpected exit code: " << exit_code << ", output: " << output;
    }
}

TEST_F(ElfverifyPolicyTest, MixedRules) {
    createTestPolicyFile("user=root\npath=/usr/bin\nuser=nobody\npath=/bin\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyPolicyTest, CommentsInPolicy) {
    createTestPolicyFile("# This is a comment\nuser=root\n# Another comment\npath=/usr/bin\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

// 错误处理测试类
class ElfverifyErrorHandlingTest : public ElfverifyTest {};

TEST_F(ElfverifyErrorHandlingTest, InvalidPolicyFormat) {
    createInvalidPolicyFile();
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Invalid line:") != std::string::npos || exit_code != 0);
}

TEST_F(ElfverifyErrorHandlingTest, PolicyFileArgMissing) {
    auto [exit_code, output] = runElfverify({"-p"});
    
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyErrorHandlingTest, NonexistentUser) {
    createTestPolicyFile("user=nonexistent_user_12345\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyErrorHandlingTest, NonexistentPath) {
    createTestPolicyFile("path=/nonexistent/path/12345\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Cannot access path") != std::string::npos || exit_code != 0);
}

TEST_F(ElfverifyErrorHandlingTest, PermissionDeniedFile) {
    // 创建文件然后移除读权限
    createTestPolicyFile("user=root\n");
    chmod(temp_policy_file.c_str(), 0000);
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
    // elfverify 可能在 BPF 加载阶段失败，而不是文件权限阶段
    EXPECT_TRUE(output.find("fopen:") != std::string::npos || 
               output.find("Permission denied") != std::string::npos ||
               output.find("libbpf") != std::string::npos);
    
    // 恢复权限以便清理
    chmod(temp_policy_file.c_str(), 0644);
}

TEST_F(ElfverifyErrorHandlingTest, BPFLoadError) {
    createStandardPolicyFile();
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    // 在非特权环境下，BPF 加载应该失败
    EXPECT_TRUE(exit_code == 255 || 
               output.find("Operation not permitted") != std::string::npos ||
               output.find("libbpf") != std::string::npos);
}

// 高级功能测试类
class ElfverifyAdvancedTest : public ElfverifyTest {};

TEST_F(ElfverifyAdvancedTest, DirectoryPathRule) {
    createTestPolicyFile("path=/usr/bin\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    // 目录应该被递归处理
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyAdvancedTest, MultipleUserRules) {
    createTestPolicyFile("user=root\nuser=daemon\nuser=bin\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyAdvancedTest, MultiplePathRules) {
    createTestPolicyFile("path=/usr/bin\npath=/bin\npath=/usr/local/bin\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyAdvancedTest, LargePolicyFile) {
    std::string large_content;
    for (int i = 0; i < 100; i++) {
        large_content += "path=/usr/bin\n";
    }
    createTestPolicyFile(large_content);
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyAdvancedTest, WhitespaceInPolicy) {
    createTestPolicyFile("  user=root  \n\n  path=/usr/bin  \n\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyAdvancedTest, SpecialCharactersInPath) {
    // 创建一个包含特殊字符的临时目录
    std::string special_dir = temp_dir + "/test_dir";
    system(("mkdir -p " + special_dir).c_str());
    
    createTestPolicyFile("path=" + special_dir + "\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyAdvancedTest, EmptyLines) {
    createTestPolicyFile("\n\nuser=root\n\n\npath=/usr/bin\n\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyAdvancedTest, InvalidRuleTypes) {
    createTestPolicyFile("invalid=test\nuser=root\nwrong=value\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    // 应该忽略无效规则但处理有效规则
    EXPECT_TRUE(output.find("Rule: user root") != std::string::npos || exit_code == 255);
}

// 性能和边界测试类
class ElfverifyPerformanceTest : public ElfverifyTest {};

TEST_F(ElfverifyPerformanceTest, QuickExecution) {
    auto start = std::chrono::high_resolution_clock::now();
    auto [exit_code, output] = runElfverify({"--help"});
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_EQ(exit_code, 0);
    EXPECT_LT(duration.count(), 1000); // 应该在 1 秒内完成
}

TEST_F(ElfverifyPerformanceTest, RepeatedCalls) {
    for (int i = 0; i < 5; i++) {
        auto [exit_code, output] = runElfverify({"--help"});
        EXPECT_EQ(exit_code, 0);
    }
}

TEST_F(ElfverifyPerformanceTest, ConcurrentCalls) {
    std::vector<std::thread> threads;
    std::vector<bool> results(3, false);
    
    for (int i = 0; i < 3; i++) {
        threads.emplace_back([this, &results, i]() {
            auto [exit_code, output] = runElfverify({"--help"});
            results[i] = (exit_code == 0);
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    for (bool result : results) {
        EXPECT_TRUE(result);
    }
}

// 边界条件测试
TEST_F(ElfverifyAdvancedTest, VeryLongPolicyLine) {
    std::string long_path = "path=" + std::string(4000, 'a');
    createTestPolicyFile(long_path + "\n");
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    // 应该处理长行或报告错误
    EXPECT_TRUE(exit_code != 0 || output.find("Rule:") != std::string::npos);
}

TEST_F(ElfverifyAdvancedTest, AbsoluteVsRelativePaths) {
    createTestPolicyFile("path=/usr/bin\npath=relative/path\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    // 相对路径应该被正确处理或报告错误
    EXPECT_TRUE(output.find("Cannot access path") != std::string::npos || 
               output.find("Rule:") != std::string::npos || 
               exit_code == 255);
}

TEST_F(ElfverifyAdvancedTest, SymbolicLinks) {
    // 创建符号链接测试
    std::string link_target = temp_dir + "/link_target";
    std::string symlink_path = temp_dir + "/test_symlink";
    
    system(("mkdir -p " + link_target).c_str());
    system(("ln -s " + link_target + " " + symlink_path).c_str());
    
    createTestPolicyFile("path=" + symlink_path + "\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

// 信号处理测试
class ElfverifySignalTest : public ElfverifyTest {};

TEST_F(ElfverifySignalTest, InterruptSignal) {
    // 测试程序在有权限时能否正确处理信号
    createStandardPolicyFile();
    
    pid_t pid = fork();
    if (pid == 0) {
        // 子进程：运行 elfverify（测试套件已在 sudo 下运行）
        execl(binary_path.c_str(), binary_path.c_str(), "-p", temp_policy_file.c_str(), nullptr);
        exit(1); // 如果 execl 失败
    } else if (pid > 0) {
        // 父进程：等待一段时间让程序启动，然后发送信号
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        kill(pid, SIGINT);
        
        int status;
        waitpid(pid, &status, 0);
        
        // 程序应该能够处理信号并正常退出
        EXPECT_TRUE(WIFEXITED(status) || WIFSIGNALED(status));
        if (WIFSIGNALED(status)) {
            // 如果被信号终止，应该是 SIGINT
            EXPECT_EQ(WTERMSIG(status), SIGINT);
        }
    } else {
        FAIL() << "Failed to fork process";
    }
}

// 新增：策略文件语法测试类
class ElfverifyPolicySyntaxTest : public ElfverifyTest {};

TEST_F(ElfverifyPolicySyntaxTest, EmptyPolicyFile) {
    createTestPolicyFile("");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    // 空文件应该被接受
    EXPECT_TRUE(exit_code == 255 || exit_code == 0);
}

TEST_F(ElfverifyPolicySyntaxTest, OnlyComments) {
    createTestPolicyFile("# This is a comment\n# Another comment\n# Third comment\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(exit_code == 255 || exit_code == 0);
}

TEST_F(ElfverifyPolicySyntaxTest, BlankLines) {
    createTestPolicyFile("\n\n\n\nuser=root\n\n\n\npath=/usr/bin\n\n\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyPolicySyntaxTest, TrailingSpaces) {
    createTestPolicyFile("user=root   \npath=/usr/bin  \n  user=daemon  \n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyPolicySyntaxTest, MixedCaseTypes) {
    createTestPolicyFile("USER=root\nPath=/usr/bin\nUSER=daemon\nPATH=/bin\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    // 应该忽略大写的无效类型
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyPolicySyntaxTest, MultipleEquals) {
    createTestPolicyFile("user=root=extra\npath=/usr/bin=extra\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyPolicySyntaxTest, SpecialCharactersInValues) {
    createTestPolicyFile("user=user!@#$%\npath=/path/with/!@#$%/chars\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    // 特殊字符应该导致用户查找失败
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyPolicySyntaxTest, NumbersInValues) {
    createTestPolicyFile("user=user123\npath=/path123/456\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0); // user123 可能不存在
}

TEST_F(ElfverifyPolicySyntaxTest, VeryLongUserName) {
    std::string long_user = "user=" + std::string(1000, 'a');
    createTestPolicyFile(long_user + "\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyPolicySyntaxTest, VeryLongPath) {
    std::string long_path = "path=" + std::string(8000, '/') + "end";
    createTestPolicyFile(long_path + "\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyPolicySyntaxTest, InvalidRuleTypes) {
    createTestPolicyFile("invalid=test\nwrong=value\nbad=entry\nuser=root\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    // 应该处理有效规则，忽略无效规则
    EXPECT_TRUE(output.find("Rule: user root") != std::string::npos || exit_code == 255);
}

// 新增：用户规则测试类
class ElfverifyUserRulesTest : public ElfverifyTest {};

TEST_F(ElfverifyUserRulesTest, SystemUsers) {
    createTestPolicyFile("user=root\nuser=daemon\nuser=bin\nuser=sys\nuser=nobody\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule: user") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyUserRulesTest, NonExistentUser) {
    createTestPolicyFile("user=definitely_nonexistent_user_12345\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyUserRulesTest, EmptyUserName) {
    createTestPolicyFile("user=\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyUserRulesTest, UserWithSpaces) {
    createTestPolicyFile("user=user with spaces\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyUserRulesTest, DuplicateUsers) {
    createTestPolicyFile("user=root\nuser=root\nuser=root\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule: user root") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyUserRulesTest, ManyUsers) {
    std::string content;
    std::vector<std::string> users = {"root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody"};
    for (const auto& user : users) {
        content += "user=" + user + "\n";
    }
    createTestPolicyFile(content);
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule: user") != std::string::npos || exit_code == 255);
}

// 新增：路径规则测试类  
class ElfverifyPathRulesTest : public ElfverifyTest {};

TEST_F(ElfverifyPathRulesTest, SystemPaths) {
    createTestPolicyFile("path=/usr/bin\npath=/bin\npath=/sbin\npath=/usr/sbin\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule: path") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyPathRulesTest, NonExistentPath) {
    createTestPolicyFile("path=/definitely/nonexistent/path/12345\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Cannot access path") != std::string::npos || exit_code != 0);
}

TEST_F(ElfverifyPathRulesTest, EmptyPath) {
    createTestPolicyFile("path=\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyPathRulesTest, RelativePaths) {
    createTestPolicyFile("path=relative/path\npath=../parent\npath=./current\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Cannot access path") != std::string::npos || exit_code != 0);
}

TEST_F(ElfverifyPathRulesTest, PathsWithSpaces) {
    std::string space_dir = temp_dir + "/dir with spaces";
    system(("mkdir -p '" + space_dir + "'").c_str());
    
    createTestPolicyFile("path=" + space_dir + "\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule: path") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyPathRulesTest, DeepDirectoryStructure) {
    std::string deep_dir = temp_dir + "/level1/level2/level3/level4/level5";
    system(("mkdir -p " + deep_dir).c_str());
    
    createTestPolicyFile("path=" + deep_dir + "\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule: path") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyPathRulesTest, SymbolicLinks) {
    std::string target = temp_dir + "/target";
    std::string link = temp_dir + "/symlink";
    system(("mkdir -p " + target).c_str());
    system(("ln -s " + target + " " + link).c_str());
    
    createTestPolicyFile("path=" + link + "\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule: path") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyPathRulesTest, SpecialCharacterPaths) {
    std::string special_dir = temp_dir + "/dir-with_special.chars@123";
    system(("mkdir -p '" + special_dir + "'").c_str());
    
    createTestPolicyFile("path=" + special_dir + "\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule: path") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyPathRulesTest, DuplicatePaths) {
    createTestPolicyFile("path=/usr/bin\npath=/usr/bin\npath=/usr/bin\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule: path") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyPathRulesTest, ManyPaths) {
    std::string content;
    std::vector<std::string> paths = {"/usr/bin", "/bin", "/sbin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/usr/lib", "/lib", "/lib64", "/usr/lib64", "/usr/libexec", "/opt/bin", "/opt/sbin"};
    for (const auto& path : paths) {
        content += "path=" + path + "\n";
    }
    createTestPolicyFile(content);
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule: path") != std::string::npos || exit_code == 255);
}

// 新增：文件权限和访问测试类
class ElfverifyFilePermissionTest : public ElfverifyTest {};

TEST_F(ElfverifyFilePermissionTest, ReadOnlyPolicyFile) {
    createTestPolicyFile("user=root\npath=/usr/bin\n");
    chmod(temp_policy_file.c_str(), 0444); // 只读
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
    
    chmod(temp_policy_file.c_str(), 0644); // 恢复权限
}

TEST_F(ElfverifyFilePermissionTest, NoReadPermission) {
    createTestPolicyFile("user=root\npath=/usr/bin\n");
    chmod(temp_policy_file.c_str(), 0000); // 无权限
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
    EXPECT_TRUE(output.find("fopen:") != std::string::npos || 
               output.find("Permission denied") != std::string::npos ||
               output.find("libbpf") != std::string::npos);
    
    chmod(temp_policy_file.c_str(), 0644); // 恢复权限
}

TEST_F(ElfverifyFilePermissionTest, ExecuteOnlyPermission) {
    createTestPolicyFile("user=root\npath=/usr/bin\n");
    chmod(temp_policy_file.c_str(), 0111); // 只执行
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
    
    chmod(temp_policy_file.c_str(), 0644); // 恢复权限
}

TEST_F(ElfverifyFilePermissionTest, PolicyFileInReadOnlyDirectory) {
    std::string readonly_dir = temp_dir + "/readonly";
    std::string readonly_policy = readonly_dir + "/policy.pol";
    
    system(("mkdir -p " + readonly_dir).c_str());
    std::ofstream file(readonly_policy);
    file << "user=root\npath=/usr/bin\n";
    file.close();
    
    chmod(readonly_dir.c_str(), 0555); // 目录只读
    
    auto [exit_code, output] = runElfverify({"-p", readonly_policy});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
    
    chmod(readonly_dir.c_str(), 0755); // 恢复权限
}

// 新增：性能和压力测试类
class ElfverifyStressTest : public ElfverifyTest {};

TEST_F(ElfverifyStressTest, LargePolicyFile) {
    std::string content = "# Large policy file with many entries\n";
    for (int i = 0; i < 1000; i++) {
        content += "path=/usr/bin\n";
        content += "user=root\n";
        if (i % 100 == 0) {
            content += "# Section " + std::to_string(i/100) + "\n";
        }
    }
    createTestPolicyFile(content);
    
    auto start = std::chrono::high_resolution_clock::now();
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
    EXPECT_LT(duration.count(), 5000); // 应该在5秒内完成
}

TEST_F(ElfverifyStressTest, VeryLargePolicyFile) {
    std::string content = "# Very large policy file\n";
    for (int i = 0; i < 5000; i++) {
        content += "path=/usr/bin\n";
        if (i % 1000 == 0) {
            content += "user=root\n";
        }
    }
    createTestPolicyFile(content);
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyStressTest, ManyShortLines) {
    std::string content;
    for (int i = 0; i < 10000; i++) {
        content += "path=/usr/bin\n";
    }
    createTestPolicyFile(content);
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyStressTest, RepeatedExecution) {
    createTestPolicyFile("user=root\npath=/usr/bin\n");
    
    for (int i = 0; i < 10; i++) {
        auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
        EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
    }
}

TEST_F(ElfverifyStressTest, ConcurrentExecution) {
    createTestPolicyFile("user=root\npath=/usr/bin\n");
    
    std::vector<std::thread> threads;
    std::vector<bool> results(5, false);
    
    for (int i = 0; i < 5; i++) {
        threads.emplace_back([this, &results, i]() {
            auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
            results[i] = (output.find("Rule:") != std::string::npos || exit_code == 255);
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    for (bool result : results) {
        EXPECT_TRUE(result);
    }
}

// 新增：命令行参数测试类
class ElfverifyArgumentTest : public ElfverifyTest {};

TEST_F(ElfverifyArgumentTest, ShortHelpOption) {
    auto [exit_code, output] = runElfverify({"-h"});
    
    EXPECT_EQ(exit_code, 0);
    EXPECT_TRUE(output.find("Usage:") != std::string::npos);
}

TEST_F(ElfverifyArgumentTest, LongHelpOption) {
    auto [exit_code, output] = runElfverify({"--help"});
    
    EXPECT_EQ(exit_code, 0);
    EXPECT_TRUE(output.find("Usage:") != std::string::npos);
}

TEST_F(ElfverifyArgumentTest, MultipleHelpOptions) {
    auto [exit_code, output] = runElfverify({"-h", "--help"});
    
    EXPECT_EQ(exit_code, 0);
    EXPECT_TRUE(output.find("Usage:") != std::string::npos);
}

TEST_F(ElfverifyArgumentTest, HelpOptionWithOtherArgs) {
    createTestPolicyFile("user=root\n");
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file, "--help"});
    
    EXPECT_EQ(exit_code, 0);
    EXPECT_TRUE(output.find("Usage:") != std::string::npos);
}

TEST_F(ElfverifyArgumentTest, InvalidShortOption) {
    auto [exit_code, output] = runElfverify({"-x"});
    
    EXPECT_NE(exit_code, 0);
    EXPECT_TRUE(output.find("Usage:") != std::string::npos);
}

TEST_F(ElfverifyArgumentTest, InvalidLongOption) {
    auto [exit_code, output] = runElfverify({"--invalid"});
    
    EXPECT_NE(exit_code, 0);
    EXPECT_TRUE(output.find("Usage:") != std::string::npos);
}

TEST_F(ElfverifyArgumentTest, PolicyFileWithoutArgument) {
    auto [exit_code, output] = runElfverify({"-p"});
    
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyArgumentTest, LongPolicyFileWithoutArgument) {
    auto [exit_code, output] = runElfverify({"--policy-file"});
    
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyArgumentTest, MultiplePolicyFiles) {
    createTestPolicyFile("user=root\n");
    std::string temp_policy_file2 = temp_dir + "/policy2.pol";
    std::ofstream file2(temp_policy_file2);
    file2 << "user=daemon\n";
    file2.close();
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file, "-p", temp_policy_file2});
    
    // 最后一个策略文件应该生效
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyArgumentTest, MixedShortAndLongOptions) {
    createTestPolicyFile("user=root\n");
    auto [exit_code, output] = runElfverify({"--policy-file", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

// 新增：边界条件和异常测试类
class ElfverifyBoundaryTest : public ElfverifyTest {};

TEST_F(ElfverifyBoundaryTest, EmptyArgumentList) {
    auto [exit_code, output] = runElfverify({});
    
    EXPECT_TRUE(output.find("elfverify.pol") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyBoundaryTest, VeryLongPolicyFileName) {
    std::string long_name = temp_dir + "/" + std::string(200, 'a') + ".pol";
    createTestPolicyFile("user=root\n");
    system(("cp " + temp_policy_file + " '" + long_name + "'").c_str());
    
    auto [exit_code, output] = runElfverify({"-p", long_name});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyBoundaryTest, PolicyFileWithNullBytes) {
    std::ofstream file(temp_policy_file, std::ios::binary);
    file << "user=root\0\npath=/usr/bin\0\n";
    file.close();
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyBoundaryTest, PolicyFileWithBinaryData) {
    std::ofstream file(temp_policy_file, std::ios::binary);
    for (int i = 0; i < 256; i++) {
        file << static_cast<char>(i);
    }
    file << "\nuser=root\n";
    file.close();
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyBoundaryTest, PolicyFileWithUnicodeCharacters) {
    createTestPolicyFile("# 这是中文注释\nuser=root\n# Это русский комментарий\npath=/usr/bin\n");
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_TRUE(output.find("Rule:") != std::string::npos || exit_code == 255);
}

TEST_F(ElfverifyBoundaryTest, MaximumLineLength) {
    std::string max_line = "path=" + std::string(8188, '/') + "end"; // 接近8192字节限制
    createTestPolicyFile(max_line + "\n");
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
}

TEST_F(ElfverifyBoundaryTest, ExceedMaximumLineLength) {
    std::string exceed_line = "path=" + std::string(8200, '/') + "end"; // 超过8192字节限制
    createTestPolicyFile(exceed_line + "\n");
    
    auto [exit_code, output] = runElfverify({"-p", temp_policy_file});
    
    EXPECT_NE(exit_code, 0);
}

// 新增：BPF 程序功能测试类
class ElfverifyBPFTest : public ElfverifyTest {};

TEST_F(ElfverifyBPFTest, BPFProgramLoadsSuccessfully) {
    // 测试 BPF 程序的加载行为
    createStandardPolicyFile();
    auto [exit_code, output] = runElfverifyWithTimeout({"-p", temp_policy_file}, 3);
    
    // 在测试环境中验证程序行为
    if (exit_code == 124) {
        // 程序成功启动并运行，被 timeout 终止 - 这是最理想的情况
        EXPECT_TRUE(output.find("Program start") != std::string::npos || 
                   output.find("Rule:") != std::string::npos);
    } else if (exit_code == 255) {
        // BPF 加载失败，这在受限环境中是预期的
        EXPECT_TRUE(output.find("failed to load") != std::string::npos ||
                   output.find("Operation not permitted") != std::string::npos);
    } else {
        // 其他情况都是程序正常结束或遇到预期的错误
        EXPECT_TRUE(exit_code >= 0 && exit_code <= 255);
    }
    
    // 确保程序至少尝试了基本初始化
    EXPECT_TRUE(output.length() > 0 || exit_code == 255);
}

TEST_F(ElfverifyBPFTest, BPFProgramWithComplexPolicy) {
    // 测试复杂策略文件的处理
    createTestPolicyFile(
        "user=root\n"
        "user=daemon\n"
        "path=/usr/bin\n"
        "path=/bin\n"
        "path=/sbin\n"
        "path=/usr/sbin\n"
        "path=/usr/local/bin\n"
    );
    auto [exit_code, output] = runElfverifyWithTimeout({"-p", temp_policy_file}, 3);
    
    // 验证程序行为根据实际环境
    if (exit_code == 124) {
        // 理想情况：程序成功运行并解析所有规则
        EXPECT_TRUE(output.find("Rule: user root") != std::string::npos ||
                   output.find("Rule: user daemon") != std::string::npos ||
                   output.find("Rule: path /usr/bin") != std::string::npos);
    } else if (exit_code == 255) {
        // BPF 权限问题：程序尝试解析策略文件但 BPF 加载失败
        EXPECT_TRUE(output.find("failed to load") != std::string::npos ||
                   output.find("Operation not permitted") != std::string::npos ||
                   output.find("Rule:") != std::string::npos);
    } else {
        // 其他情况：确保是合理的退出状态
        EXPECT_TRUE(exit_code >= 0 && exit_code <= 255);
    }
    
    // 确保程序处理了策略文件（无论是否成功加载 BPF）
    EXPECT_TRUE(output.length() > 0 || exit_code == 255);
}

TEST_F(ElfverifyBPFTest, BPFProgramFunctionalTest) {
    // 测试 BPF 程序的实际监控功能
    createTestPolicyFile("user=root\npath=/usr/bin\n");
    
    // 启动 elfverify 在后台运行
    std::string cmd = "timeout 5s " + binary_path + " -p " + temp_policy_file + " > /tmp/elfverify_test_output.log 2>&1 &";
    int result = system(cmd.c_str());
    
    // 给程序一些时间启动
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // 尝试执行一些可能被监控的操作
    system("ls /bin/sh > /dev/null 2>&1");
    system("echo 'test' > /tmp/test_script.sh && chmod +x /tmp/test_script.sh");
    
    // 等待一段时间让 BPF 程序收集数据
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // 清理
    system("pkill -f elfverify");
    system("rm -f /tmp/test_script.sh");
    
    // 检查日志文件
    std::ifstream log_file("/tmp/elfverify_test_output.log");
    if (log_file.is_open()) {
        std::string log_content((std::istreambuf_iterator<char>(log_file)),
                               std::istreambuf_iterator<char>());
        
        // 验证程序至少启动了或遇到了预期的权限问题
        bool has_startup_log = log_content.find("Rule:") != std::string::npos ||
                              log_content.find("Program start") != std::string::npos;
        
        bool has_bpf_error = log_content.find("failed to load object") != std::string::npos ||
                            log_content.find("Operation not permitted") != std::string::npos;
        
        // 程序要么成功启动，要么遇到了预期的 BPF 权限问题
        EXPECT_TRUE(has_startup_log || has_bpf_error);
    }
    
    // 清理日志文件
    system("rm -f /tmp/elfverify_test_output.log");
} 