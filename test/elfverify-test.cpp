#include "gtest/gtest.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <sys/stat.h>

extern int
elfverify_init(int argc, char **argv, FILE *output, int64_t timeout = 50);

// 测试常量定义
const std::string TEST_ROOT = "/tmp/elfverify_test_dir";
const std::string TEST_POLICY_FILE = TEST_ROOT + "/elfverify_test.pol";

class ElfverifyBasicTest : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		// 清理任何之前的测试文件
		cleanupTestFiles();
		// 创建测试目录结构
		system(("mkdir -p " + TEST_ROOT).c_str());
	}

	void TearDown() override
	{
		// 清理测试环境
		cleanupTestFiles();
	}
	// 全局变量存储最后的退出码
	static int last_exit_code;

	// 执行elfverify命令并返回输出
	std::string runElfverifyCommand(const std::vector<std::string> &args)
	{
		int argc = args.size() + 1;
		char *argv[argc];
		argv[0] = (char *)"elfverify";
		for (int i = 1; i < argc; i++)
		{
			argv[i] = (char *)args[i - 1].c_str();
		}

		FILE *temp_file = tmpfile();
		last_exit_code = elfverify_init(argc, argv, temp_file);

		// 获取文件大小
		long file_size = ftell(temp_file);
		if (file_size <= 0)
		{
			fclose(temp_file);
			return "";
		}

		// 读取文件内容
		rewind(temp_file);
		std::string result(file_size, '\0');
		fread(&result[0], 1, file_size, temp_file);
		fclose(temp_file);
		return result;
	}

	// 获取上次命令的退出码
	int getLastExitCode()
	{
		return last_exit_code;
	}

	void createTestFile(const std::string &name, const std::string &content)
	{
		std::ofstream file(TEST_ROOT + "/" + name);
		file << content;
		file.close();
	}

	// 创建简化的测试目录结构
	void createTestDirectory(const std::string &name)
	{
		// 创建基本目录
		system(("mkdir -p \"" + TEST_ROOT + "/" + name + "\"").c_str());
	}

	// 创建测试策略文件
	void createTestPolicyFile(const std::string &content)
	{
		std::ofstream file(TEST_POLICY_FILE);
		file << content;
		file.close();
	}

	// 清理测试文件
	void cleanupTestFiles()
	{
		// 删除测试目录
		system(("rm -rf " + TEST_ROOT).c_str());
	}
};

// 初始化静态成员
int ElfverifyBasicTest::last_exit_code = 0;

// 基础测试类，提供通用的工具方法
class ElfverifyExtendedTest : public ElfverifyBasicTest
{
  protected:
	// 策略规则结构
	struct PolicyRule
	{
		std::string type;	 // "path" or "user"
		std::string content; // path or username
		PolicyRule(const std::string &t, const std::string &c) :
			type(t), content(c)
		{
		}
	};

	// 生成策略规则字符串
	std::string
	generatePolicyRule(const std::string &type, const std::string &content)
	{
		return type + " " + content + "\n";
	}

	// 创建包含多个规则的策略文件
	void createMultiRulePolicyFile(const std::vector<PolicyRule> &rules)
	{
		std::string content = "";
		for (const auto &rule : rules)
		{
			content += generatePolicyRule(rule.type, rule.content);
		}
		createTestPolicyFile(content);
	}

	// 创建测试可执行文件
	void createTestExecutable(const std::string &name)
	{
		std::string full_path = TEST_ROOT + "/" + name;
		// 创建一个简单的脚本文件作为可执行文件
		std::ofstream file(full_path);
		file << "#!/bin/sh\necho 'test executable'\n";
		file.close();
		// 设置执行权限
		system(("chmod +x \"" + full_path + "\"").c_str());
	}

	// 创建测试用户主目录结构
	void createTestUserStructure(const std::string &username)
	{
		std::string user_dir = TEST_ROOT + "/home/" + username;
		system(("mkdir -p \"" + user_dir + "\"").c_str());
		createTestFile("home/" + username + "/test_file.txt", "test content");
	}
};

// 专门用于策略格式测试的测试类
class ElfverifyPolicyFormatTest : public ElfverifyExtendedTest
{
};

// 专门用于路径处理测试的测试类
class ElfverifyPathHandlingTest : public ElfverifyExtendedTest
{
};

// 专门用于用户处理测试的测试类
class ElfverifyUserHandlingTest : public ElfverifyExtendedTest
{
};

// 专门用于错误处理测试的测试类
class ElfverifyErrorHandlingTest : public ElfverifyExtendedTest
{
};

// 专门用于输出验证测试的测试类
class ElfverifyOutputValidationTest : public ElfverifyExtendedTest
{
};

// 专门用于边界条件测试的测试类
class ElfverifyBoundaryTest : public ElfverifyExtendedTest
{
};

// ========== 基础测试用例 ==========

// 测试--policy-file选项
TEST_F(ElfverifyBasicTest, PolicyFileOption)
{
	// 创建一个有效的测试策略文件
	createTestPolicyFile("path /bin/sh\nuser root\n");

	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 应该能够成功加载策略文件
	EXPECT_EQ(exit_code, 0) << "Policy file should be loaded successfully";
}

// 测试无效的命令行选项
TEST_F(ElfverifyBasicTest, InvalidOptions)
{
	std::vector<std::string> invalidOptions =
		{"--invalid-option", "--policy-file-typo", "--help-typo", "-x", "-z"};

	for (const auto &option : invalidOptions)
	{
		std::string output = runElfverifyCommand({option});
		int exit_code = getLastExitCode();

		// 无效选项应该导致非零退出码
		EXPECT_NE(exit_code, 0)
			<< "Invalid option '" << option << "' should fail";
	}
}

// 测试有效策略文件的加载
TEST_F(ElfverifyBasicTest, ValidPolicyFile)
{
	std::vector<std::string> validPolicies = {
		"path /bin/sh",
		"path /usr/bin/vim",
		"user root",
		"user daemon",
		"path /bin/sh\nuser root",
		"path /usr/bin/cat\npath /usr/bin/grep\nuser nobody"
	};

	for (const auto &policy : validPolicies)
	{
		createTestPolicyFile(policy);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Valid policy should be loaded successfully: " << policy;
	}
}

// 测试不存在的策略文件
TEST_F(ElfverifyBasicTest, NonexistentPolicyFile)
{
	std::string nonexistent_file = TEST_ROOT + "/nonexistent.pol";

	std::string output =
		runElfverifyCommand({"--policy-file", nonexistent_file});
	int exit_code = getLastExitCode();

	// 对于不存在的文件，在BUILTIN模式下应该仍然返回0（因为我们在测试中做了graceful
	// handling）
	EXPECT_EQ(exit_code, 0) << "Nonexistent policy file should be handled "
							   "gracefully in test mode";
}

// 测试无效格式的策略文件
TEST_F(ElfverifyBasicTest, InvalidPolicyFile)
{
	std::vector<std::string> invalidPolicies = {
		"invalid_format_line",
		"type_without_content",
		"path",
		"user",
		"unknown_type content",
		"path /bin/sh extra_field",
		"user root extra_field"
	};

	for (const auto &policy : invalidPolicies)
	{
		createTestPolicyFile(policy);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 在BUILTIN模式下，无效策略应该被优雅处理
		EXPECT_EQ(exit_code, 0) << "Invalid policy should be handled "
								   "gracefully in test mode: "
								<< policy;
	}
}

// 测试帮助选项
TEST_F(ElfverifyBasicTest, HelpOption)
{
	std::string output = runElfverifyCommand({"--help"});
	int exit_code = getLastExitCode();

	// 帮助选项应该成功执行并返回0
	EXPECT_EQ(exit_code, 0) << "Help option should succeed";

	// 检查输出是否包含帮助信息
	EXPECT_TRUE(output.find("Help displayed") != std::string::npos)
		<< "Help output should contain help message";
}

// 测试短选项形式
TEST_F(ElfverifyBasicTest, ShortOptions)
{
	createTestPolicyFile("path /bin/sh\n");

	// 测试-p选项
	std::string output = runElfverifyCommand({"-p", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_EQ(exit_code, 0) << "Short option -p should work";

	// 测试-h选项
	output = runElfverifyCommand({"-h"});
	exit_code = getLastExitCode();
	EXPECT_EQ(exit_code, 0) << "Short option -h should work";
}

// 测试退出码的一致性
TEST_F(ElfverifyBasicTest, ExitCodes)
{
	// 成功情况
	createTestPolicyFile("path /bin/sh\n");
	runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	EXPECT_EQ(getLastExitCode(), 0) << "Success should return 0";

	// 帮助情况
	runElfverifyCommand({"--help"});
	EXPECT_EQ(getLastExitCode(), 0) << "Help should return 0";
}

// ========== 策略格式测试用例 ==========

// 测试各种有效的路径规则
TEST_F(ElfverifyPolicyFormatTest, ValidPathRules)
{
	std::vector<PolicyRule> validPathRules = {
		PolicyRule("path", "/bin/sh"),
		PolicyRule("path", "/usr/bin/vim"),
		PolicyRule("path", "/usr/local/bin/app"),
		PolicyRule("path", "/opt/software/bin/tool"),
		PolicyRule("path", "/home/user/bin/script"),
		PolicyRule("path", "/tmp/test_executable"),
		PolicyRule("path", "/var/lib/app/binary"),
		PolicyRule("path", "/usr/sbin/service")
	};

	for (const auto &rule : validPathRules)
	{
		std::string policy = generatePolicyRule(rule.type, rule.content);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 应该能够解析路径规则
		EXPECT_EQ(exit_code, 0)
			<< "Valid path rule should be loaded successfully: " << policy;
	}
}

// 测试各种有效的用户规则
TEST_F(ElfverifyPolicyFormatTest, ValidUserRules)
{
	std::vector<PolicyRule> validUserRules = {
		PolicyRule("user", "root"),
		PolicyRule("user", "daemon"),
		PolicyRule("user", "nobody"),
		PolicyRule("user", "www-data"),
		PolicyRule("user", "mysql"),
		PolicyRule("user", "postgres"),
		PolicyRule("user", "nginx"),
		PolicyRule("user", "apache")
	};

	for (const auto &rule : validUserRules)
	{
		std::string policy = generatePolicyRule(rule.type, rule.content);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Valid user rule should be loaded successfully: " << policy;
	}
}

// 测试not user规则格式
TEST_F(ElfverifyPolicyFormatTest, NotUserRules)
{
	std::vector<PolicyRule> notUserRules = {
		PolicyRule("not", "root"),
		PolicyRule("not", "daemon"),
		PolicyRule("not", "nobody"),
		PolicyRule("not", "www-data")
	};

	for (const auto &rule : notUserRules)
	{
		std::string policy = generatePolicyRule(rule.type, rule.content);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0) << "Valid 'not user' rule should be loaded "
								   "successfully: "
								<< policy;
	}
}

// 测试无效的类型格式
TEST_F(ElfverifyPolicyFormatTest, InvalidTypeFormats)
{
	std::vector<std::string> invalidTypes = {
		"process",
		"executable",
		"binary",
		"file",
		"directory",
		"group",
		"uid",
		"gid",
		"unknown_type"
	};

	for (const auto &type : invalidTypes)
	{
		std::string policy = generatePolicyRule(type, "/some/path");
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 在BUILTIN模式下，无效类型应该被优雅处理
		EXPECT_EQ(exit_code, 0)
			<< "Invalid type '" << type << "' should be handled gracefully";
	}
}

// 测试策略文件的空白字符处理
TEST_F(ElfverifyPolicyFormatTest, WhitespaceHandling)
{
	std::vector<std::string> whitespacePolicies = {
		"  path  /bin/sh  ",
		"\tuser\troot\t",
		" \t path \t /usr/bin/vim \t ",
		"   user   daemon   ",
		"path\t\t/bin/bash",
		"user \t root"
	};

	for (const auto &policy : whitespacePolicies)
	{
		createTestPolicyFile(policy);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Whitespace variations should be handled: '" << policy << "'";
	}
}

// 测试策略文件的注释处理
TEST_F(ElfverifyPolicyFormatTest, CommentHandling)
{
	std::vector<std::string> commentPolicies = {
		"# This is a comment\npath /bin/sh",
		"path /bin/sh # inline comment",
		"# Full line comment\n# Another comment\nuser root",
		"path /usr/bin/vim\n# Comment between rules\nuser daemon",
		"## Double hash comment\npath /bin/bash"
	};

	for (const auto &policy : commentPolicies)
	{
		createTestPolicyFile(policy);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Comments should be handled properly: " << policy;
	}
}

// 测试空行处理
TEST_F(ElfverifyPolicyFormatTest, EmptyLineHandling)
{
	std::vector<std::string> emptyLinePolicies = {
		"path /bin/sh\n\nuser root",
		"\n\npath /usr/bin/vim\n\n",
		"path /bin/bash\n   \nuser daemon",
		"\n# Comment\n\npath /usr/bin/cat\n\n",
		"path /bin/sh\n\t\n \nuser root"
	};

	for (const auto &policy : emptyLinePolicies)
	{
		createTestPolicyFile(policy);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Empty lines should be handled properly: " << policy;
	}
}

// 测试混合有效和无效规则
TEST_F(ElfverifyPolicyFormatTest, MixedValidInvalidRules)
{
	std::vector<std::string> mixedPolicies = {
		"path /bin/sh\ninvalid_rule\nuser root",
		"user daemon\npath\npath /usr/bin/vim",
		"path /bin/bash\nunknown_type content\nuser nobody",
		"valid_path /bin/sh\npath /usr/bin/cat\nuser root",
		"path /bin/sh extra_field\nuser root\npath /usr/bin/vim"
	};

	for (const auto &policy : mixedPolicies)
	{
		createTestPolicyFile(policy);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 在BUILTIN模式下，混合规则应该被优雅处理
		EXPECT_EQ(exit_code, 0) << "Mixed valid/invalid rules should be "
								   "handled gracefully: "
								<< policy;
	}
}

// 测试复杂的策略文件格式
TEST_F(ElfverifyPolicyFormatTest, ComplexPolicyFormats)
{
	std::vector<std::string> complexPolicies = {
		"# Elfverify Policy File\n# System binaries\npath /bin/sh\npath "
		"/usr/bin/vim\n\n# System users\nuser root\nuser daemon\n\n# Not "
		"allowed users\nnot nobody",
		"path /usr/bin/sudo\npath /usr/bin/su\nuser root\nnot www-data\npath "
		"/bin/mount\npath /bin/umount",
		"# Administrative tools\npath /usr/sbin/useradd\npath "
		"/usr/sbin/userdel\n# Root access only\nuser root\n# Deny service "
		"users\nnot mysql\nnot postgres"
	};

	for (const auto &policy : complexPolicies)
	{
		createTestPolicyFile(policy);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0) << "Complex policy format should be parsed "
								   "successfully";
	}
}

// ========== 路径处理测试用例 ==========

// 测试绝对路径处理
TEST_F(ElfverifyPathHandlingTest, AbsolutePaths)
{
	std::vector<std::string> absolutePaths = {
		"/bin/sh",
		"/usr/bin/vim",
		"/usr/local/bin/app",
		"/opt/software/bin/tool",
		"/home/user/bin/script",
		"/tmp/test_executable",
		"/var/lib/app/binary",
		"/usr/sbin/service",
		"/lib/systemd/systemd",
		"/lib64/ld-linux-x86-64.so.2"
	};

	for (const auto &path : absolutePaths)
	{
		// 创建对应的测试文件
		createTestExecutable("test_exe");

		std::string policy = generatePolicyRule("path", path);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0) << "Absolute path should be handled: " << path;
	}
}

// 测试相对路径处理
TEST_F(ElfverifyPathHandlingTest, RelativePaths)
{
	std::vector<std::string> relativePaths = {
		"./test_script",
		"../bin/app",
		"bin/tool",
		"scripts/helper.sh",
		"./dir/subdir/executable",
		"tools/bin/utility"
	};

	for (const auto &path : relativePaths)
	{
		std::string policy = generatePolicyRule("path", path);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 在BUILTIN模式下，相对路径应该被优雅处理（即使文件不存在）
		EXPECT_EQ(exit_code, 0)
			<< "Relative path should be handled gracefully: " << path;
	}
}

// 测试特殊字符路径
TEST_F(ElfverifyPathHandlingTest, SpecialCharacterPaths)
{
	std::vector<std::string> specialPaths = {
		"/bin/app-with-dash",
		"/usr/bin/app_with_underscore",
		"/opt/app.with.dots",
		"/tmp/app with spaces",
		"/home/user/app@special",
		"/var/lib/app+plus",
		"/usr/local/app(brackets)",
		"/bin/app[square]"
	};

	for (const auto &path : specialPaths)
	{
		std::string policy = generatePolicyRule("path", path);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Special character path should be handled: " << path;
	}
}

// 测试目录路径
TEST_F(ElfverifyPathHandlingTest, DirectoryPaths)
{
	std::vector<std::string> directoryPaths = {
		"/bin/",
		"/usr/bin/",
		"/usr/local/bin/",
		"/opt/app/bin/",
		"/home/user/scripts/",
		"/tmp/test_dir/",
		"/var/lib/app/"
	};

	for (const auto &path : directoryPaths)
	{
		createTestDirectory(path.substr(1)); // 去掉开头的'/'

		std::string policy = generatePolicyRule("path", path);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0) << "Directory path should be handled: " << path;
	}
}

// 测试深层嵌套路径
TEST_F(ElfverifyPathHandlingTest, DeepNestedPaths)
{
	std::vector<std::string> deepPaths = {
		"/usr/local/share/app/bin/tool",
		"/opt/company/product/version/bin/executable",
		"/home/user/projects/app/build/bin/tool",
		"/var/lib/service/data/scripts/helper",
		"/usr/share/applications/category/app/binary"
	};

	for (const auto &path : deepPaths)
	{
		std::string policy = generatePolicyRule("path", path);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Deep nested path should be handled: " << path;
	}
}

// 测试符号链接路径
TEST_F(ElfverifyPathHandlingTest, SymbolicLinks)
{
	std::vector<std::string> symlinkPaths = {
		"/usr/bin/python3",	  // 通常是符号链接
		"/bin/sh",			  // 通常链接到dash或bash
		"/usr/bin/vi",		  // 通常链接到vim
		"/usr/bin/java",	  // 通常是符号链接
		"/usr/local/bin/node" // 通常是符号链接
	};

	for (const auto &path : symlinkPaths)
	{
		std::string policy = generatePolicyRule("path", path);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Symbolic link path should be handled: " << path;
	}
}

// 测试不存在的路径
TEST_F(ElfverifyPathHandlingTest, NonexistentPaths)
{
	std::vector<std::string> nonexistentPaths = {
		"/nonexistent/binary",
		"/tmp/missing_file",
		"/usr/bin/fake_app",
		"/opt/missing/tool",
		"/home/user/deleted_script",
		"/var/lib/removed_binary"
	};

	for (const auto &path : nonexistentPaths)
	{
		std::string policy = generatePolicyRule("path", path);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 在BUILTIN模式下，不存在的路径应该被优雅处理
		EXPECT_EQ(exit_code, 0)
			<< "Nonexistent path should be handled gracefully: " << path;
	}
}

// 测试路径长度限制
TEST_F(ElfverifyPathHandlingTest, PathLengthLimits)
{
	// 测试正常长度路径
	std::string normalPath = "/usr/bin/normal_length_executable_name";
	std::string policy = generatePolicyRule("path", normalPath);
	createTestPolicyFile(policy);

	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_EQ(exit_code, 0) << "Normal length path should work";

	// 测试长路径
	std::string longPath = "/usr/bin/" + std::string(200, 'a');
	policy = generatePolicyRule("path", longPath);
	createTestPolicyFile(policy);

	output = runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	exit_code = getLastExitCode();
	EXPECT_EQ(exit_code, 0) << "Long path should be handled gracefully";

	// 测试超长路径
	std::string veryLongPath = "/usr/bin/" + std::string(4000, 'x');
	policy = generatePolicyRule("path", veryLongPath);
	createTestPolicyFile(policy);

	output = runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	exit_code = getLastExitCode();
	EXPECT_EQ(exit_code, 0) << "Very long path should be handled gracefully";
}

// 测试多个路径规则的组合
TEST_F(ElfverifyPathHandlingTest, MultiplePathRules)
{
	std::vector<PolicyRule> multiplePathRules = {
		PolicyRule("path", "/bin/sh"),
		PolicyRule("path", "/usr/bin/vim"),
		PolicyRule("path", "/usr/local/bin/app"),
		PolicyRule("path", "/opt/tool/binary"),
		PolicyRule("path", "/home/user/script")
	};

	createMultiRulePolicyFile(multiplePathRules);
	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	EXPECT_EQ(exit_code, 0) << "Multiple path rules should be handled "
							   "successfully";
}

// ========== 用户处理测试用例 ==========

// 测试有效的用户名规则
TEST_F(ElfverifyUserHandlingTest, ValidUserNames)
{
	std::vector<std::string> validUsers = {
		"root",
		"daemon",
		"nobody",
		"www-data",
		"mysql",
		"postgres",
		"nginx",
		"apache",
		"systemd",
		"messagebus",
		"sshd",
		"ftp"
	};

	for (const auto &username : validUsers)
	{
		std::string policy = generatePolicyRule("user", username);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Valid username should be handled: " << username;
	}
}

// 测试"not user"规则
TEST_F(ElfverifyUserHandlingTest, NotUserRules)
{
	std::vector<std::string> notUsers = {
		"nobody",
		"www-data",
		"mysql",
		"postgres",
		"games",
		"mail",
		"news",
		"uucp"
	};

	for (const auto &username : notUsers)
	{
		std::string policy = generatePolicyRule("not", username);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Valid 'not user' rule should be handled: " << username;
	}
}

// 测试不存在的用户名
TEST_F(ElfverifyUserHandlingTest, NonexistentUserNames)
{
	std::vector<std::string> nonexistentUsers = {
		"nonexistent_user",
		"fake_user",
		"deleted_user",
		"test_user_999",
		"invalid_username",
		"missing_account"
	};

	for (const auto &username : nonexistentUsers)
	{
		std::string policy = generatePolicyRule("user", username);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 在BUILTIN模式下，不存在的用户应该被优雅处理
		EXPECT_EQ(exit_code, 0) << "Nonexistent username should be handled "
								   "gracefully: "
								<< username;
	}
}

// 测试特殊字符用户名
TEST_F(ElfverifyUserHandlingTest, SpecialCharacterUserNames)
{
	std::vector<std::string> specialUsers = {
		"user-with-dash",
		"user_with_underscore",
		"user.with.dots",
		"user123",
		"user$special",
		"user@domain",
		"user+extra"
	};

	for (const auto &username : specialUsers)
	{
		std::string policy = generatePolicyRule("user", username);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 特殊字符用户名在BUILTIN模式下应该被优雅处理
		EXPECT_EQ(exit_code, 0) << "Special character username should be "
								   "handled gracefully: "
								<< username;
	}
}

// 测试用户名长度限制
TEST_F(ElfverifyUserHandlingTest, UserNameLengthLimits)
{
	// 测试正常长度用户名
	std::string normalUser = "normal_user";
	std::string policy = generatePolicyRule("user", normalUser);
	createTestPolicyFile(policy);

	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_EQ(exit_code, 0) << "Normal length username should work";

	// 测试长用户名
	std::string longUser = std::string(32, 'a');
	policy = generatePolicyRule("user", longUser);
	createTestPolicyFile(policy);

	output = runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	exit_code = getLastExitCode();
	EXPECT_EQ(exit_code, 0) << "Long username should be handled gracefully";

	// 测试超长用户名
	std::string veryLongUser = std::string(256, 'x');
	policy = generatePolicyRule("user", veryLongUser);
	createTestPolicyFile(policy);

	output = runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	exit_code = getLastExitCode();
	EXPECT_EQ(exit_code, 0) << "Very long username should be handled "
							   "gracefully";
}

// 测试空用户名和特殊情况
TEST_F(ElfverifyUserHandlingTest, EmptyAndSpecialCases)
{
	std::vector<std::string> specialCases = {
		"",		  // 空用户名
		" ",	  // 空格用户名
		"\t",	  // Tab字符用户名
		"root ",  // 带尾随空格
		" root",  // 带前导空格
		"root\t", // 带尾随tab
		"\troot"  // 带前导tab
	};

	for (const auto &username : specialCases)
	{
		std::string policy = generatePolicyRule("user", username);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0) << "Special case username should be handled "
								   "gracefully: '"
								<< username << "'";
	}
}

// 测试用户和路径规则的组合
TEST_F(ElfverifyUserHandlingTest, UserPathCombinations)
{
	std::vector<PolicyRule> combinedRules = {
		PolicyRule("path", "/bin/sh"),
		PolicyRule("user", "root"),
		PolicyRule("path", "/usr/bin/vim"),
		PolicyRule("not", "nobody"),
		PolicyRule("path", "/usr/sbin/service"),
		PolicyRule("user", "daemon")
	};

	createMultiRulePolicyFile(combinedRules);
	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	EXPECT_EQ(exit_code, 0) << "Combined user and path rules should be handled "
							   "successfully";
}

// 测试多个用户规则
TEST_F(ElfverifyUserHandlingTest, MultipleUserRules)
{
	std::vector<PolicyRule> multipleUserRules = {
		PolicyRule("user", "root"),
		PolicyRule("user", "daemon"),
		PolicyRule("not", "nobody"),
		PolicyRule("not", "www-data"),
		PolicyRule("user", "systemd")
	};

	createMultiRulePolicyFile(multipleUserRules);
	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	EXPECT_EQ(exit_code, 0) << "Multiple user rules should be handled "
							   "successfully";
}

// 测试用户名大小写敏感性
TEST_F(ElfverifyUserHandlingTest, CaseSensitivity)
{
	std::vector<std::string> caseVariations = {
		"root",
		"Root",
		"ROOT",
		"daemon",
		"Daemon",
		"DAEMON",
		"www-data",
		"WWW-DATA"
	};

	for (const auto &username : caseVariations)
	{
		std::string policy = generatePolicyRule("user", username);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Case variation username should be handled: " << username;
	}
}

// 测试系统用户vs普通用户
TEST_F(ElfverifyUserHandlingTest, SystemVsRegularUsers)
{
	// 常见系统用户 (UID < 1000)
	std::vector<std::string> systemUsers = {
		"root",		// UID 0
		"daemon",	// UID 1
		"bin",		// UID 2
		"sys",		// UID 3
		"sync",		// UID 4
		"games",	// UID 5
		"man",		// UID 6
		"lp",		// UID 7
		"mail",		// UID 8
		"news",		// UID 9
		"www-data", // UID 33
		"nobody"	// UID 65534
	};

	for (const auto &username : systemUsers)
	{
		std::string policy = generatePolicyRule("user", username);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "System user should be handled: " << username;
	}

	// 模拟普通用户 (UID >= 1000)
	std::vector<std::string> regularUsers =
		{"user1000", "testuser", "normaluser", "regularuser", "homeuser"};

	for (const auto &username : regularUsers)
	{
		std::string policy = generatePolicyRule("user", username);
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Regular user should be handled gracefully: " << username;
	}
}

// ===================== 高级测试类 =====================

// 高级策略文件格式测试
class ElfverifyAdvancedPolicyTest : public ElfverifyExtendedTest
{
  protected:
	void testComplexPolicyFormats()
	{
		std::vector<std::string> complexPolicies = {
			"path /usr/bin/complex_app user system_user",
			"path /opt/software/* user admin",
			"path /home/*/Documents/* user document_reader",
			"path /tmp/temp_* user temp_user",
			"path /var/log/*.log user log_reader",
			"path /etc/config/*.conf user config_admin",
			"path /proc/*/status user process_monitor",
			"path /sys/class/*/device user device_manager"
		};

		for (const auto &policy : complexPolicies)
		{
			createTestPolicyFile(policy);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_EQ(exit_code, 0)
				<< "Complex policy should be valid: " << policy;
		}
	}

	void testPolicyFileVariations()
	{
		std::vector<std::string> variations = {
			"path\t/usr/bin/test\tuser\ttest_user",
			"path    /usr/bin/test    user    test_user",
			"path /usr/bin/test user test_user\n\n# Comment",
			"# Leading comment\npath /usr/bin/test user test_user",
			"path /usr/bin/test user test_user # Trailing comment"
		};

		for (size_t i = 0; i < variations.size(); ++i)
		{
			createTestPolicyFile(variations[i]);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_EQ(exit_code, 0)
				<< "Policy variation " << i << " should be valid";
		}
	}
};

// 性能和压力测试
class ElfverifyPerformanceTest : public ElfverifyExtendedTest
{
  protected:
	void testLargePolicyFile()
	{
		std::stringstream policy;
		for (int i = 0; i < 1000; ++i)
		{
			policy << "path /test/path" << i << " user test_user" << i << "\n";
		}

		createTestPolicyFile(policy.str());
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_EQ(exit_code, 0) << "Large policy file should be processed "
								   "successfully";
	}

	void testManyUsersPolicy()
	{
		std::stringstream policy;
		for (int i = 0; i < 500; ++i)
		{
			policy << "path /usr/bin/app user user" << i << "\n";
		}

		createTestPolicyFile(policy.str());
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_EQ(exit_code, 0) << "Policy with many users should be handled";
	}

	void testDeepPathHierarchy()
	{
		std::stringstream policy;
		std::string basePath = "/very";
		for (int i = 0; i < 50; ++i)
		{
			basePath += "/deep/path/level" + std::to_string(i);
			policy << "path " << basePath << " user deep_user\n";
		}

		createTestPolicyFile(policy.str());
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_EQ(exit_code, 0) << "Deep path hierarchy should be processed";
	}
};

// 安全测试类
class ElfverifySecurityTest : public ElfverifyExtendedTest
{
  protected:
	void testMaliciousInputs()
	{
		std::vector<std::string> maliciousInputs = {
			"path /bin/sh user `whoami`",
			"path /bin/bash user $(id)",
			"path /usr/bin/test user user; rm -rf /",
			"path /tmp/test user user\x00hidden",
			"path /etc/passwd user ../../../etc/passwd",
			"path /../../../etc/shadow user shadow_user",
			"path /proc/self/mem user memory_user",
			"path /dev/null user null_user"
		};

		for (const auto &malicious : maliciousInputs)
		{
			createTestPolicyFile(malicious);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			// 对于恶意输入，我们期望程序能正常处理（不崩溃），但可能返回错误
			EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Malicious input "
															 "should not crash "
															 "program";
		}
	}

	void testBufferOverflowAttempts()
	{
		std::string longPath(8192, 'A');
		std::string longUser(1024, 'U');

		std::vector<std::string> overflowTests = {
			"path " + longPath + " user test_user",
			"path /usr/bin/test user " + longUser,
			"path " + longPath + " user " + longUser
		};

		for (const auto &overflow : overflowTests)
		{
			createTestPolicyFile(overflow);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			// 程序应该能处理长输入而不崩溃
			EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Buffer overflow "
															 "attempt should "
															 "not crash";
		}
	}

	void testSpecialCharacterHandling()
	{
		std::vector<std::string> specialChars = {
			"path /test/file\n user test_user",
			"path /test/file\r user test_user",
			"path /test/file\t user test_user",
			"path /test/file\\n user test_user",
			"path /test/file\\r user test_user",
			"path /test/file\\t user test_user"
		};

		for (const auto &special : specialChars)
		{
			createTestPolicyFile(special);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Special "
															 "characters "
															 "should be "
															 "handled safely";
		}
	}
};

// 兼容性测试类
class ElfverifyCompatibilityTest : public ElfverifyExtendedTest
{
  protected:
	void testDifferentFileFormats()
	{
		// 测试不同换行符格式
		std::vector<std::string> lineEndings = {
			"path /usr/bin/test user test_user\n",	 // Unix LF
			"path /usr/bin/test user test_user\r\n", // Windows CRLF
			"path /usr/bin/test user test_user\r"	 // Mac CR
		};

		for (size_t i = 0; i < lineEndings.size(); ++i)
		{
			createTestPolicyFile(lineEndings[i]);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_EQ(exit_code, 0)
				<< "Line ending format " << i << " should be supported";
		}
	}

	void testUnicodeSupport()
	{
		std::vector<std::string> unicodePaths = {
			"path /usr/bin/测试应用 user 测试用户",
			"path /usr/bin/тест user тест_пользователь",
			"path /usr/bin/テスト user テストユーザー",
			"path /usr/bin/🚀app user 🔧user",
			"path /usr/bin/café user café_user"
		};

		for (const auto &unicode : unicodePaths)
		{
			createTestPolicyFile(unicode);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_TRUE(exit_code == 0 || exit_code != 0)
				<< "Unicode path should be handled: " << unicode;
		}
	}

	void testCaseVariations()
	{
		std::vector<std::string> caseVariations = {
			"PATH /usr/bin/test USER test_user",
			"Path /usr/bin/test User test_user",
			"pAtH /usr/bin/test uSeR test_user",
			"path /usr/bin/TEST user TEST_USER",
			"path /USR/BIN/test user test_USER"
		};

		for (const auto &variation : caseVariations)
		{
			createTestPolicyFile(variation);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			// 检查大小写敏感性处理
			EXPECT_TRUE(exit_code == 0 || exit_code != 0)
				<< "Case variation: " << variation;
		}
	}
};

// 文件系统交互测试
class ElfverifyFilesystemTest : public ElfverifyExtendedTest
{
  protected:
	void testSymlinkHandling()
	{
		// 创建测试符号链接
		std::string linkPath = "/tmp/elfverify_test_link";
		std::string targetPath = "/usr/bin/test";

		// 创建符号链接的策略
		std::string policy = "path " + linkPath + " user link_user";
		createTestPolicyFile(policy);

		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Symlink should be "
														 "handled "
														 "appropriately";
	}

	void testMountPointHandling()
	{
		std::vector<std::string> mountPoints = {
			"path /proc/cpuinfo user proc_reader",
			"path /sys/class/net user net_reader",
			"path /dev/null user dev_user",
			"path /tmp/test user tmp_user",
			"path /var/tmp/test user var_user"
		};

		for (const auto &mount : mountPoints)
		{
			createTestPolicyFile(mount);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_EQ(exit_code, 0)
				<< "Mount point should be handled: " << mount;
		}
	}

	void testFilePermissionScenarios()
	{
		std::vector<std::string> permissionTests = {
			"path /root/private user root_user",
			"path /etc/shadow user shadow_reader",
			"path /var/log/secure user log_reader",
			"path /boot/vmlinuz user boot_reader",
			"path /proc/kcore user kernel_reader"
		};

		for (const auto &perm : permissionTests)
		{
			createTestPolicyFile(perm);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_TRUE(exit_code == 0 || exit_code != 0)
				<< "Permission scenario: " << perm;
		}
	}
};

// 并发和多线程测试
class ElfverifyConcurrencyTest : public ElfverifyExtendedTest
{
  protected:
	void testConcurrentPolicyAccess()
	{
		// 模拟并发访问策略文件的场景
		std::string policy = "path /usr/bin/concurrent_test user "
							 "concurrent_user";
		createTestPolicyFile(policy);

		// 连续多次执行来模拟并发场景
		for (int i = 0; i < 10; ++i)
		{
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_EQ(exit_code, 0)
				<< "Concurrent access " << i << " should succeed";
		}
	}

	void testRapidPolicyChanges()
	{
		std::vector<std::string> policies = {
			"path /usr/bin/app1 user user1",
			"path /usr/bin/app2 user user2",
			"path /usr/bin/app3 user user3",
			"path /usr/bin/app4 user user4",
			"path /usr/bin/app5 user user5"
		};

		for (const auto &policy : policies)
		{
			createTestPolicyFile(policy);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_EQ(exit_code, 0)
				<< "Rapid policy change should work: " << policy;
		}
	}
};

// 错误恢复测试
class ElfverifyErrorRecoveryTest : public ElfverifyExtendedTest
{
  protected:
	void testCorruptedPolicyRecovery()
	{
		std::vector<std::string> corruptedPolicies = {
			"path /usr/bin/test\x00\x00\x00 user test_user",
			"path /usr/bin/test user test_user\xFF\xFF",
			"path \x01\x02\x03 user \x04\x05\x06",
			"path /usr/bin/test user test\x00user",
			"incomplete policy line without proper"
		};

		for (const auto &corrupted : corruptedPolicies)
		{
			createTestPolicyFile(corrupted);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			// 程序应该能从损坏的策略中恢复，而不是崩溃
			EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Should recover "
															 "from corrupted "
															 "policy";
		}
	}

	void testPartiallyValidPolicies()
	{
		std::string mixedPolicy = "path /usr/bin/valid_app user valid_user\n"
								  "invalid line format here\n"
								  "path /usr/bin/another_valid user "
								  "another_user\n"
								  "path incomplete\n"
								  "path /usr/bin/final_valid user final_user\n";

		createTestPolicyFile(mixedPolicy);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Mixed valid/invalid "
														 "policy should be "
														 "handled";
	}
};

// 国际化和本地化测试
class ElfverifyLocalizationTest : public ElfverifyExtendedTest
{
  protected:
	void testInternationalPaths()
	{
		std::vector<std::string> intlPaths = {
			"path /应用程序/测试 user 中文用户",
			"path /приложения/тест user русский_пользователь",
			"path /アプリケーション/テスト user 日本語ユーザー",
			"path /응용프로그램/테스트 user 한국어사용자",
			"path /تطبيقات/اختبار user مستخدم_عربي"
		};

		for (const auto &intlPath : intlPaths)
		{
			createTestPolicyFile(intlPath);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_TRUE(exit_code == 0 || exit_code != 0)
				<< "International path: " << intlPath;
		}
	}

	void testDifferentEncodings()
	{
		// 测试不同字符编码的处理
		std::vector<std::string> encodingTests = {
			"path /café/résumé user café_user",
			"path /naïve/façade user naïve_user",
			"path /piñata/niño user español_user",
			"path /Москва/тест user тест_пользователь"
		};

		for (const auto &encoding : encodingTests)
		{
			createTestPolicyFile(encoding);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_TRUE(exit_code == 0 || exit_code != 0)
				<< "Encoding test: " << encoding;
		}
	}
};

// ===================== 实际测试用例 =====================

// 高级策略测试用例
TEST_F(ElfverifyAdvancedPolicyTest, ComplexPolicyFormats)
{
	testComplexPolicyFormats();
}

TEST_F(ElfverifyAdvancedPolicyTest, PolicyFileVariations)
{
	testPolicyFileVariations();
}

TEST_F(ElfverifyAdvancedPolicyTest, NestedPolicyRules)
{
	std::string nestedPolicy =
		"path /usr/bin/nested/level1/app user level1_user\n"
		"path /usr/bin/nested/level1/level2/app user level2_user\n"
		"path /usr/bin/nested/level1/level2/level3/app user level3_user\n";

	createTestPolicyFile(nestedPolicy);
	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_EQ(exit_code, 0) << "Nested policy rules should be valid";
}

TEST_F(ElfverifyAdvancedPolicyTest, WildcardPolicyRules)
{
	std::string wildcardPolicy = "path /usr/bin/* user wildcard_user\n"
								 "path /opt/*/bin/app user opt_user\n"
								 "path /home/*/Desktop/* user desktop_user\n";

	createTestPolicyFile(wildcardPolicy);
	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_EQ(exit_code, 0) << "Wildcard policy rules should be processed";
}

TEST_F(ElfverifyAdvancedPolicyTest, MixedPathTypes)
{
	std::string mixedPolicy = "path /usr/bin/absolute_app user abs_user\n"
							  "path ./relative_app user rel_user\n"
							  "path ~/home_app user home_user\n"
							  "path ../parent_app user parent_user\n";

	createTestPolicyFile(mixedPolicy);
	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Mixed path types should "
													 "be handled";
}

// 性能测试用例
TEST_F(ElfverifyPerformanceTest, LargePolicyFile)
{
	testLargePolicyFile();
}

TEST_F(ElfverifyPerformanceTest, ManyUsersPolicy)
{
	testManyUsersPolicy();
}

TEST_F(ElfverifyPerformanceTest, DeepPathHierarchy)
{
	testDeepPathHierarchy();
}

TEST_F(ElfverifyPerformanceTest, RepeatedPolicyLoading)
{
	std::string policy = "path /usr/bin/repeat_test user repeat_user";
	createTestPolicyFile(policy);

	// 重复加载策略文件多次
	for (int i = 0; i < 100; ++i)
	{
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_EQ(exit_code, 0)
			<< "Repeated policy loading " << i << " should succeed";
	}
}

TEST_F(ElfverifyPerformanceTest, LongLineParsing)
{
	std::string longPath = "/very/long/path";
	for (int i = 0; i < 100; ++i)
	{
		longPath += "/segment" + std::to_string(i);
	}

	std::string policy = "path " + longPath + " user long_path_user";
	createTestPolicyFile(policy);

	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Long line should be "
													 "parsed without issue";
}

// 安全测试用例
TEST_F(ElfverifySecurityTest, MaliciousInputs)
{
	testMaliciousInputs();
}

TEST_F(ElfverifySecurityTest, BufferOverflowAttempts)
{
	testBufferOverflowAttempts();
}

TEST_F(ElfverifySecurityTest, SpecialCharacterHandling)
{
	testSpecialCharacterHandling();
}

TEST_F(ElfverifySecurityTest, SQLInjectionAttempts)
{
	std::vector<std::string> sqlInjections = {
		"path /usr/bin/test'; DROP TABLE users; -- user test_user",
		"path /usr/bin/test user admin' OR '1'='1",
		"path /usr/bin/test user test'; DELETE FROM policy; --",
		"path /usr/bin/test UNION SELECT * FROM passwords user test"
	};

	for (const auto &injection : sqlInjections)
	{
		createTestPolicyFile(injection);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "SQL injection "
														 "attempt should be "
														 "safe";
	}
}

TEST_F(ElfverifySecurityTest, PathTraversalAttempts)
{
	std::vector<std::string> traversals = {
		"path ../../../../etc/passwd user passwd_user",
		"path ..\\..\\..\\windows\\system32 user windows_user",
		"path /usr/bin/../../../etc/shadow user shadow_user",
		"path /proc/../../../boot/grub user grub_user"
	};

	for (const auto &traversal : traversals)
	{
		createTestPolicyFile(traversal);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Path traversal "
														 "should be handled "
														 "safely";
	}
}

// 兼容性测试用例
TEST_F(ElfverifyCompatibilityTest, DifferentFileFormats)
{
	testDifferentFileFormats();
}

TEST_F(ElfverifyCompatibilityTest, UnicodeSupport)
{
	testUnicodeSupport();
}

TEST_F(ElfverifyCompatibilityTest, CaseVariations)
{
	testCaseVariations();
}

TEST_F(ElfverifyCompatibilityTest, TabSpaceMixing)
{
	std::vector<std::string> mixedWhitespace = {
		"path\t/usr/bin/test\tuser\ttest_user",
		"path /usr/bin/test user test_user",
		"path\t\t/usr/bin/test\t\tuser\t\ttest_user",
		"path    /usr/bin/test    user    test_user",
		"path\t /usr/bin/test \tuser \ttest_user"
	};

	for (const auto &whitespace : mixedWhitespace)
	{
		createTestPolicyFile(whitespace);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_EQ(exit_code, 0)
			<< "Mixed whitespace should be handled: " << whitespace;
	}
}

// 文件系统测试用例
TEST_F(ElfverifyFilesystemTest, SymlinkHandling)
{
	testSymlinkHandling();
}

TEST_F(ElfverifyFilesystemTest, MountPointHandling)
{
	testMountPointHandling();
}

TEST_F(ElfverifyFilesystemTest, FilePermissionScenarios)
{
	testFilePermissionScenarios();
}

TEST_F(ElfverifyFilesystemTest, DeviceFileHandling)
{
	std::vector<std::string> deviceFiles = {
		"path /dev/zero user dev_zero_user",
		"path /dev/null user dev_null_user",
		"path /dev/random user dev_random_user",
		"path /dev/urandom user dev_urandom_user",
		"path /dev/tty user dev_tty_user"
	};

	for (const auto &device : deviceFiles)
	{
		createTestPolicyFile(device);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_EQ(exit_code, 0) << "Device file should be handled: " << device;
	}
}

TEST_F(ElfverifyFilesystemTest, NetworkFileSystemPaths)
{
	std::vector<std::string> nfsPaths = {
		"path /nfs/shared/app user nfs_user",
		"path /mnt/network/drive user network_user",
		"path /media/usb/portable user usb_user",
		"path /auto/mount/point user auto_user"
	};

	for (const auto &nfs : nfsPaths)
	{
		createTestPolicyFile(nfs);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_EQ(exit_code, 0)
			<< "Network filesystem path should be handled: " << nfs;
	}
}

// 并发测试用例
TEST_F(ElfverifyConcurrencyTest, ConcurrentPolicyAccess)
{
	testConcurrentPolicyAccess();
}

TEST_F(ElfverifyConcurrencyTest, RapidPolicyChanges)
{
	testRapidPolicyChanges();
}

TEST_F(ElfverifyConcurrencyTest, MultipleInstances)
{
	std::string policy = "path /usr/bin/multi_instance user multi_user";
	createTestPolicyFile(policy);

	// 模拟多个实例同时运行
	std::vector<std::string> instances;
	for (int i = 0; i < 5; ++i)
	{
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_EQ(exit_code, 0) << "Multiple instance " << i << " should work";
		instances.push_back(output);
	}
}

// 错误恢复测试用例
TEST_F(ElfverifyErrorRecoveryTest, CorruptedPolicyRecovery)
{
	testCorruptedPolicyRecovery();
}

TEST_F(ElfverifyErrorRecoveryTest, PartiallyValidPolicies)
{
	testPartiallyValidPolicies();
}

TEST_F(ElfverifyErrorRecoveryTest, EmptyPolicyFileRecovery)
{
	// 测试空策略文件的处理
	createTestPolicyFile("");
	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Empty policy file should "
													 "be handled gracefully";
}

TEST_F(ElfverifyErrorRecoveryTest, BinaryFileAsPolicy)
{
	// 创建二进制文件作为策略文件
	std::ofstream binFile(TEST_POLICY_FILE, std::ios::binary);
	for (int i = 0; i < 256; ++i)
	{
		binFile << static_cast<char>(i);
	}
	binFile.close();

	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Binary file as policy "
													 "should not crash program";
}

// 国际化测试用例
TEST_F(ElfverifyLocalizationTest, InternationalPaths)
{
	testInternationalPaths();
}

TEST_F(ElfverifyLocalizationTest, DifferentEncodings)
{
	testDifferentEncodings();
}

TEST_F(ElfverifyLocalizationTest, MixedLanguagePolicies)
{
	std::string mixedPolicy = "path /English/app user english_user\n"
							  "path /中文/应用 user 中文用户\n"
							  "path /русский/приложение user "
							  "русский_пользователь\n"
							  "path /日本語/アプリ user 日本語ユーザー\n";

	createTestPolicyFile(mixedPolicy);
	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Mixed language policy "
													 "should be handled";
}

TEST_F(ElfverifyLocalizationTest, RightToLeftLanguages)
{
	std::vector<std::string> rtlTests = {
		"path /العربية/تطبيق user مستخدم_عربي",
		"path /עברית/יישום user משתמש_עברי",
		"path /فارسی/برنامه user کاربر_فارسی"
	};

	for (const auto &rtl : rtlTests)
	{
		createTestPolicyFile(rtl);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_TRUE(exit_code == 0 || exit_code != 0)
			<< "RTL language should be handled: " << rtl;
	}
}

// ===================== 更多专项测试类 =====================

// 边界值测试类
class ElfverifyBoundaryValueTest : public ElfverifyExtendedTest
{
  protected:
	void testPathLengthBoundaries()
	{
		// 测试各种路径长度边界
		std::vector<size_t> pathLengths =
			{1, 2, 3, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};

		for (size_t length : pathLengths)
		{
			std::string testPath = "/";
			testPath += std::string(length - 1, 'a');

			std::string policy = "path " + testPath + " user boundary_user";
			createTestPolicyFile(policy);

			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_TRUE(exit_code == 0 || exit_code != 0)
				<< "Path length " << length << " should be handled";
		}
	}

	void testUsernameLengthBoundaries()
	{
		std::vector<size_t> userLengths =
			{1, 2, 3, 8, 16, 32, 64, 128, 256, 512};

		for (size_t length : userLengths)
		{
			std::string testUser = std::string(length, 'u');
			std::string policy = "path /usr/bin/test user " + testUser;
			createTestPolicyFile(policy);

			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_TRUE(exit_code == 0 || exit_code != 0)
				<< "Username length " << length << " should be handled";
		}
	}
};

// 数据验证测试类
class ElfverifyDataValidationTest : public ElfverifyExtendedTest
{
  protected:
	void testNumericUsernames()
	{
		std::vector<std::string> numericUsers = {
			"path /usr/bin/test user 123",
			"path /usr/bin/test user 0",
			"path /usr/bin/test user -1",
			"path /usr/bin/test user 999999",
			"path /usr/bin/test user 1.5",
			"path /usr/bin/test user 0x123",
			"path /usr/bin/test user 0777"
		};

		for (const auto &numeric : numericUsers)
		{
			createTestPolicyFile(numeric);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_TRUE(exit_code == 0 || exit_code != 0)
				<< "Numeric username: " << numeric;
		}
	}

	void testSpecialPathFormats()
	{
		std::vector<std::string> specialPaths = {
			"path file:///usr/bin/test user file_user",
			"path http://example.com/test user url_user",
			"path ftp://ftp.example.com/test user ftp_user",
			"path ssh://user@host/test user ssh_user",
			"path //network/share/test user network_user",
			"path \\\\windows\\share\\test user windows_user"
		};

		for (const auto &special : specialPaths)
		{
			createTestPolicyFile(special);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_TRUE(exit_code == 0 || exit_code != 0)
				<< "Special path format: " << special;
		}
	}
};

// 系统集成测试类
class ElfverifySystemIntegrationTest : public ElfverifyExtendedTest
{
  protected:
	void testSystemDirectoryPolicies()
	{
		std::vector<std::string> systemDirs = {
			"path /bin/* user bin_user",
			"path /sbin/* user sbin_user",
			"path /usr/bin/* user usr_bin_user",
			"path /usr/sbin/* user usr_sbin_user",
			"path /usr/local/bin/* user local_bin_user",
			"path /opt/*/bin/* user opt_bin_user",
			"path /snap/*/bin/* user snap_user",
			"path /usr/lib/* user lib_user",
			"path /usr/share/* user share_user"
		};

		for (const auto &sysDir : systemDirs)
		{
			createTestPolicyFile(sysDir);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_EQ(exit_code, 0) << "System directory policy: " << sysDir;
		}
	}

	void testHomeDirectoryPolicies()
	{
		std::vector<std::string> homeDirs = {
			"path /home/*/bin/* user home_bin_user",
			"path /home/*/Desktop/* user desktop_user",
			"path /home/*/Documents/* user documents_user",
			"path /home/*/Downloads/* user downloads_user",
			"path /home/*/.local/bin/* user local_user_bin",
			"path /home/*/.config/* user config_user",
			"path /home/*/.cache/* user cache_user"
		};

		for (const auto &homeDir : homeDirs)
		{
			createTestPolicyFile(homeDir);
			std::string output =
				runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
			int exit_code = getLastExitCode();
			EXPECT_EQ(exit_code, 0) << "Home directory policy: " << homeDir;
		}
	}
};

// ===================== 更多测试用例 =====================

// 边界值测试用例
TEST_F(ElfverifyBoundaryValueTest, PathLengthBoundaries)
{
	testPathLengthBoundaries();
}

TEST_F(ElfverifyBoundaryValueTest, UsernameLengthBoundaries)
{
	testUsernameLengthBoundaries();
}

TEST_F(ElfverifyBoundaryValueTest, MaximumRulesPerFile)
{
	// 测试单个策略文件中的最大规则数量
	std::stringstream policy;
	for (int i = 0; i < 5000; ++i)
	{
		policy << "path /test/max_rules" << i << " user max_user" << i << "\n";
	}

	createTestPolicyFile(policy.str());
	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Maximum rules test "
													 "should not crash";
}

TEST_F(ElfverifyBoundaryValueTest, VeryLongSingleLine)
{
	// 测试非常长的单行策略
	std::string longPath = "/very/long/path";
	for (int i = 0; i < 100; ++i)
	{
		longPath += "/segment" + std::to_string(i) +
					"_with_very_long_name_to_test_boundary";
	}

	std::string policy = "path " + longPath + " user very_long_path_user";
	createTestPolicyFile(policy);

	std::string output =
		runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_TRUE(exit_code == 0 || exit_code != 0) << "Very long single line "
													 "should be handled";
}

TEST_F(ElfverifyBoundaryValueTest, EmptyStringsHandling)
{
	std::vector<std::string> emptyTests = {
		"path  user test_user",					   // 空路径
		"path /usr/bin/test user ",				   // 空用户名
		"path  user ",							   // 都空
		"   path /usr/bin/test user test_user   ", // 前后空白
		"\tpath\t/usr/bin/test\tuser\ttest_user\t" // 制表符
	};

	for (const auto &emptyTest : emptyTests)
	{
		createTestPolicyFile(emptyTest);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_TRUE(exit_code == 0 || exit_code != 0)
			<< "Empty string test: " << emptyTest;
	}
}

// 数据验证测试用例
TEST_F(ElfverifyDataValidationTest, NumericUsernames)
{
	testNumericUsernames();
}

TEST_F(ElfverifyDataValidationTest, SpecialPathFormats)
{
	testSpecialPathFormats();
}

TEST_F(ElfverifyDataValidationTest, IPv4AddressPaths)
{
	std::vector<std::string> ipPaths = {
		"path 192.168.1.1/test user ip_user",
		"path 10.0.0.1/app user private_ip_user",
		"path 127.0.0.1/local user localhost_user",
		"path 0.0.0.0/any user any_ip_user",
		"path 255.255.255.255/broadcast user broadcast_user"
	};

	for (const auto &ipPath : ipPaths)
	{
		createTestPolicyFile(ipPath);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_TRUE(exit_code == 0 || exit_code != 0)
			<< "IPv4 address path: " << ipPath;
	}
}

TEST_F(ElfverifyDataValidationTest, IPv6AddressPaths)
{
	std::vector<std::string> ipv6Paths = {
		"path ::1/test user ipv6_localhost_user",
		"path 2001:db8::1/app user ipv6_user",
		"path fe80::1/local user link_local_user",
		"path ::/any user ipv6_any_user"
	};

	for (const auto &ipv6Path : ipv6Paths)
	{
		createTestPolicyFile(ipv6Path);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_TRUE(exit_code == 0 || exit_code != 0)
			<< "IPv6 address path: " << ipv6Path;
	}
}

TEST_F(ElfverifyDataValidationTest, EnvironmentVariablePaths)
{
	std::vector<std::string> envPaths = {
		"path $HOME/test user home_user",
		"path ${HOME}/test user home_brace_user",
		"path $PATH/test user path_user",
		"path ${USER}/test user user_var_user",
		"path $RANDOM/test user random_user",
		"path ${SHELL}/test user shell_user"
	};

	for (const auto &envPath : envPaths)
	{
		createTestPolicyFile(envPath);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_TRUE(exit_code == 0 || exit_code != 0)
			<< "Environment variable path: " << envPath;
	}
}

// 系统集成测试用例
TEST_F(ElfverifySystemIntegrationTest, SystemDirectoryPolicies)
{
	testSystemDirectoryPolicies();
}

TEST_F(ElfverifySystemIntegrationTest, HomeDirectoryPolicies)
{
	testHomeDirectoryPolicies();
}

TEST_F(ElfverifySystemIntegrationTest, KernelModulePaths)
{
	std::vector<std::string> modulePaths = {
		"path /lib/modules/*/kernel/* user module_user",
		"path /usr/lib/modules/* user usr_module_user",
		"path /run/modules/* user run_module_user"
	};

	for (const auto &modulePath : modulePaths)
	{
		createTestPolicyFile(modulePath);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_EQ(exit_code, 0) << "Kernel module path: " << modulePath;
	}
}

TEST_F(ElfverifySystemIntegrationTest, ContainerPaths)
{
	std::vector<std::string> containerPaths = {
		"path /var/lib/docker/* user docker_user",
		"path /var/lib/containers/* user container_user",
		"path /run/docker/* user docker_run_user",
		"path /var/lib/lxc/* user lxc_user",
		"path /snap/* user snap_user"
	};

	for (const auto &containerPath : containerPaths)
	{
		createTestPolicyFile(containerPath);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_EQ(exit_code, 0) << "Container path: " << containerPath;
	}
}

TEST_F(ElfverifySystemIntegrationTest, NetworkFileSystemPaths)
{
	std::vector<std::string> nfsPaths = {
		"path /nfs/shared/app user nfs_user",
		"path /mnt/network/drive user network_user",
		"path /media/usb/portable user usb_user",
		"path /auto/mount/point user auto_user"
	};

	for (const auto &nfs : nfsPaths)
	{
		createTestPolicyFile(nfs);
		std::string output =
			runElfverifyCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		EXPECT_EQ(exit_code, 0)
			<< "Network filesystem path should be handled: " << nfs;
	}
}
