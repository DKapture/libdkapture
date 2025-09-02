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

extern int frtp_init(int argc, char **argv, FILE *output, int64_t timeout = 50);

// 测试常量定义
const std::string TEST_ROOT = "/tmp/frtp_test_dir";
const std::string TEST_POLICY_FILE = TEST_ROOT + "/frtp_test.pol";

class FrtpBasicTest : public ::testing::Test
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

	// 执行frtp命令并返回输出
	std::string runFrtpCommand(const std::vector<std::string> &args)
	{
		int argc = args.size() + 1;
		char *argv[argc];
		argv[0] = (char *)"frtp";
		for (int i = 1; i < argc; i++)
		{
			argv[i] = (char *)args[i - 1].c_str();
		}

		FILE *temp_file = tmpfile();
		last_exit_code = frtp_init(argc, argv, temp_file);
		std::string result(ftell(temp_file), '\0');
		rewind(temp_file);
		fread(&result[0], result.capacity(), 1, temp_file);
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
int FrtpBasicTest::last_exit_code = 0;

// 测试--policy-file选项
TEST_F(FrtpBasicTest, PolicyFileOption)
{
	// 创建一个有效的测试策略文件
	std::string policy_content = "# Test policy file\n"
								 "forbid proc=/usr/bin/cat rw /etc/passwd\n"
								 "forbid pid=1234 r /root/secret\n";
	createTestPolicyFile(policy_content);

	// 测试使用--policy-file指定策略文件
	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();
	EXPECT_EQ(exit_code, 0) << "Policy file should be loaded successfully";
}

// 测试无效参数处理
TEST_F(FrtpBasicTest, InvalidOptions)
{
	// 测试无效的长选项
	std::string output1 = runFrtpCommand({"--invalid-option"});
	int exit_code1 = getLastExitCode();

	// 无效选项应该导致非零退出码
	EXPECT_NE(exit_code1, 0) << "Invalid option should result in non-zero exit "
								"code";

	// 测试无效的短选项
	std::string output2 = runFrtpCommand({"-x"});
	int exit_code2 = getLastExitCode();

	// 无效选项应该导致非零退出码
	EXPECT_NE(exit_code2, 0) << "Invalid short option should result in "
								"non-zero exit code";

	// 测试--policy-file缺少参数
	std::string output3 = runFrtpCommand({"--policy-file"});
	int exit_code3 = getLastExitCode();

	// 缺少必需参数应该导致非零退出码
	EXPECT_NE(exit_code3, 0) << "Missing required argument should result in "
								"non-zero exit code";
}

// 测试有效策略文件
TEST_F(FrtpBasicTest, ValidPolicyFile)
{
	// 创建一个格式正确的策略文件
	std::string valid_policy = "# Valid policy file\n"
							   "forbid proc=/usr/bin/cat rw /etc/passwd\n"
							   "forbid proc=/usr/bin/vim w /etc/shadow\n"
							   "forbid pid=1234 r /root/secret\n";
	createTestPolicyFile(valid_policy);

	// 运行frtp并验证它尝试处理策略文件
	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	EXPECT_EQ(exit_code, 0) << "Expected success";
}

// 测试不存在的策略文件
TEST_F(FrtpBasicTest, NonexistentPolicyFile)
{
	// 使用一个不存在的策略文件路径
	std::string nonexistent_file = "/tmp/nonexistent_policy.pol";

	// 确保文件不存在
	unlink(nonexistent_file.c_str());

	std::string output = runFrtpCommand({"--policy-file", nonexistent_file});
	int exit_code = getLastExitCode();

	// 应该返回错误退出码
	EXPECT_NE(exit_code, 0) << "Nonexistent policy file should cause error";

	// 输出应该包含错误信息（可能在BPF阶段失败，或者在文件访问阶段失败）
	EXPECT_FALSE(output.empty()) << "Should produce error output";
}

// 测试格式错误的策略文件
TEST_F(FrtpBasicTest, InvalidPolicyFile)
{
	// 创建一个格式错误的策略文件
	std::string invalid_policy = "# Invalid policy file\n"
								 "invalid line format\n"
								 "forbid invalid syntax here\n"
								 "not a valid policy line at all\n";
	createTestPolicyFile(invalid_policy);

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	EXPECT_EQ(exit_code, 0) << "Expected success";
}

// 测试各种退出码
TEST_F(FrtpBasicTest, ExitCodes)
{
	// 测试help命令的退出码（应该是0）
	runFrtpCommand({"--help"});
	EXPECT_EQ(getLastExitCode(), 0) << "Help should exit with code 0";

	// 测试无效参数的退出码
	runFrtpCommand({"--invalid-option"});
	EXPECT_NE(getLastExitCode(), 0) << "Invalid option should exit with "
									   "non-zero code";
}

// ========== 扩展功能测试类定义 ==========

// 策略规则结构体
struct PolicyRule
{
	std::string type;		// "proc" or "pid"
	std::string identifier; // process path or PID
	std::string action;		// "r", "w", "rw"
	std::string target;		// target path

	PolicyRule(
		const std::string &t,
		const std::string &i,
		const std::string &a,
		const std::string &tgt
	) :
		type(t),
		identifier(i), action(a), target(tgt)
	{
	}
};

// 基础测试类，包含扩展的辅助函数
class FrtpExtendedTest : public FrtpBasicTest
{
  protected:
	// 策略生成工具
	std::string generatePolicyRule(
		const std::string &type,
		const std::string &identifier,
		const std::string &action,
		const std::string &target
	)
	{
		return "forbid " + type + "=" + identifier + " " + action + " " +
			   target + "\n";
	}

	std::string createMultiRulePolicy(const std::vector<PolicyRule> &rules)
	{
		std::string policy = "# Generated multi-rule policy file\n";
		for (const auto &rule : rules)
		{
			policy += generatePolicyRule(
				rule.type,
				rule.identifier,
				rule.action,
				rule.target
			);
		}
		return policy;
	}

	// 文件系统工具
	void createTestFileStructure(const std::vector<std::string> &paths)
	{
		for (const auto &path : paths)
		{
			std::string dir = path.substr(0, path.find_last_of('/'));
			if (!dir.empty())
			{
				system(("mkdir -p " + dir).c_str());
			}
			std::ofstream file(path);
			file << "test content for " << path << std::endl;
			file.close();
		}
	}

	// 输出分析工具
	bool containsAllKeywords(
		const std::string &output,
		const std::vector<std::string> &keywords
	)
	{
		for (const auto &keyword : keywords)
		{
			if (output.find(keyword) == std::string::npos)
			{
				return false;
			}
		}
		return true;
	}

	std::vector<std::string> extractErrorMessages(const std::string &output)
	{
		std::vector<std::string> errors;
		std::istringstream stream(output);
		std::string line;
		while (std::getline(stream, line))
		{
			if (line.find("error") != std::string::npos ||
				line.find("Error") != std::string::npos ||
				line.find("ERROR") != std::string::npos ||
				line.find("unrecognized") != std::string::npos ||
				line.find("invalid") != std::string::npos ||
				line.find("Invalid") != std::string::npos)
			{
				errors.push_back(line);
			}
		}
		return errors;
	}

	bool
	validateOutputFormat(const std::string &output, const std::string &pattern)
	{
		// 简单的模式匹配，检查输出是否包含预期的格式元素
		return output.find(pattern) != std::string::npos;
	}

	// 测试数据生成
	std::vector<std::string> generateTestPaths()
	{
		return {
			TEST_ROOT + "/test_file.txt",
			TEST_ROOT + "/test_dir1/nested_file.txt",
			TEST_ROOT + "/test_dir2/nested_file.txt",
			TEST_ROOT + "/special-chars@file.txt",
			TEST_ROOT + "/file with spaces.txt",
			TEST_ROOT + "/test_dir2/very/deeply/nested/directory/file.txt",
			TEST_ROOT + "/test_dir3/nested_file.txt",
			TEST_ROOT + "/test_dir4/nested_file.txt",
			TEST_ROOT + "/test_dir5/nested_file.txt",
			TEST_ROOT + "/test_dir6/nested_file.txt",
			TEST_ROOT + "/test_dir3/subdir1/nested_file.txt",
			TEST_ROOT + "/test_dir3/subdir2/nested_file.txt",
			TEST_ROOT + "/test_dir3/subdir3/nested_file.txt",
			TEST_ROOT + "/test_dir3/subdir3/subdir/nested_file.txt",
		};
	}

	std::vector<PolicyRule> generateSampleRules()
	{
		return {
			PolicyRule(
				"proc",
				"/usr/bin/cat",
				"r",
				TEST_ROOT + "/test_file.txt"
			),
			PolicyRule(
				"proc",
				"/usr/bin/tee",
				"w",
				TEST_ROOT + "/test_file.txt"
			),
			PolicyRule("pid", "1234", "rw", TEST_ROOT + "/test_file.txt"),
			PolicyRule("proc", "/bin/*", "r", TEST_ROOT + "/test_dir2/*"),
			PolicyRule(
				"proc",
				"/usr/bin/truncate",
				"w",
				TEST_ROOT + "/test_file.txt"
			)
		};
	}
};

// 策略格式测试类
class FrtpPolicyFormatTest : public FrtpExtendedTest
{
};

// 路径处理测试类
class FrtpPathHandlingTest : public FrtpExtendedTest
{
};

// 错误处理测试类
class FrtpErrorHandlingTest : public FrtpExtendedTest
{
};

// 输出验证测试类
class FrtpOutputValidationTest : public FrtpExtendedTest
{
};

// 边界条件测试类
class FrtpBoundaryTest : public FrtpExtendedTest
{
};

// ========== 策略格式测试用例 ==========

// 测试各种有效的proc规则
TEST_F(FrtpPolicyFormatTest, ValidProcRules)
{
	std::vector<PolicyRule> validRules = {
		PolicyRule("proc", "/usr/bin/cat", "r", "/etc/passwd"),
		PolicyRule("proc", "/usr/bin/vim", "w", "/etc/hosts"),
		PolicyRule("proc", "/usr/bin/grep", "rw", "/tmp/test.txt"),
		PolicyRule("proc", "/bin/sh", "r", "/root/script.sh"),
		PolicyRule("proc", "/usr/local/bin/app", "w", "/var/log/app.log")
	};

	for (const auto &rule : validRules)
	{
		std::string policy = generatePolicyRule(
			rule.type,
			rule.identifier,
			rule.action,
			rule.target
		);
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 应该能够解析规则
		EXPECT_EQ(exit_code, 0)
			<< "Valid proc rule should be loaded successfully: " << policy;
	}
}

// 测试各种有效的PID规则
TEST_F(FrtpPolicyFormatTest, ValidPidRules)
{
	std::vector<PolicyRule> validPidRules = {
		PolicyRule("pid", "1", "r", "/etc/passwd"),
		PolicyRule("pid", "1234", "w", "/tmp/test.txt"),
		PolicyRule("pid", "65535", "rw", "/var/log/test.log"),
		PolicyRule("pid", "99999", "r", "/home/user/file.txt")
	};

	for (const auto &rule : validPidRules)
	{
		std::string policy = generatePolicyRule(
			rule.type,
			rule.identifier,
			rule.action,
			rule.target
		);
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0)
			<< "Valid PID rule should be loaded successfully: " << policy;
	}
}

// 测试动作组合
TEST_F(FrtpPolicyFormatTest, ActionCombinations)
{
	std::vector<std::string> actions = {"r", "w", "rw"};

	for (const auto &action : actions)
	{
		PolicyRule rule("proc", "/usr/bin/test", action, "/tmp/test.txt");
		std::string policy = generatePolicyRule(
			rule.type,
			rule.identifier,
			rule.action,
			rule.target
		);
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_EQ(exit_code, 0) << "Action '" << action << "' should be valid";
	}
}

// 测试无效的type格式
TEST_F(FrtpPolicyFormatTest, InvalidTypeFormats)
{
	std::vector<std::string> invalidTypes = {
		"process",
		"process_id",
		"executable",
		"binary",
		"program",
		"user",
		"group"
	};

	for (const auto &type : invalidTypes)
	{
		std::string policy =
			generatePolicyRule(type, "/usr/bin/cat", "r", "/etc/passwd");
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 无效type会被忽略，且有相应的调试信息
		EXPECT_NE(output.find("Invalid type: " + type), std::string::npos)
			<< "Invalid type '" << type << "' should be ignored";
		EXPECT_EQ(exit_code, 0) << "Invalid type would not cause error";
	}
}

// 测试无效的标识符格式
TEST_F(FrtpPolicyFormatTest, InvalidIdentifierFormats)
{
	// 测试proc类型的无效标识符
	std::vector<std::string> invalidProcIdentifiers =
		{"not-a-path", "relative/path", "path/without/leading/slash"};

	for (const auto &identifier : invalidProcIdentifiers)
	{
		std::string policy =
			generatePolicyRule("proc", identifier, "r", "/etc/passwd");
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_NE(
			output.find("Invalid process path: " + identifier),
			std::string::npos
		) << "Invalid process path should be ignored: '"
		  << identifier << "'";
		EXPECT_EQ(exit_code, 0) << "Invalid proc identifier should be ignored: "
								   "'"
								<< identifier << "'";
	}

	// 测试pid类型的无效标识符
	std::vector<std::string> invalidPidIdentifiers =
		{"-1", "abc", "12.34", "0x123"};

	for (const auto &identifier : invalidPidIdentifiers)
	{
		std::string policy =
			generatePolicyRule("pid", identifier, "r", "/etc/passwd");
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_NE(output.find("Invalid PID: " + identifier), std::string::npos)
			<< "Invalid PID should be ignored: '" << identifier << "'";
		EXPECT_EQ(exit_code, 0) << "Invalid PID identifier should be ignored: "
								   "'"
								<< identifier << "'";
	}
}

// 测试无效的动作格式
TEST_F(FrtpPolicyFormatTest, InvalidActionFormats)
{
	std::vector<std::string> invalidActions =
		{"x", "e", "exec", "read", "write", "rwe", "wr", "R", "W", "RW", "rwx"};

	for (const auto &action : invalidActions)
	{
		std::string policy =
			generatePolicyRule("proc", "/usr/bin/cat", action, "/etc/passwd");
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_NE(output.find("Invalid action: " + action), std::string::npos)
			<< "Invalid action '" << action << "' should be ignored";
		EXPECT_EQ(exit_code, 0) << "Invalid action would not cause error";
	}
}

// 测试空格和制表符处理
TEST_F(FrtpPolicyFormatTest, WhitespaceHandling)
{
	std::vector<std::string> policies = {
		"forbid proc=/usr/bin/cat r /etc/passwd\n",	   // 正常空格
		"forbid  proc=/usr/bin/cat  r  /etc/passwd\n", // 多个空格
		"forbid\tproc=/usr/bin/cat\tr\t/etc/passwd\n", // 制表符
		" forbid proc=/usr/bin/cat r /etc/passwd\n",   // 行首空格
		"forbid proc=/usr/bin/cat r /etc/passwd \n"	   // 行尾空格
	};

	for (const auto &policy : policies)
	{
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 应该能处理各种空格格式
		EXPECT_EQ(exit_code, 0)
			<< "Should handle whitespace correctly in: " << policy;
	}
}

// 测试注释行处理
TEST_F(FrtpPolicyFormatTest, CommentHandling)
{
	std::string policy = "# This is a comment line\n"
						 "# Another comment\n"
						 "forbid proc=/usr/bin/cat r /etc/passwd\n"
						 "# Comment after rule\n"
						 "forbid pid=1234 w /tmp/test.txt\n"
						 "## Double hash comment\n"
						 "#forbid proc=/usr/bin/vim r /etc/hosts  # This "
						 "should be ignored\n";

	createTestPolicyFile(policy);

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 应该正确处理注释行，只解析非注释规则
	EXPECT_EQ(
		output.find("Rule (process): proc /usr/bin/vim r /etc/hosts"),
		std::string::npos
	) << "Should parse comment lines";
	EXPECT_EQ(exit_code, 0) << "Should correctly handle comment lines";
}

// 测试空行处理
TEST_F(FrtpPolicyFormatTest, EmptyLineHandling)
{
	std::string policy = "\n"
						 "forbid proc=/usr/bin/cat r /etc/passwd\n"
						 "\n"
						 "\n"
						 "forbid pid=1234 w /tmp/test.txt\n"
						 "\n"
						 "   \n" // 只有空格的行
						 "\t\n"	 // 只有制表符的行
						 "forbid proc=/usr/bin/vim rw /etc/hosts\n"
						 "\n";

	createTestPolicyFile(policy);

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 应该正确处理空行
	EXPECT_EQ(exit_code, 0) << "Should correctly handle empty lines";
}

// 测试混合有效无效规则
TEST_F(FrtpPolicyFormatTest, MixedValidInvalidRules)
{
	createTestDirectory("MixedValidInvalidRules");
	createTestFile("MixedValidInvalidRules/test.txt", "test data content\n");
	std::string policy = "# Mixed valid and invalid rules\n"
						 "forbid proc=/usr/bin/cat r " +
						 TEST_ROOT +
						 "/MixedValidInvalidRules/test.txt\n" // valid
						 "invalid line format here\n"		  // invalid
						 "forbid pid=1234 w " +
						 TEST_ROOT +
						 "/MixedValidInvalidRules/test.txt\n" // valid
						 "forbid invalid_type=something r " +
						 TEST_ROOT +
						 "/test.txt\n" // invalid
						 "forbid proc=/usr/bin/vim invalid_action " +
						 TEST_ROOT +
						 "/MixedValidInvalidRules/test.txt\n" // invalid
						 "forbid proc=/usr/bin/grep rw " +
						 TEST_ROOT +
						 "/MixedValidInvalidRules/test.txt\n"; // valid

	createTestPolicyFile(policy);

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 程序应该跳过无效行，处理有效行
	EXPECT_NE(
		output.find(
			"Rule (regular file): proc /usr/bin/cat r " + TEST_ROOT +
			"/MixedValidInvalidRules/test.txt"
		),
		std::string::npos
	) << "Should parse valid proc rule";
	EXPECT_NE(
		output.find("Invalid line: invalid line format here"),
		std::string::npos
	) << "Should parse invalid line";
	EXPECT_NE(
		output.find(
			"Rule (regular file): pid 1234 w " + TEST_ROOT +
			"/MixedValidInvalidRules/test.txt"
		),
		std::string::npos
	) << "Should parse valid pid rule";
	EXPECT_NE(output.find("Invalid type: invalid_type"), std::string::npos)
		<< "Should parse invalid type";
	EXPECT_NE(output.find("Invalid action: invalid_action"), std::string::npos)
		<< "Should parse invalid action";
	EXPECT_NE(
		output.find(
			"Rule (regular file): proc /usr/bin/grep rw " + TEST_ROOT +
			"/MixedValidInvalidRules/test.txt"
		),
		std::string::npos
	) << "Should parse valid proc rule";
	EXPECT_EQ(exit_code, 0) << "Should handle mixed valid/invalid rules";
}

// ========== 路径处理测试用例 ==========

// 测试绝对路径处理
TEST_F(FrtpPathHandlingTest, AbsolutePaths)
{
	createTestDirectory("AbsolutePaths");
	std::vector<std::string> absolutePaths = {
		"passwd",
		"cat",
		"messages",
		"document.txt",
		"temporary_file.tmp",
		"config.conf",
		".bashrc"
	};

	for (const auto &path : absolutePaths)
	{
		createTestFile("AbsolutePaths/" + path, "test file");
		PolicyRule rule(
			"proc",
			"/usr/bin/cat",
			"r",
			TEST_ROOT + "/AbsolutePaths/" + path
		);
		std::string policy = generatePolicyRule(
			rule.type,
			rule.identifier,
			rule.action,
			rule.target
		);
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 绝对路径应该被正确处理
		EXPECT_EQ(exit_code, 0) << "Should handle absolute path: " << path;
	}
}

// 测试相对路径处理
TEST_F(FrtpPathHandlingTest, RelativePaths)
{
	std::vector<std::string> relativePaths = {
		"file.txt",
		"./file.txt",
		"../parent_file.txt",
		"subdir/file.txt",
		"./subdir/../file.txt",
		"../../grandparent.txt"
	};

	for (const auto &path : relativePaths)
	{
		PolicyRule rule("proc", "/usr/bin/cat", "r", path);
		std::string policy = generatePolicyRule(
			rule.type,
			rule.identifier,
			rule.action,
			rule.target
		);
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		// 相对路径会导致错误，因为frtp要求绝对路径
		EXPECT_NE(
			output.find("Invalid target path: " + path),
			std::string::npos
		) << "Relative path not supported: "
		  << path;
		EXPECT_EQ(exit_code, 0)
			<< "Invalid path would not cause error: " << exit_code;
	}
}

// 测试通配符路径
TEST_F(FrtpPathHandlingTest, WildcardPaths)
{
	// 先创建测试文件结构
	createTestFileStructure(generateTestPaths());

	std::vector<std::string> wildcardPaths = {
		TEST_ROOT + "/test_dir1",
		TEST_ROOT + "/test_dir2",
		TEST_ROOT + "/test_dir3",
		TEST_ROOT + "/test_dir5"
	};

	for (const auto &path : wildcardPaths)
	{
		PolicyRule rule("proc", "/usr/bin/cat", "r", path + "/*");
		std::string policy = generatePolicyRule(
			rule.type,
			rule.identifier,
			rule.action,
			rule.target
		);
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();
		// 通配符路径应该被支持
		EXPECT_NE(output.find(path), std::string::npos)
			<< "Should support wildcard path: " << path;
		EXPECT_EQ(exit_code, 0)
			<< "Wildcard paths should not cause error: " << exit_code;
	}
}

// 测试目录路径（带/结尾）
TEST_F(FrtpPathHandlingTest, DirectoryPaths)
{
	createTestFileStructure(generateTestPaths());
	std::vector<std::string> directoryPaths = {
		TEST_ROOT + "/test_dir1",
		TEST_ROOT + "/test_dir2",
		TEST_ROOT + "/test_dir3/subdir1",
		TEST_ROOT + "/test_dir4",
	};

	for (const auto &path : directoryPaths)
	{
		PolicyRule rule("proc", "/usr/bin/cat", "r", path + '/');
		std::string policy = generatePolicyRule(
			rule.type,
			rule.identifier,
			rule.action,
			rule.target
		);
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 目录路径应该被支持
		EXPECT_NE(output.find("Rule (diretory)"), std::string::npos)
			<< "Should support directory path: " << path;
		EXPECT_NE(output.find(path), std::string::npos)
			<< "Should support directory path: " << path;
		EXPECT_EQ(exit_code, 0)
			<< "Directory paths should not cause error: " << exit_code;
	}
}

// 测试递归目录（/*）
TEST_F(FrtpPathHandlingTest, RecursiveDirectories)
{
	createTestFileStructure(generateTestPaths());
	std::vector<std::string> recursivePaths = {
		TEST_ROOT + "/test_dir1",
		TEST_ROOT + "/test_dir2",
		TEST_ROOT + "/test_dir3",
	};

	for (const auto &path : recursivePaths)
	{
		PolicyRule rule("proc", "/usr/bin/cat", "rw", path + "/*");
		std::string policy = generatePolicyRule(
			rule.type,
			rule.identifier,
			rule.action,
			rule.target
		);
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 递归目录应该被支持
		EXPECT_NE(output.find("Rule (diretory)"), std::string::npos)
			<< "Should support recursive directory: " << path;
		EXPECT_NE(output.find(path), std::string::npos)
			<< "Should support recursive directory: " << path;
		EXPECT_EQ(exit_code, 0)
			<< "Recursive directories should not cause error: " << exit_code;
	}
}

// 测试特殊字符路径
TEST_F(FrtpPathHandlingTest, SpecialCharacterPaths)
{
	std::vector<std::string> specialPaths = {
		TEST_ROOT + "/file-with-dashes.txt",
		TEST_ROOT + "/file_with_underscores.txt",
		TEST_ROOT + "/file.with.dots.txt",
		TEST_ROOT + "/file@with@at.txt",
		TEST_ROOT + "/file#with#hash.txt",
		TEST_ROOT + "/file$with$dollar.txt"
	};

	// 创建这些测试文件
	createTestFileStructure(specialPaths);

	for (const auto &path : specialPaths)
	{
		PolicyRule rule("proc", "/usr/bin/cat", "r", path);
		std::string policy = generatePolicyRule(
			rule.type,
			rule.identifier,
			rule.action,
			rule.target
		);
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 特殊字符路径应该被正确处理
		EXPECT_NE(output.find("Rule (regular file)"), std::string::npos)
			<< "Should handle special characters in path: " << path;
		EXPECT_NE(output.find(path), std::string::npos)
			<< "Should handle special characters in path: " << path;
		EXPECT_EQ(exit_code, 0) << "Special characters in paths should not "
								   "cause error: "
								<< exit_code;
	}
}

// 测试不存在的路径
TEST_F(FrtpPathHandlingTest, NonexistentPaths)
{
	std::vector<std::string> nonexistentPaths = {
		"/nonexistent/path/file.txt",
		"/tmp/does_not_exist.txt",
		"/var/fake_directory/file.log",
		"/home/fake_user/document.txt",
		"/usr/bin/nonexistent_binary"
	};

	for (const auto &path : nonexistentPaths)
	{
		PolicyRule rule("proc", "/usr/bin/test", "r", TEST_ROOT + path);
		std::string policy = generatePolicyRule(
			rule.type,
			rule.identifier,
			rule.action,
			rule.target
		);
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 不存在的路径应该正确处理
		EXPECT_NE(
			output.find("Cannot access path " + TEST_ROOT + path),
			std::string::npos
		) << "Nonexistent path";
		EXPECT_EQ(exit_code, 0)
			<< "Nonexiesent paths should not cause error: " << path;
	}
}

// 测试权限被拒绝的路径
TEST_F(FrtpPathHandlingTest, PermissionDeniedPaths)
{
	std::vector<std::string> restrictedPaths = {
		TEST_ROOT + "/root/secret_file.txt",	  // 通常用户无权访问
		TEST_ROOT + "/etc/shadow",				  // 系统敏感文件
		TEST_ROOT + "/proc/1/mem",				  // 内核内存文件
		TEST_ROOT + "/sys/kernel/debug/something" // 调试文件系统
	};

	for (const auto &path : restrictedPaths)
	{
		PolicyRule rule("proc", "/usr/bin/cat", "r", path);
		std::string policy = generatePolicyRule(
			rule.type,
			rule.identifier,
			rule.action,
			rule.target
		);
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 权限受限的路径应该可以正常处理
		EXPECT_EQ(exit_code, 0)
			<< "Permission denied path might cause error: " << path;
	}
}

// 测试符号链接处理
TEST_F(FrtpPathHandlingTest, SymbolicLinks)
{
	// 创建测试文件和符号链接
	std::string targetFile = TEST_ROOT + "/frtp_test_target.txt";
	std::string linkFile = TEST_ROOT + "/frtp_test_link.txt";

	// 创建目标文件
	createTestFileStructure({targetFile});

	// 创建符号链接
	system(("ln -sf " + targetFile + " " + linkFile).c_str());

	// 测试指向符号链接的规则
	PolicyRule rule("proc", "/usr/bin/cat", "r", linkFile);
	std::string policy = generatePolicyRule(
		rule.type,
		rule.identifier,
		rule.action,
		rule.target
	);
	createTestPolicyFile(policy);

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 符号链接应该被正确处理
	EXPECT_EQ(exit_code, 0) << "Should handle symbolic links correctly";
}

// ========== 错误处理测试用例 ==========

// 测试格式错误的策略行
TEST_F(FrtpErrorHandlingTest, MalformedPolicyLines)
{
	std::vector<std::string> malformedLines = {
		"forbid",								  // 缺少所有参数
		"forbid proc=/usr/bin/cat",				  // 缺少action和target
		"forbid proc=/usr/bin/cat r",			  // 缺少target
		"proc=/usr/bin/cat r /etc/passwd",		  // 缺少forbid关键字
		"forbid proc /usr/bin/cat r /etc/passwd", // 缺少等号
		"allow proc=/usr/bin/cat r /etc/passwd",  // 错误的关键字
		"deny proc=/usr/bin/cat r /etc/passwd"	  // 错误的关键字
	};

	for (const auto &line : malformedLines)
	{
		createTestPolicyFile(line + "\n");

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 应该包含错误信息
		EXPECT_NE(output.find("Invalid line: " + line), std::string::npos)
			<< "Invalid line should have error message: " << line;
		// 格式错误的行应该正常处理
		EXPECT_EQ(exit_code, 0)
			<< "Malformed line should not cause error: " << exit_code;
	}
}

// 测试缺少字段的策略
TEST_F(FrtpErrorHandlingTest, MissingFields)
{
	std::vector<std::string> incompleteRules = {
		"forbid proc= r /etc/passwd",			 // 空的标识符
		"forbid proc=/usr/bin/cat  /etc/passwd", // 缺少动作
		"forbid =test r /etc/passwd",			 // 缺少类型
		"forbid proc=/usr/bin/cat r ",			 // 空的目标路径
		"forbid  =/usr/bin/cat r /etc/passwd"	 // 空的类型
	};

	for (const auto &rule : incompleteRules)
	{
		createTestPolicyFile(rule + "\n");

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_NE(output.find("Invalid line: " + rule), std::string::npos)
			<< "Incomplete rule should have error message: " << rule;
		EXPECT_EQ(exit_code, 0)
			<< "Incomplete rule should not cause error: " << exit_code;
	}
}

// 测试多余字段的策略
TEST_F(FrtpErrorHandlingTest, ExtraFields)
{
	createTestFileStructure(generateTestPaths());
	std::vector<std::string> rulesWithExtra = {
		"forbid proc=/usr/bin/cat r " + TEST_ROOT + "/test_file.txt" +
			" extra_field",
		"forbid proc=/usr/bin/cat r " + TEST_ROOT + "/test_file.txt" +
			" another extra",
		"forbid proc=/usr/bin/cat r " + TEST_ROOT + "/test_file.txt" +
			" # comment should be ok",
	};

	for (const auto &rule : rulesWithExtra)
	{
		createTestPolicyFile(rule + "\n");

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 多余字段应该被忽略
		EXPECT_NE(output.find("Rule (regular file)"), std::string::npos)
			<< "Extra fields of rule should be ignored: " << rule;
		EXPECT_EQ(exit_code, 0) << "Extra fields of rule with should not cause "
								   "error: "
								<< exit_code;
	}
}

// 测试无效字符处理
TEST_F(FrtpErrorHandlingTest, InvalidCharacters)
{
	createTestFileStructure(generateTestPaths());
	const std::string target_path = TEST_ROOT + "/test_file.txt";
	std::map<std::string, std::string> rulesAndResults = {
		{"forbid proc=/usr/bin/cat\0 r " + target_path,
		 "Invalid line: forbid proc=/usr/bin/cat"					 }, // 空字符
		{"forbid proc=/usr/bin/cat\n r " + target_path,
		 "Invalid line: forbid proc=/usr/bin/cat"					 }, // 换行符在中间
		{"forbid proc=/usr/bin/cat\t\t r " + target_path,
		 "Rule (regular file): proc /usr/bin/cat r " + target_path
		}, // 多个制表符
		{"forbid proc=/usr/bin/cat® r " + target_path,
		 "Rule (regular file): proc /usr/bin/cat® r " + target_path
		}, // 特殊Unicode字符
		{"forbid proc=/usr/bin/cat™ r " + target_path,
		 "Rule (regular file): proc /usr/bin/cat™ r " + target_path}	 // 商标符号
	};

	for (const auto &rule : rulesAndResults)
	{
		createTestPolicyFile(rule.first + "\n");

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 无效字符可能导致解析错误
		EXPECT_NE(output.find(rule.second), std::string::npos)
			<< "Invalid characters might not be handled due to the "
			   "expectation: "
			<< rule.first;
		EXPECT_EQ(exit_code, 0) << "Invalid characters should not cause fatal "
								   "errors: "
								<< exit_code;
	}
}

// 测试编码问题
TEST_F(FrtpErrorHandlingTest, EncodingIssues)
{
	createTestFileStructure(generateTestPaths());
	const std::string target_path = TEST_ROOT + "/test_file.txt";
	// 创建包含不同编码的策略文件
	std::vector<std::string> encodingTests = {
		"forbid proc=/usr/bin/测试程序 r " + target_path, // 中文程序名
		"forbid proc=/usr/bin/café r " + target_path, // 带重音符的程序名
		"forbid proc=/usr/bin/naïve r " + target_path // 带变音符的程序名
	};

	for (const auto &rule : encodingTests)
	{
		createTestPolicyFile(rule + "\n");

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// Unicode字符应该不会导致问题
		EXPECT_NE(output.find("Rule (regular file):"), std::string::npos)
			<< "Unicode characters should not cause issue: " << rule;
		EXPECT_EQ(exit_code, 0)
			<< "Unicode characters should not cause fatal error: " << exit_code;
	}
}

// 测试二进制策略文件
TEST_F(FrtpErrorHandlingTest, BinaryPolicyFile)
{
	// 创建包含二进制数据的文件
	std::ofstream binaryFile(TEST_POLICY_FILE, std::ios::binary);
	for (int i = 0; i < 256; i++)
	{
		binaryFile.put(static_cast<char>(i));
	}
	binaryFile.close();

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 二进制文件应该导致解析错误
	EXPECT_NE(output.find("Invalid line:"), std::string::npos)
		<< "Binary file should cause invalid line";
	EXPECT_EQ(exit_code, 0)
		<< "Binary file should not cause fatal error: " << exit_code;
}

// 测试空策略文件
TEST_F(FrtpErrorHandlingTest, EmptyPolicyFile)
{
	// 创建完全空的策略文件
	createTestPolicyFile("");

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 空策略文件也是合法的
	EXPECT_EQ(output.find("Rule"), std::string::npos)
		<< "Empty file should not contain valid rule: " << output;
	EXPECT_EQ(exit_code, 0)
		<< "Empty policy file should not cause fatal error: " << exit_code;
}

// 测试只读策略文件
TEST_F(FrtpErrorHandlingTest, ReadOnlyPolicyFile)
{
	createTestFileStructure(generateTestPaths());
	const std::string target_path = TEST_ROOT + "/test_file.txt";
	// 创建策略文件并设置为只读
	createTestPolicyFile("forbid proc=/usr/bin/cat r " + target_path);
	chmod(TEST_POLICY_FILE.c_str(), 0444); // 只读权限

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 只读文件应该可以正常读取
	EXPECT_NE(output.find("Rule"), std::string::npos) << "Read-only policy "
														 "file should be "
														 "parsed correctly";
	EXPECT_EQ(exit_code, 0) << "Read-only policy file should be readable";

	// 恢复权限以便清理
	chmod(TEST_POLICY_FILE.c_str(), 0644);
}

// 测试策略文件权限问题
TEST_F(FrtpErrorHandlingTest, PolicyFilePermissions)
{
	// 创建策略文件
	createTestPolicyFile("forbid proc=/usr/bin/cat r /etc/passwd\n");

	// 测试不同的权限设置
	std::vector<mode_t> permissions = {
		0000, // 无权限
		0200, // 只写
		0100, // 只执行
		0300, // 写+执行
		0400, // 只读
		0600, // 读+写
		0644  // 正常权限
	};

	for (mode_t perm : permissions)
	{
		chmod(TEST_POLICY_FILE.c_str(), perm);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		if (perm & 0400)
		{ // 有读权限
			EXPECT_EQ(exit_code, 0) << "Should be able to read file with "
									   "permission "
									<< std::oct << perm;
		}
		else
		{ // 无读权限
			EXPECT_NE(exit_code, 0) << "Should fail to read file without read "
									   "permission "
									<< std::oct << perm;
		}
	}

	// 恢复正常权限
	chmod(TEST_POLICY_FILE.c_str(), 0644);
}

// ========== 输出验证测试用例 ==========

// 测试详细输出验证
TEST_F(FrtpOutputValidationTest, VerboseOutputValidation)
{
	// 创建复杂的策略文件
	std::string complexPolicy = "# Complex policy for verbose output testing\n"
								"forbid proc=/usr/bin/cat r /etc/passwd\n"
								"forbid proc=/usr/bin/vim w /etc/hosts\n"
								"forbid pid=1234 rw /tmp/test.txt\n";

	createTestPolicyFile(complexPolicy);

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});

	// 应该包含策略处理的相关信息
	bool hasProcessingInfo = output.find("Rule") != std::string::npos;

	EXPECT_TRUE(hasProcessingInfo) << "Should contain policy processing "
									  "information";
}

// 测试日志消息格式
TEST_F(FrtpOutputValidationTest, LogMessageFormats)
{
	createTestPolicyFile("forbid proc=/usr/bin/cat r /etc/passwd\n");
	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});

	// 检查日志消息的结构
	std::istringstream stream(output);
	std::string line;
	bool hasProperLogFormat = false;

	while (std::getline(stream, line))
	{
		if (!line.empty() && line.find("Rule") != std::string::npos)
		{
			hasProperLogFormat = true;
			break;
		}
	}

	EXPECT_TRUE(hasProperLogFormat) << "Should have properly formatted log "
									   "messages";
}

// ========== 边界条件测试用例 ==========

// 测试Unicode字符处理
TEST_F(FrtpBoundaryTest, UnicodeCharacters)
{
	std::vector<std::string> unicodeTests = {
		"/tmp/文件.txt",	 // 中文字符
		"/tmp/файл.txt",	 // 俄文字符
		"/tmp/αρχείο.txt",	 // 希腊字符
		"/tmp/ファイル.txt", // 日文字符
		"/tmp/🚀rocket.txt", // Emoji字符
		"/tmp/café.txt",	 // 带重音符
		"/tmp/naïve.txt"	 // 带变音符
	};

	for (const auto &path : unicodeTests)
	{
		PolicyRule rule("proc", "/usr/bin/cat", "r", path);
		std::string policy = generatePolicyRule(
			rule.type,
			rule.identifier,
			rule.action,
			rule.target
		);
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// Unicode字符可能导致编码或路径问题
		EXPECT_EQ(exit_code, 0)
			<< "Unicode path might cause encoding issues: " << path;
	}
}
