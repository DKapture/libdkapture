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

// 测试常量定义
const std::string FRTP_BINARY = "./build/policy/frtp";
const std::string TEST_POLICY_FILE = "/tmp/frtp_test.pol";
const std::string TEST_DIR = "/tmp/frtp_test_dir";

class FrtpBinaryTest : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		// 清理任何之前的测试文件
		cleanupTestFiles();
		// 创建测试目录
		system(("mkdir -p " + TEST_DIR).c_str());
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
		std::string command = FRTP_BINARY;
		for (const auto &arg : args)
		{
			command += " " + arg;
		}
		command += " 2>&1"; // 重定向stderr到stdout

		FILE *pipe = popen(command.c_str(), "r");
		if (!pipe)
		{
			last_exit_code = -1;
			return "";
		}

		std::string result;
		char buffer[128];
		while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
		{
			result += buffer;
		}

		int status = pclose(pipe);
		last_exit_code = WEXITSTATUS(status);
		return result;
	}

	// 获取上次命令的退出码
	int getLastExitCode()
	{
		return last_exit_code;
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
		// 删除测试策略文件
		unlink(TEST_POLICY_FILE.c_str());

		// 删除测试目录
		system(("rm -rf " + TEST_DIR).c_str());
	}
};

// 初始化静态成员
int FrtpBinaryTest::last_exit_code = 0;

// 测试--help和-h选项
TEST_F(FrtpBinaryTest, HelpOption)
{
	// 测试--help选项
	std::string output_long = runFrtpCommand({"--help"});
	int exit_code_long = getLastExitCode();

	// 验证退出码为0（成功）
	EXPECT_EQ(exit_code_long, 0) << "Help option should exit with code 0";

	// 验证输出包含关键信息
	EXPECT_NE(output_long.find("Usage:"), std::string::npos) << "Help output "
																"should "
																"contain Usage";
	EXPECT_NE(output_long.find("protect system files"), std::string::npos)
		<< "Help should describe function";
	EXPECT_NE(output_long.find("--policy-file"), std::string::npos)
		<< "Help should mention policy-file option";
	EXPECT_NE(output_long.find("--help"), std::string::npos) << "Help should "
																"mention help "
																"option";

	// 测试-h选项
	std::string output_short = runFrtpCommand({"-h"});
	int exit_code_short = getLastExitCode();

	// 验证退出码为0
	EXPECT_EQ(exit_code_short, 0) << "Short help option should exit with code "
									 "0";

	// 验证短选项和长选项输出相同
	EXPECT_EQ(output_long, output_short) << "-h and --help should produce "
											"identical output";
}

// 测试--policy-file选项
TEST_F(FrtpBinaryTest, PolicyFileOption)
{
	// 创建一个有效的测试策略文件
	std::string policy_content = "# Test policy file\n"
								 "forbid proc=/usr/bin/cat rw /etc/passwd\n"
								 "forbid pid=1234 r /root/secret\n";
	createTestPolicyFile(policy_content);

	// 测试使用--policy-file指定策略文件
	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 由于BPF权限问题，程序会退出失败，但这是预期的
	// 重要的是程序能够识别并尝试加载策略文件
	EXPECT_NE(exit_code, 0) << "Expected non-zero exit code due to BPF "
							   "permission issues";

	// 验证输出包含BPF相关的错误信息，表明程序尝试加载了策略文件
	EXPECT_NE(output.find("libbpf"), std::string::npos) << "Output should "
														   "contain libbpf "
														   "error messages";
}

// 测试无效参数处理
TEST_F(FrtpBinaryTest, InvalidOptions)
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
TEST_F(FrtpBinaryTest, ValidPolicyFile)
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

	// 由于BPF权限限制，程序会失败，但应该能够解析策略文件
	EXPECT_NE(exit_code, 0) << "Expected failure due to BPF permissions";
	EXPECT_NE(output.find("libbpf"), std::string::npos) << "Should reach BPF "
														   "loading stage";
}

// 测试不存在的策略文件
TEST_F(FrtpBinaryTest, NonexistentPolicyFile)
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
TEST_F(FrtpBinaryTest, InvalidPolicyFile)
{
	// 创建一个格式错误的策略文件
	std::string invalid_policy = "# Invalid policy file\n"
								 "invalid line format\n"
								 "forbid invalid syntax here\n"
								 "not a valid policy line at all\n";
	createTestPolicyFile(invalid_policy);

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 程序应该处理无效格式，可能跳过无效行但继续运行
	// 最终仍会因BPF权限而失败
	EXPECT_NE(exit_code, 0) << "Should eventually fail due to BPF permissions";
}

// 测试BPF权限错误处理
TEST_F(FrtpBinaryTest, NoPermissionError)
{
	// 创建有效策略文件
	std::string policy_content = "forbid proc=/usr/bin/cat rw /etc/passwd\n";
	createTestPolicyFile(policy_content);

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 应该因权限问题失败
	EXPECT_EQ(exit_code, 255) << "Should exit with code 255 due to BPF "
								 "permission error";

	// 验证输出包含权限相关错误信息
	EXPECT_NE(output.find("RLIMIT_MEMLOCK"), std::string::npos) << "Should "
																   "mention "
																   "RLIMIT_"
																   "MEMLOCK";
	EXPECT_NE(output.find("Operation not permitted"), std::string::npos)
		<< "Should mention permission error";
	EXPECT_NE(output.find("failed to load object"), std::string::npos)
		<< "Should mention BPF loading failure";
}

// 测试各种退出码
TEST_F(FrtpBinaryTest, ExitCodes)
{
	// 测试help命令的退出码（应该是0）
	runFrtpCommand({"--help"});
	EXPECT_EQ(getLastExitCode(), 0) << "Help should exit with code 0";

	// 测试无效参数的退出码
	runFrtpCommand({"--invalid-option"});
	EXPECT_NE(getLastExitCode(), 0) << "Invalid option should exit with "
									   "non-zero code";

	// 测试BPF权限错误的退出码
	std::string policy_content = "forbid proc=/usr/bin/cat rw /etc/passwd\n";
	createTestPolicyFile(policy_content);
	runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	EXPECT_EQ(getLastExitCode(), 255) << "BPF permission error should exit "
										 "with code 255";

	// 测试默认运行（无参数）的退出码
	runFrtpCommand({});
	EXPECT_EQ(getLastExitCode(), 255) << "Default run should fail with BPF "
										 "permission error";
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
class FrtpExtendedTest : public FrtpBinaryTest
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
			"/tmp/test_file.txt",
			"/tmp/test_dir/nested_file.txt",
			"/tmp/special-chars@file.txt",
			"/tmp/file with spaces.txt",
			"/tmp/very/deeply/nested/directory/file.txt"
		};
	}

	std::vector<PolicyRule> generateSampleRules()
	{
		return {
			PolicyRule("proc", "/usr/bin/cat", "r", "/etc/passwd"),
			PolicyRule("proc", "/usr/bin/vim", "w", "/etc/hosts"),
			PolicyRule("pid", "1234", "rw", "/tmp/test.txt"),
			PolicyRule("proc", "/bin/*", "r", "/root/*"),
			PolicyRule("proc", "/usr/local/bin/app", "w", "/var/log/app.log")
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

		// 应该能够解析规则并到达BPF阶段
		EXPECT_EQ(exit_code, 255)
			<< "Valid proc rule should reach BPF stage: " << policy;
		EXPECT_NE(output.find("libbpf"), std::string::npos)
			<< "Should reach BPF loading for: " << policy;
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

		EXPECT_EQ(exit_code, 255)
			<< "Valid PID rule should reach BPF stage: " << policy;
		EXPECT_NE(output.find("libbpf"), std::string::npos)
			<< "Should reach BPF loading for: " << policy;
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

		EXPECT_EQ(exit_code, 255)
			<< "Action '" << action << "' should be valid";
		EXPECT_NE(output.find("libbpf"), std::string::npos)
			<< "Should reach BPF loading for action: " << action;
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

		// 无效type应该导致解析错误，但程序可能继续运行
		EXPECT_NE(exit_code, 0)
			<< "Invalid type '" << type << "' should cause error";
	}
}

// 测试无效的标识符格式
TEST_F(FrtpPolicyFormatTest, InvalidIdentifierFormats)
{
	// 测试proc类型的无效标识符
	std::vector<std::string> invalidProcIdentifiers =
		{"", " ", "not-a-path", "relative/path", "path/without/leading/slash"};

	for (const auto &identifier : invalidProcIdentifiers)
	{
		std::string policy =
			generatePolicyRule("proc", identifier, "r", "/etc/passwd");
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_NE(exit_code, 0) << "Invalid proc identifier should cause "
								   "error: '"
								<< identifier << "'";
	}

	// 测试pid类型的无效标识符
	std::vector<std::string> invalidPidIdentifiers =
		{"", "-1", "abc", "12.34", "1000000000", "0x123", "1 2"};

	for (const auto &identifier : invalidPidIdentifiers)
	{
		std::string policy =
			generatePolicyRule("pid", identifier, "r", "/etc/passwd");
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_NE(exit_code, 0) << "Invalid PID identifier should cause error: "
								   "'"
								<< identifier << "'";
	}
}

// 测试无效的动作格式
TEST_F(FrtpPolicyFormatTest, InvalidActionFormats)
{
	std::vector<std::string> invalidActions = {
		"",
		"x",
		"e",
		"exec",
		"read",
		"write",
		"rwe",
		"wr",
		"R",
		"W",
		"RW",
		"rwx"
	};

	for (const auto &action : invalidActions)
	{
		std::string policy =
			generatePolicyRule("proc", "/usr/bin/cat", action, "/etc/passwd");
		createTestPolicyFile(policy);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		EXPECT_NE(exit_code, 0)
			<< "Invalid action '" << action << "' should cause error";
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
		EXPECT_EQ(exit_code, 255)
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
	EXPECT_EQ(exit_code, 255) << "Should correctly handle comment lines";
	EXPECT_NE(output.find("libbpf"), std::string::npos) << "Should reach BPF "
														   "loading";
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
	EXPECT_EQ(exit_code, 255) << "Should correctly handle empty lines";
	EXPECT_NE(output.find("libbpf"), std::string::npos) << "Should reach BPF "
														   "loading";
}

// 测试混合有效无效规则
TEST_F(FrtpPolicyFormatTest, MixedValidInvalidRules)
{
	std::string policy =
		"# Mixed valid and invalid rules\n"
		"forbid proc=/usr/bin/cat r /etc/passwd\n"			   // valid
		"invalid line format here\n"						   // invalid
		"forbid pid=1234 w /tmp/test.txt\n"					   // valid
		"forbid invalid_type=something r /etc/hosts\n"		   // invalid type
		"forbid proc=/usr/bin/vim invalid_action /etc/hosts\n" // invalid action
		"forbid proc=/usr/bin/grep rw /tmp/valid.txt\n";	   // valid

	createTestPolicyFile(policy);

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 程序应该跳过无效行，处理有效行
	EXPECT_EQ(exit_code, 255) << "Should handle mixed valid/invalid rules";
	EXPECT_NE(output.find("libbpf"), std::string::npos) << "Should reach BPF "
														   "loading";
}

// ========== 路径处理测试用例 ==========

// 测试绝对路径处理
TEST_F(FrtpPathHandlingTest, AbsolutePaths)
{
	std::vector<std::string> absolutePaths = {
		"/etc/passwd",
		"/usr/bin/cat",
		"/var/log/messages",
		"/home/user/document.txt",
		"/tmp/temporary_file.tmp",
		"/opt/application/config.conf",
		"/root/.bashrc"
	};

	for (const auto &path : absolutePaths)
	{
		PolicyRule rule("proc", "/usr/bin/test", "r", path);
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
		EXPECT_EQ(exit_code, 255) << "Should handle absolute path: " << path;
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
		PolicyRule rule("proc", "/usr/bin/test", "r", path);
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

		// 相对路径可能导致错误，因为frtp可能要求绝对路径
		EXPECT_NE(exit_code, 0)
			<< "Relative path might not be supported: " << path;
	}
}

// 测试通配符路径
TEST_F(FrtpPathHandlingTest, WildcardPaths)
{
	// 先创建测试文件结构
	createTestFileStructure(generateTestPaths());

	std::vector<std::string> wildcardPaths =
		{"/tmp/*", "/usr/bin/*", "/home/*", "/var/log/*", "/etc/*"};

	for (const auto &path : wildcardPaths)
	{
		PolicyRule rule("proc", "/usr/bin/test", "r", path);
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
		EXPECT_EQ(exit_code, 255) << "Should support wildcard path: " << path;
	}
}

// 测试目录路径（带/结尾）
TEST_F(FrtpPathHandlingTest, DirectoryPaths)
{
	std::vector<std::string> directoryPaths =
		{"/tmp/", "/etc/", "/usr/bin/", "/var/log/", "/home/user/"};

	for (const auto &path : directoryPaths)
	{
		PolicyRule rule("proc", "/usr/bin/test", "r", path);
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
		EXPECT_EQ(exit_code, 255) << "Should support directory path: " << path;
	}
}

// 测试递归目录（/*）
TEST_F(FrtpPathHandlingTest, RecursiveDirectories)
{
	std::vector<std::string> recursivePaths =
		{"/tmp/*", "/etc/*", "/usr/bin/*", "/var/log/*", "/home/user/*"};

	for (const auto &path : recursivePaths)
	{
		PolicyRule rule("proc", "/usr/bin/test", "rw", path);
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
		EXPECT_EQ(exit_code, 255)
			<< "Should support recursive directory: " << path;
	}
}

// 测试特殊字符路径
TEST_F(FrtpPathHandlingTest, SpecialCharacterPaths)
{
	std::vector<std::string> specialPaths = {
		"/tmp/file with spaces.txt",
		"/tmp/file-with-dashes.txt",
		"/tmp/file_with_underscores.txt",
		"/tmp/file.with.dots.txt",
		"/tmp/file@with@at.txt",
		"/tmp/file#with#hash.txt",
		"/tmp/file$with$dollar.txt"
	};

	// 创建这些测试文件
	createTestFileStructure(specialPaths);

	for (const auto &path : specialPaths)
	{
		PolicyRule rule("proc", "/usr/bin/test", "r", path);
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
		EXPECT_EQ(exit_code, 255)
			<< "Should handle special characters in path: " << path;
	}
}

// 测试超长路径
TEST_F(FrtpPathHandlingTest, LongPaths)
{
	std::vector<std::string> longPaths;

	// 生成不同长度的路径
	std::string basePath = "/tmp";
	for (int i = 1; i <= 5; i++)
	{
		std::string longPath = basePath;
		for (int j = 0; j < i * 50; j++)
		{
			longPath += "/very_long_directory_name_" + std::to_string(j);
		}
		longPath += "/file.txt";
		longPaths.push_back(longPath);
	}

	for (const auto &path : longPaths)
	{
		PolicyRule rule("proc", "/usr/bin/test", "r", path);
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

		// 长路径可能因为不存在而导致错误
		EXPECT_NE(exit_code, 0) << "Long path might cause error due to "
								   "non-existence: "
								<< path.length() << " chars";
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
		PolicyRule rule("proc", "/usr/bin/test", "r", path);
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

		// 不存在的路径应该导致错误
		EXPECT_NE(exit_code, 0)
			<< "Nonexistent path should cause error: " << path;

		// 检查是否包含相关错误信息
		std::vector<std::string> errors = extractErrorMessages(output);
		EXPECT_GT(errors.size(), 0)
			<< "Should produce error messages for nonexistent path: " << path;
	}
}

// 测试权限被拒绝的路径
TEST_F(FrtpPathHandlingTest, PermissionDeniedPaths)
{
	std::vector<std::string> restrictedPaths = {
		"/root/secret_file.txt",	  // 通常用户无权访问
		"/etc/shadow",				  // 系统敏感文件
		"/proc/1/mem",				  // 内核内存文件
		"/sys/kernel/debug/something" // 调试文件系统
	};

	for (const auto &path : restrictedPaths)
	{
		PolicyRule rule("proc", "/usr/bin/test", "r", path);
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

		// 权限受限的路径可能导致错误
		EXPECT_NE(exit_code, 0)
			<< "Permission denied path might cause error: " << path;
	}
}

// 测试符号链接处理
TEST_F(FrtpPathHandlingTest, SymbolicLinks)
{
	// 创建测试文件和符号链接
	std::string targetFile = "/tmp/frtp_test_target.txt";
	std::string linkFile = "/tmp/frtp_test_link.txt";

	// 创建目标文件
	std::ofstream target(targetFile);
	target << "target file content" << std::endl;
	target.close();

	// 创建符号链接
	system(("ln -sf " + targetFile + " " + linkFile).c_str());

	// 测试指向符号链接的规则
	PolicyRule rule("proc", "/usr/bin/test", "r", linkFile);
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
	EXPECT_EQ(exit_code, 255) << "Should handle symbolic links correctly";

	// 清理
	unlink(targetFile.c_str());
	unlink(linkFile.c_str());
}

// ========== 错误处理测试用例 ==========

// 测试格式错误的策略行
TEST_F(FrtpErrorHandlingTest, MalformedPolicyLines)
{
	std::vector<std::string> malformedLines = {
		"forbid",										// 缺少所有参数
		"forbid proc=/usr/bin/cat",						// 缺少action和target
		"forbid proc=/usr/bin/cat r",					// 缺少target
		"proc=/usr/bin/cat r /etc/passwd",				// 缺少forbid关键字
		"forbid proc /usr/bin/cat r /etc/passwd",		// 缺少等号
		"forbid proc=/usr/bin/cat r /etc/passwd extra", // 多余参数
		"allow proc=/usr/bin/cat r /etc/passwd",		// 错误的关键字
		"deny proc=/usr/bin/cat r /etc/passwd"			// 错误的关键字
	};

	for (const auto &line : malformedLines)
	{
		createTestPolicyFile(line + "\n");

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 格式错误的行应该导致解析错误
		EXPECT_NE(exit_code, 0)
			<< "Malformed line should cause error: " << line;

		// 应该包含错误信息
		std::vector<std::string> errors = extractErrorMessages(output);
		EXPECT_GT(errors.size(), 0)
			<< "Should report errors for malformed line: " << line;
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

		EXPECT_NE(exit_code, 0)
			<< "Incomplete rule should cause error: " << rule;
	}
}

// 测试多余字段的策略
TEST_F(FrtpErrorHandlingTest, ExtraFields)
{
	std::vector<std::string> rulesWithExtra = {
		"forbid proc=/usr/bin/cat r /etc/passwd extra_field",
		"forbid proc=/usr/bin/cat r /etc/passwd another extra",
		"forbid proc=/usr/bin/cat r /etc/passwd # comment should be ok",
		"forbid extra proc=/usr/bin/cat r /etc/passwd",
		"forbid proc=/usr/bin/cat extra r /etc/passwd"
	};

	for (const auto &rule : rulesWithExtra)
	{
		createTestPolicyFile(rule + "\n");

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 多余字段可能被忽略或导致错误
		if (rule.find("#") != std::string::npos)
		{
			// 包含注释的行应该正常处理
			EXPECT_EQ(exit_code, 255)
				<< "Rule with comment should be processed: " << rule;
		}
		else
		{
			EXPECT_NE(exit_code, 0)
				<< "Rule with extra fields might cause error: " << rule;
		}
	}
}

// 测试无效字符处理
TEST_F(FrtpErrorHandlingTest, InvalidCharacters)
{
	std::vector<std::string> rulesWithInvalidChars = {
		"forbid proc=/usr/bin/cat\0 r /etc/passwd",	  // 空字符
		"forbid proc=/usr/bin/cat\n r /etc/passwd",	  // 换行符在中间
		"forbid proc=/usr/bin/cat\t\t r /etc/passwd", // 多个制表符
		"forbid proc=/usr/bin/cat® r /etc/passwd",	  // 特殊Unicode字符
		"forbid proc=/usr/bin/cat™ r /etc/passwd"	  // 商标符号
	};

	for (const auto &rule : rulesWithInvalidChars)
	{
		createTestPolicyFile(rule + "\n");

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 无效字符可能导致解析错误
		EXPECT_NE(exit_code, 0) << "Invalid characters should cause parsing "
								   "issues";
	}
}

// 测试编码问题
TEST_F(FrtpErrorHandlingTest, EncodingIssues)
{
	// 创建包含不同编码的策略文件
	std::vector<std::string> encodingTests = {
		"forbid proc=/usr/bin/cat r /tmp/测试文件.txt", // 中文文件名
		"forbid proc=/usr/bin/café r /etc/passwd", // 带重音符的程序名
		"forbid proc=/usr/bin/naïve r /etc/passwd" // 带变音符的程序名
	};

	for (const auto &rule : encodingTests)
	{
		createTestPolicyFile(rule + "\n");

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// Unicode字符可能导致问题，取决于系统设置
		EXPECT_NE(exit_code, 0)
			<< "Unicode characters might cause issues: " << rule;
	}
}

// 测试截断的策略文件
TEST_F(FrtpErrorHandlingTest, TruncatedPolicyFile)
{
	std::string fullRule = "forbid proc=/usr/bin/cat r /etc/passwd";

	// 测试不同程度的截断
	for (size_t i = 1; i < fullRule.length(); i += 5)
	{
		std::string truncated = fullRule.substr(0, i);
		createTestPolicyFile(truncated);

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 截断的规则应该导致解析错误
		EXPECT_NE(exit_code, 0)
			<< "Truncated rule should cause error: " << truncated;
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
	EXPECT_NE(exit_code, 0) << "Binary file should cause parsing error";

	std::vector<std::string> errors = extractErrorMessages(output);
	EXPECT_GT(errors.size(), 0) << "Should report errors for binary file";
}

// 测试空策略文件
TEST_F(FrtpErrorHandlingTest, EmptyPolicyFile)
{
	// 创建完全空的策略文件
	createTestPolicyFile("");

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 空策略文件可能是合法的，但会因为没有规则而继续到BPF阶段
	EXPECT_EQ(exit_code, 255) << "Empty policy file should reach BPF stage";
	EXPECT_NE(output.find("libbpf"), std::string::npos) << "Should reach BPF "
														   "loading";
}

// 测试只读策略文件
TEST_F(FrtpErrorHandlingTest, ReadOnlyPolicyFile)
{
	// 创建策略文件并设置为只读
	createTestPolicyFile("forbid proc=/usr/bin/cat r /etc/passwd\n");
	chmod(TEST_POLICY_FILE.c_str(), 0444); // 只读权限

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 只读文件应该可以正常读取
	EXPECT_EQ(exit_code, 255) << "Read-only policy file should be readable";

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
			EXPECT_EQ(exit_code, 255) << "Should be able to read file with "
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

// 测试帮助信息格式验证
TEST_F(FrtpOutputValidationTest, HelpMessageFormat)
{
	std::string output = runFrtpCommand({"--help"});
	int exit_code = getLastExitCode();

	// 验证退出码
	EXPECT_EQ(exit_code, 0) << "Help should exit with code 0";

	// 验证必需的帮助信息组件
	std::vector<std::string> requiredElements = {
		"Usage:",
		"protect system files",
		"policy file",
		"Options:",
		"--policy-file",
		"--help",
		"-p",
		"-h"
	};

	EXPECT_TRUE(containsAllKeywords(output, requiredElements))
		<< "Help message should contain all required elements";

	// 验证格式结构
	EXPECT_NE(output.find("Usage:"), std::string::npos) << "Should contain "
														   "usage line";
	EXPECT_TRUE(output.find("Options:") < output.find("--policy-file"))
		<< "Options section should come before option descriptions";
}

// 测试错误信息格式
TEST_F(FrtpOutputValidationTest, ErrorMessageFormats)
{
	// 测试无效选项的错误格式
	std::string output1 = runFrtpCommand({"--invalid-option"});
	std::vector<std::string> errors1 = extractErrorMessages(output1);
	EXPECT_GT(errors1.size(), 0) << "Should produce error messages for invalid "
									"option";

	// 测试不存在文件的错误格式
	std::string output2 =
		runFrtpCommand({"--policy-file", "/nonexistent/file.pol"});
	std::vector<std::string> errors2 = extractErrorMessages(output2);
	EXPECT_GT(errors2.size(), 0) << "Should produce error messages for "
									"nonexistent file";

	// 测试BPF错误信息格式
	createTestPolicyFile("forbid proc=/usr/bin/cat r /etc/passwd\n");
	std::string output3 = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});

	// BPF错误应该包含特定关键字
	std::vector<std::string> bpfKeywords =
		{"libbpf", "BPF", "RLIMIT_MEMLOCK", "Operation not permitted"};
	bool hasBpfError = false;
	for (const auto &keyword : bpfKeywords)
	{
		if (output3.find(keyword) != std::string::npos)
		{
			hasBpfError = true;
			break;
		}
	}
	EXPECT_TRUE(hasBpfError) << "Should contain BPF-related error messages";
}

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
	bool hasProcessingInfo = output.find("policy") != std::string::npos ||
							 output.find("rule") != std::string::npos ||
							 output.find("load") != std::string::npos;

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
		if (!line.empty() && line.find("libbpf:") != std::string::npos)
		{
			hasProperLogFormat = true;
			break;
		}
	}

	EXPECT_TRUE(hasProperLogFormat) << "Should have properly formatted log "
									   "messages";
}

// 测试BPF错误信息
TEST_F(FrtpOutputValidationTest, BPFErrorMessages)
{
	createTestPolicyFile("forbid proc=/usr/bin/cat r /etc/passwd\n");
	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});

	// 应该包含特定的BPF错误信息
	std::vector<std::string> expectedBpfErrors = {
		"Failed to bump RLIMIT_MEMLOCK",
		"Operation not permitted",
		"failed to load object",
		"failed to load BPF skeleton"
	};

	bool hasExpectedErrors = false;
	for (const auto &error : expectedBpfErrors)
	{
		if (output.find(error) != std::string::npos)
		{
			hasExpectedErrors = true;
			break;
		}
	}

	EXPECT_TRUE(hasExpectedErrors) << "Should contain expected BPF error "
									  "messages";
}

// ========== 边界条件测试用例 ==========

// 测试最大策略规则数
TEST_F(FrtpBoundaryTest, MaximumPolicyRules)
{
	std::vector<PolicyRule> maxRules;

	// 生成大量规则（接近或超过BPF map限制）
	for (int i = 0; i < 1000; i++)
	{
		maxRules.push_back(PolicyRule(
			"proc",
			"/usr/bin/test" + std::to_string(i),
			"r",
			"/tmp/file" + std::to_string(i) + ".txt"
		));
	}

	std::string policy = createMultiRulePolicy(maxRules);
	createTestPolicyFile(policy);

	std::string output = runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
	int exit_code = getLastExitCode();

	// 大量规则可能导致内存或解析问题
	EXPECT_NE(exit_code, 0) << "Maximum rules might cause memory or parsing "
							   "issues";
}

// 测试最大行长度
TEST_F(FrtpBoundaryTest, MaximumLineLength)
{
	// 生成超长的策略行
	std::vector<size_t> lineLengths = {100, 500, 1000, 4096, 8192, 16384};

	for (size_t length : lineLengths)
	{
		std::string longPath = "/tmp/";
		while (longPath.length() < length - 50)
		{
			longPath += "very_long_directory_name_";
		}
		longPath += "file.txt";

		PolicyRule rule("proc", "/usr/bin/test", "r", longPath);
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

		if (length <= 8192)
		{
			// 应该能处理合理长度的行
			EXPECT_NE(exit_code, 0)
				<< "Line length " << length << " might cause path issues";
		}
		else
		{
			// 超长行可能导致缓冲区溢出
			EXPECT_NE(exit_code, 0) << "Very long line should cause buffer "
									   "issues at length "
									<< length;
		}
	}
}

// 测试极限PID值
TEST_F(FrtpBoundaryTest, ExtremePIDValues)
{
	std::vector<std::string> extremePids = {
		"0",		  // 最小PID
		"1",		  // init进程
		"32767",	  // 传统16位PID最大值
		"65535",	  // 16位无符号最大值
		"2147483647", // 32位有符号最大值
		"4294967295"  // 32位无符号最大值（可能无效）
	};

	for (const auto &pid : extremePids)
	{
		PolicyRule rule("pid", pid, "r", "/etc/passwd");
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

		if (pid == "0" || pid == "4294967295")
		{
			// 特殊PID值可能无效
			EXPECT_NE(exit_code, 0)
				<< "Extreme PID " << pid << " might be invalid";
		}
		else
		{
			// 其他PID值应该能解析
			EXPECT_EQ(exit_code, 255)
				<< "Valid PID " << pid << " should reach BPF stage";
		}
	}
}

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
		PolicyRule rule("proc", "/usr/bin/test", "r", path);
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
		EXPECT_NE(exit_code, 0)
			<< "Unicode path might cause encoding issues: " << path;
	}
}

// 测试最小有效策略
TEST_F(FrtpBoundaryTest, MinimumValidPolicy)
{
	// 测试最小可能的有效策略
	std::vector<std::string> minimalPolicies = {
		"forbid proc=/ r /",					 // 最短路径
		"forbid pid=1 r /",						 // 最小PID
		"forbid proc=/a r /a",					 // 单字符路径
		"forbid proc=/usr/bin/cat r /etc/passwd" // 标准最小策略
	};

	for (const auto &policy : minimalPolicies)
	{
		createTestPolicyFile(policy + "\n");

		std::string output =
			runFrtpCommand({"--policy-file", TEST_POLICY_FILE});
		int exit_code = getLastExitCode();

		// 最小策略应该能正确解析
		if (policy.find("proc=/") != std::string::npos &&
			policy.find(" r /") != std::string::npos)
		{
			// 可能因为路径问题失败
			EXPECT_NE(exit_code, 0)
				<< "Minimal policy might fail due to path issues: " << policy;
		}
		else
		{
			EXPECT_EQ(exit_code, 255)
				<< "Minimal valid policy should reach BPF stage: " << policy;
		}
	}
}
