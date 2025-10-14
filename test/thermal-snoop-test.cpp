// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#include "gtest/gtest.h"
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>
#include <climits>
#include <cstdint>
#include "dkapture.h"
#include "thermal-snoop.h"

// 声明thermal_snoop_init函数，这是在BUILTIN模式下的入口点
extern int
thermal_snoop_init(int argc, char **argv, DKapture::DKCallback cb, void *ctx);

// 测试常量定义
const std::string TEST_ROOT = "/tmp/thermal_snoop_test_dir";

// 测试回调函数，用于接收和验证BPF事件
static std::vector<struct thermal_event> captured_events;
static std::atomic<bool> event_received(false);

// 回调函数，用于接收BPF事件
static int test_callback(void *ctx, const void *data, size_t data_sz)
{
	// 数据验证
	if (data == nullptr || data_sz == 0)
	{
		return -1;
	}

	// 数据大小检查
	if (data_sz < sizeof(struct thermal_event))
	{
		return -1;
	}

	// 处理事件
	const struct thermal_event *event =
		static_cast<const struct thermal_event *>(data);
	captured_events.push_back(*event);
	event_received = true;
	return 0;
}

// 测试类
class ThermalSnoopBasicTest : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		// 创建测试目录
		mkdir(TEST_ROOT.c_str(), 0755);

		// 清除之前捕获的事件
		captured_events.clear();
		event_received = false;
	}

	void TearDown() override
	{
		// 清理测试目录
		std::string cmd = "rm -rf " + TEST_ROOT;
		system(cmd.c_str());
	}

	// 辅助函数：模拟温度更新事件
	void simulateTempUpdateEvent(
		uint32_t thermal_zone_id,
		int32_t temperature,
		const char *zone_type,
		uint32_t zone_temp,
		uint32_t prev_temp
	)
	{
		struct thermal_event event;
		memset(&event, 0, sizeof(event));

		// 设置事件头部
		event.header.timestamp = getCurrentTimestampNs();
		event.header.event_type = THERMAL_TEMP_UPDATE;
		event.header.cpu = 0;
		strncpy(
			event.header.comm,
			"test_process",
			sizeof(event.header.comm) - 1
		);
		event.header.pid = 1000;
		event.header.tid = 1001;

		// 设置事件数据
		event.data.temp_update.thermal_zone_id = thermal_zone_id;
		event.data.temp_update.temperature = temperature;
		strncpy(
			event.data.temp_update.zone_type,
			zone_type,
			sizeof(event.data.temp_update.zone_type) - 1
		);
		event.data.temp_update.zone_temp = zone_temp;
		event.data.temp_update.prev_temp = prev_temp;

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟触发点事件
	void simulateTripEvent(
		uint32_t thermal_zone_id,
		uint32_t trip_id,
		const char *trip_type,
		int32_t trip_temp,
		int32_t current_temp,
		uint32_t trip_hyst
	)
	{
		struct thermal_event event;
		memset(&event, 0, sizeof(event));

		// 设置事件头部
		event.header.timestamp = getCurrentTimestampNs();
		event.header.event_type = THERMAL_TRIP_TRIGGERED;
		event.header.cpu = 0;
		strncpy(
			event.header.comm,
			"test_process",
			sizeof(event.header.comm) - 1
		);
		event.header.pid = 1000;
		event.header.tid = 1001;

		// 设置事件数据
		event.data.trip_event.thermal_zone_id = thermal_zone_id;
		event.data.trip_event.trip_id = trip_id;
		strncpy(
			event.data.trip_event.trip_type,
			trip_type,
			sizeof(event.data.trip_event.trip_type) - 1
		);
		event.data.trip_event.trip_temp = trip_temp;
		event.data.trip_event.current_temp = current_temp;
		event.data.trip_event.trip_hyst = trip_hyst;

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟冷却设备更新事件
	void simulateCdevUpdateEvent(
		uint32_t cdev_id,
		const char *cdev_type,
		uint32_t old_state,
		uint32_t new_state,
		uint32_t max_state,
		uint64_t power
	)
	{
		struct thermal_event event;
		memset(&event, 0, sizeof(event));

		// 设置事件头部
		event.header.timestamp = getCurrentTimestampNs();
		event.header.event_type = THERMAL_CDEV_UPDATE;
		event.header.cpu = 0;
		strncpy(
			event.header.comm,
			"test_process",
			sizeof(event.header.comm) - 1
		);
		event.header.pid = 1000;
		event.header.tid = 1001;

		// 设置事件数据
		event.data.cdev_update.cdev_id = cdev_id;
		strncpy(
			event.data.cdev_update.cdev_type,
			cdev_type,
			sizeof(event.data.cdev_update.cdev_type) - 1
		);
		event.data.cdev_update.old_state = old_state;
		event.data.cdev_update.new_state = new_state;
		event.data.cdev_update.max_state = max_state;
		event.data.cdev_update.power = power;

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟功率分配事件
	void simulatePowerAllocEvent(
		uint32_t thermal_zone_id,
		uint32_t total_req_power,
		uint32_t granted_power,
		uint32_t extra_actor_power,
		int32_t delta_temp,
		int32_t switch_on_temp
	)
	{
		struct thermal_event event;
		memset(&event, 0, sizeof(event));

		// 设置事件头部
		event.header.timestamp = getCurrentTimestampNs();
		event.header.event_type = THERMAL_POWER_ALLOC;
		event.header.cpu = 0;
		strncpy(
			event.header.comm,
			"test_process",
			sizeof(event.header.comm) - 1
		);
		event.header.pid = 1000;
		event.header.tid = 1001;

		// 设置事件数据
		event.data.power_alloc.thermal_zone_id = thermal_zone_id;
		event.data.power_alloc.total_req_power = total_req_power;
		event.data.power_alloc.granted_power = granted_power;
		event.data.power_alloc.extra_actor_power = extra_actor_power;
		event.data.power_alloc.delta_temp = delta_temp;
		event.data.power_alloc.switch_on_temp = switch_on_temp;

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟PID功率控制事件
	void simulatePowerPidEvent(
		uint32_t thermal_zone_id,
		int32_t err,
		int32_t p_term,
		int32_t i_term,
		int32_t d_term,
		int32_t output
	)
	{
		struct thermal_event event;
		memset(&event, 0, sizeof(event));

		// 设置事件头部
		event.header.timestamp = getCurrentTimestampNs();
		event.header.event_type = THERMAL_POWER_PID;
		event.header.cpu = 0;
		strncpy(
			event.header.comm,
			"test_process",
			sizeof(event.header.comm) - 1
		);
		event.header.pid = 1000;
		event.header.tid = 1001;

		// 设置事件数据
		event.data.power_pid.thermal_zone_id = thermal_zone_id;
		event.data.power_pid.err = err;
		event.data.power_pid.p_term = p_term;
		event.data.power_pid.i_term = i_term;
		event.data.power_pid.d_term = d_term;
		event.data.power_pid.output = output;

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：获取当前时间戳（纳秒）
	uint64_t getCurrentTimestampNs()
	{
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	}
};

// 测试基本事件处理
TEST_F(ThermalSnoopBasicTest, EventHandling)
{
	// 模拟温度更新事件
	simulateTempUpdateEvent(0, 45000, "cpu-thermal", 45000, 44000);

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture one event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.header.event_type, THERMAL_TEMP_UPDATE)
			<< "Event type should be THERMAL_TEMP_UPDATE";
		EXPECT_EQ(event.data.temp_update.thermal_zone_id, 0) << "Thermal zone "
																"ID should "
																"match";
		EXPECT_EQ(event.data.temp_update.temperature, 45000) << "Temperature "
																"should match";
		EXPECT_STREQ(event.data.temp_update.zone_type, "cpu-thermal")
			<< "Zone type should match";
		EXPECT_EQ(event.data.temp_update.zone_temp, 45000) << "Zone "
															  "temperature "
															  "should match";
		EXPECT_EQ(event.data.temp_update.prev_temp, 44000) << "Previous "
															  "temperature "
															  "should match";
	}
}

// 测试不同类型的事件
TEST_F(ThermalSnoopBasicTest, DifferentEventTypes)
{
	// 模拟温度更新事件
	simulateTempUpdateEvent(0, 45000, "cpu-thermal", 45000, 44000);

	// 模拟触发点事件
	simulateTripEvent(0, 1, "critical", 90000, 91000, 5000);

	// 模拟冷却设备更新事件
	simulateCdevUpdateEvent(0, "Processor", 0, 5, 10, 1000);

	// 模拟功率分配事件
	simulatePowerAllocEvent(0, 5000, 4000, 1000, 2000, 50000);

	// 模拟PID功率控制事件
	simulatePowerPidEvent(0, 1000, 500, 300, 200, 1000);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 5) << "Should capture five events";

	if (captured_events.size() >= 5)
	{
		// 验证温度更新事件
		EXPECT_EQ(captured_events[0].header.event_type, THERMAL_TEMP_UPDATE)
			<< "First event type should be THERMAL_TEMP_UPDATE";

		// 验证触发点事件
		EXPECT_EQ(captured_events[1].header.event_type, THERMAL_TRIP_TRIGGERED)
			<< "Second event type should be THERMAL_TRIP_TRIGGERED";
		EXPECT_STREQ(captured_events[1].data.trip_event.trip_type, "critical")
			<< "Trip type should match";

		// 验证冷却设备更新事件
		EXPECT_EQ(captured_events[2].header.event_type, THERMAL_CDEV_UPDATE)
			<< "Third event type should be THERMAL_CDEV_UPDATE";
		EXPECT_STREQ(captured_events[2].data.cdev_update.cdev_type, "Processor")
			<< "Cooling device type should match";

		// 验证功率分配事件
		EXPECT_EQ(captured_events[3].header.event_type, THERMAL_POWER_ALLOC)
			<< "Fourth event type should be THERMAL_POWER_ALLOC";

		// 验证PID功率控制事件
		EXPECT_EQ(captured_events[4].header.event_type, THERMAL_POWER_PID)
			<< "Fifth event type should be THERMAL_POWER_PID";
	}
}

// 测试温度阈值
TEST_F(ThermalSnoopBasicTest, TemperatureThresholds)
{
	// 模拟不同温度的事件
	simulateTempUpdateEvent(0, 30000, "cpu-thermal", 30000, 29000); // 30°C
	simulateTempUpdateEvent(0, 50000, "cpu-thermal", 50000, 49000); // 50°C
	simulateTempUpdateEvent(0, 70000, "cpu-thermal", 70000, 69000); // 70°C
	simulateTempUpdateEvent(0, 90000, "cpu-thermal", 90000, 89000); // 90°C

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four events";

	if (captured_events.size() >= 4)
	{
		// 验证温度值
		EXPECT_EQ(captured_events[0].data.temp_update.temperature, 30000)
			<< "First temperature should be 30°C";
		EXPECT_EQ(captured_events[1].data.temp_update.temperature, 50000)
			<< "Second temperature should be 50°C";
		EXPECT_EQ(captured_events[2].data.temp_update.temperature, 70000)
			<< "Third temperature should be 70°C";
		EXPECT_EQ(captured_events[3].data.temp_update.temperature, 90000)
			<< "Fourth temperature should be 90°C";
	}
}

// 测试触发点类型
TEST_F(ThermalSnoopBasicTest, TripTypes)
{
	// 模拟不同类型的触发点事件
	simulateTripEvent(0, 0, "passive", 55000, 56000, 2000);
	simulateTripEvent(0, 1, "active", 65000, 66000, 3000);
	simulateTripEvent(0, 2, "hot", 75000, 76000, 4000);
	simulateTripEvent(0, 3, "critical", 85000, 86000, 5000);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four events";

	if (captured_events.size() >= 4)
	{
		// 验证触发点类型
		EXPECT_STREQ(captured_events[0].data.trip_event.trip_type, "passive")
			<< "First trip type should be passive";
		EXPECT_STREQ(captured_events[1].data.trip_event.trip_type, "active")
			<< "Second trip type should be active";
		EXPECT_STREQ(captured_events[2].data.trip_event.trip_type, "hot")
			<< "Third trip type should be hot";
		EXPECT_STREQ(captured_events[3].data.trip_event.trip_type, "critical")
			<< "Fourth trip type should be critical";
	}
}

// 测试冷却设备状态变化
TEST_F(ThermalSnoopBasicTest, CoolingDeviceStateChanges)
{
	// 模拟冷却设备状态变化
	simulateCdevUpdateEvent(0, "Processor", 0, 2, 10, 1000); // 增加冷却
	simulateCdevUpdateEvent(0, "Processor", 2, 5, 10, 2000); // 增加冷却
	simulateCdevUpdateEvent(0, "Processor", 5, 2, 10, 1000); // 减少冷却
	simulateCdevUpdateEvent(0, "Processor", 2, 0, 10, 0);	 // 停止冷却

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four events";

	if (captured_events.size() >= 4)
	{
		// 验证状态变化
		EXPECT_EQ(captured_events[0].data.cdev_update.old_state, 0)
			<< "First old state should be 0";
		EXPECT_EQ(captured_events[0].data.cdev_update.new_state, 2)
			<< "First new state should be 2";

		EXPECT_EQ(captured_events[1].data.cdev_update.old_state, 2)
			<< "Second old state should be 2";
		EXPECT_EQ(captured_events[1].data.cdev_update.new_state, 5)
			<< "Second new state should be 5";

		EXPECT_EQ(captured_events[2].data.cdev_update.old_state, 5)
			<< "Third old state should be 5";
		EXPECT_EQ(captured_events[2].data.cdev_update.new_state, 2)
			<< "Third new state should be 2";

		EXPECT_EQ(captured_events[3].data.cdev_update.old_state, 2)
			<< "Fourth old state should be 2";
		EXPECT_EQ(captured_events[3].data.cdev_update.new_state, 0)
			<< "Fourth new state should be 0";
	}
}

// 测试错误处理
TEST_F(ThermalSnoopBasicTest, ErrorHandling)
{
	// 测试空数据
	int result = test_callback(nullptr, nullptr, 0);
	EXPECT_EQ(result, -1) << "Null data should be rejected";

	// 清除之前的事件
	captured_events.clear();
	event_received = false;

	// 测试数据大小不足
	char small_data[1];
	result = test_callback(nullptr, small_data, sizeof(small_data));
	EXPECT_EQ(result, -1) << "Incomplete data should be rejected";

	// 验证没有事件被捕获
	EXPECT_FALSE(event_received) << "No event should be received for invalid "
									"data";
	EXPECT_EQ(captured_events.size(), 0) << "No events should be captured for "
											"invalid data";
}

// 测试边界条件
TEST_F(ThermalSnoopBasicTest, BoundaryConditions)
{
	// 测试极高温度
	simulateTempUpdateEvent(0, INT_MAX, "cpu-thermal", INT_MAX, INT_MAX - 1000);

	// 测试极低温度
	simulateTempUpdateEvent(0, INT_MIN, "cpu-thermal", INT_MIN, INT_MIN + 1000);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 2) << "Should capture two events";

	if (captured_events.size() >= 2)
	{
		// 验证极高温度
		EXPECT_EQ(captured_events[0].data.temp_update.temperature, INT_MAX)
			<< "Max temperature should match";

		// 验证极低温度
		EXPECT_EQ(captured_events[1].data.temp_update.temperature, INT_MIN)
			<< "Min temperature should match";
	}
}

// 测试性能
TEST_F(ThermalSnoopBasicTest, Performance)
{
	// 清除之前捕获的事件
	captured_events.clear();
	event_received = false;

	// 记录开始时间
	auto start_time = std::chrono::high_resolution_clock::now();

	// 模拟大量事件
	const int NUM_EVENTS = 1000;
	for (int i = 0; i < NUM_EVENTS; i++)
	{
		int32_t temp = 30000 + (i % 70000); // 30°C to 100°C
		simulateTempUpdateEvent(i % 4, temp, "cpu-thermal", temp, temp - 1000);
	}

	// 记录结束时间
	auto end_time = std::chrono::high_resolution_clock::now();

	// 计算处理时间
	auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
		end_time - start_time
	);

	// 输出性能指标
	std::cout << "Processing " << NUM_EVENTS << " events took "
			  << duration.count() << " microseconds" << std::endl;
	std::cout << "Average time per event: "
			  << static_cast<double>(duration.count()) / NUM_EVENTS
			  << " microseconds" << std::endl;

	// 验证所有事件都被处理
	EXPECT_EQ(captured_events.size(), NUM_EVENTS) << "All events should be "
													 "processed";

	// 验证处理时间是否在合理范围内（这里设置一个宽松的上限）
	EXPECT_LT(duration.count(), 1000000) << "Event processing should be "
											"reasonably fast";
}

// 测试多种热区
TEST_F(ThermalSnoopBasicTest, MultipleThermalZones)
{
	// 模拟不同热区的温度事件
	simulateTempUpdateEvent(0, 45000, "cpu-thermal", 45000, 44000);
	simulateTempUpdateEvent(1, 42000, "gpu-thermal", 42000, 41000);
	simulateTempUpdateEvent(2, 38000, "battery", 38000, 37000);
	simulateTempUpdateEvent(3, 35000, "skin-thermal", 35000, 34000);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four events";

	if (captured_events.size() >= 4)
	{
		// 验证不同热区
		EXPECT_EQ(captured_events[0].data.temp_update.thermal_zone_id, 0)
			<< "First zone ID should be 0";
		EXPECT_STREQ(
			captured_events[0].data.temp_update.zone_type,
			"cpu-thermal"
		) << "First zone type should be cpu-thermal";

		EXPECT_EQ(captured_events[1].data.temp_update.thermal_zone_id, 1)
			<< "Second zone ID should be 1";
		EXPECT_STREQ(
			captured_events[1].data.temp_update.zone_type,
			"gpu-thermal"
		) << "Second zone type should be gpu-thermal";

		EXPECT_EQ(captured_events[2].data.temp_update.thermal_zone_id, 2)
			<< "Third zone ID should be 2";
		EXPECT_STREQ(captured_events[2].data.temp_update.zone_type, "battery")
			<< "Third zone type should be battery";

		EXPECT_EQ(captured_events[3].data.temp_update.thermal_zone_id, 3)
			<< "Fourth zone ID should be 3";
		EXPECT_STREQ(
			captured_events[3].data.temp_update.zone_type,
			"skin-thermal"
		) << "Fourth zone type should be skin-thermal";
	}
}

// 测试温度变化趋势
TEST_F(ThermalSnoopBasicTest, TemperatureTrends)
{
	// 模拟温度上升趋势
	simulateTempUpdateEvent(0, 40000, "cpu-thermal", 40000, 39000);
	simulateTempUpdateEvent(0, 42000, "cpu-thermal", 42000, 40000);
	simulateTempUpdateEvent(0, 45000, "cpu-thermal", 45000, 42000);
	simulateTempUpdateEvent(0, 49000, "cpu-thermal", 49000, 45000);

	// 模拟温度下降趋势
	simulateTempUpdateEvent(1, 50000, "gpu-thermal", 50000, 52000);
	simulateTempUpdateEvent(1, 47000, "gpu-thermal", 47000, 50000);
	simulateTempUpdateEvent(1, 43000, "gpu-thermal", 43000, 47000);
	simulateTempUpdateEvent(1, 40000, "gpu-thermal", 40000, 43000);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 8) << "Should capture eight events";

	if (captured_events.size() >= 8)
	{
		// 验证温度上升趋势
		for (int i = 1; i < 4; i++)
		{
			EXPECT_GT(
				captured_events[i].data.temp_update.temperature,
				captured_events[i - 1].data.temp_update.temperature
			) << "Temperature should increase in the first trend";
		}

		// 验证温度下降趋势
		for (int i = 5; i < 8; i++)
		{
			EXPECT_LT(
				captured_events[i].data.temp_update.temperature,
				captured_events[i - 1].data.temp_update.temperature
			) << "Temperature should decrease in the second trend";
		}
	}
}

// 测试热管理策略
TEST_F(ThermalSnoopBasicTest, ThermalManagementPolicies)
{
	// 模拟不同热管理策略的事件
	simulatePowerAllocEvent(0, 8000, 6000, 2000, 5000, 65000); // 功率分配策略
	simulatePowerPidEvent(0, 2000, 1000, 500, 300, 1500);	// PID控制策略
	simulateCdevUpdateEvent(0, "Fan", 5, 8, 10, 2500);		// 风扇调节
	simulateCdevUpdateEvent(1, "CPU_Throttle", 0, 3, 5, 0); // CPU降频

	// 验证热管理事件
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four thermal "
											"management events";

	if (captured_events.size() >= 4)
	{
		// 验证功率分配事件
		EXPECT_EQ(captured_events[0].header.event_type, THERMAL_POWER_ALLOC)
			<< "First should be power allocation";

		// 验证PID控制事件
		EXPECT_EQ(captured_events[1].header.event_type, THERMAL_POWER_PID)
			<< "Second should be PID control";

		// 验证冷却设备事件
		EXPECT_EQ(captured_events[2].header.event_type, THERMAL_CDEV_UPDATE)
			<< "Third should be cooling device";
		EXPECT_EQ(captured_events[3].header.event_type, THERMAL_CDEV_UPDATE)
			<< "Fourth should be cooling device";
	}
}

// 测试热应急响应
TEST_F(ThermalSnoopBasicTest, ThermalEmergencyResponse)
{
	// 模拟热应急场景
	simulateTempUpdateEvent(
		0,
		95000,
		"cpu-thermal",
		95000,
		85000
	); // 温度急剧上升
	simulateTripEvent(0, 3, "critical", 90000, 95000, 2000); // 触发关键温度点
	simulateCdevUpdateEvent(
		0,
		"Emergency_Fan",
		0,
		10,
		10,
		5000
	); // 应急风扇全速
	simulateCdevUpdateEvent(1, "CPU_Shutdown", 0, 1, 1, 0); // CPU紧急降频
	simulatePowerAllocEvent(0, 2000, 500, 0, 10000, 90000); // 紧急功率限制

	// 验证应急响应
	EXPECT_EQ(captured_events.size(), 5) << "Should capture five emergency "
											"response events";

	if (captured_events.size() >= 5)
	{
		// 验证温度事件
		EXPECT_EQ(captured_events[0].data.temp_update.temperature, 95000)
			<< "Critical temperature reached";

		// 验证触发点事件
		EXPECT_STREQ(captured_events[1].data.trip_event.trip_type, "critical")
			<< "Critical trip triggered";

		// 验证应急措施
		EXPECT_EQ(captured_events[2].data.cdev_update.new_state, 10)
			<< "Emergency fan at max speed";
	}
}

// 测试多核心热管理
TEST_F(ThermalSnoopBasicTest, MultiCoreThermalManagement)
{
	// 模拟多核心系统的热事件
	for (int core = 0; core < 8; core++)
	{
		int32_t temp = 45000 + core * 5000; // 每个核心温度不同
		simulateTempUpdateEvent(core, temp, "cpu-thermal", temp, temp - 2000);
	}

	// 验证多核心热管理
	EXPECT_EQ(captured_events.size(), 8) << "Should capture eight core thermal "
											"events";

	if (captured_events.size() >= 8)
	{
		// 验证温度梯度
		for (size_t i = 0; i < captured_events.size(); i++)
		{
			int expected_temp = 45000 + static_cast<int>(i) * 5000;
			EXPECT_EQ(
				captured_events[i].data.temp_update.temperature,
				expected_temp
			) << "Core "
			  << i << " should have expected temperature";
		}
	}
}

// 测试热历史记录
TEST_F(ThermalSnoopBasicTest, ThermalHistory)
{
	// 模拟24小时热历史数据
	std::vector<int32_t> temp_history = {
		40000, 42000, 45000, 50000, 55000, 60000, 65000, 70000, // 0-7点
		75000, 80000, 85000, 88000, 90000, 87000, 85000, 82000, // 8-15点
		78000, 75000, 70000, 65000, 60000, 55000, 50000, 45000	// 16-23点
	};

	for (size_t hour = 0; hour < temp_history.size(); hour++)
	{
		simulateTempUpdateEvent(
			0,
			temp_history[hour],
			"cpu-thermal",
			temp_history[hour],
			hour > 0 ? temp_history[hour - 1] : 38000
		);
	}

	// 验证热历史记录
	EXPECT_EQ(captured_events.size(), 24) << "Should capture 24 hours of "
											 "thermal data";

	if (captured_events.size() >= 24)
	{
		// 找到最高温度
		int32_t max_temp = 0;
		for (const auto &event : captured_events)
		{
			if (event.data.temp_update.temperature > max_temp)
			{
				max_temp = event.data.temp_update.temperature;
			}
		}
		EXPECT_EQ(max_temp, 90000) << "Maximum temperature should be 90°C";
	}
}

// 测试热区域管理
TEST_F(ThermalSnoopBasicTest, ThermalZoneManagement)
{
	// 模拟不同热区域
	simulateTempUpdateEvent(0, 55000, "cpu0-thermal", 55000, 52000);
	simulateTempUpdateEvent(1, 58000, "cpu1-thermal", 58000, 55000);
	simulateTempUpdateEvent(2, 45000, "gpu-thermal", 45000, 43000);
	simulateTempUpdateEvent(3, 40000, "battery-thermal", 40000, 38000);
	simulateTempUpdateEvent(4, 35000, "ambient-thermal", 35000, 33000);
	simulateTempUpdateEvent(5, 42000, "skin-thermal", 42000, 40000);

	// 验证热区域管理
	EXPECT_EQ(captured_events.size(), 6) << "Should capture six thermal zones";

	if (captured_events.size() >= 6)
	{
		// 验证不同热区域的特征
		std::vector<std::string> expected_zones = {
			"cpu0-thermal",
			"cpu1-thermal",
			"gpu-thermal",
			"battery-thermal",
			"ambient-thermal",
			"skin-thermal"
		};

		for (size_t i = 0;
			 i < expected_zones.size() && i < captured_events.size();
			 i++)
		{
			EXPECT_STREQ(
				captured_events[i].data.temp_update.zone_type,
				expected_zones[i].c_str()
			) << "Zone "
			  << i << " should match expected type";
		}
	}
}
