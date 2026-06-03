// Qt 应用程序类，管理 GUI 应用的事件循环
#include <QApplication>
// Qt 主窗口框架，提供菜单栏、工具栏、状态栏
#include <QMainWindow>
// Qt 表格视图控件，用于显示进程网速数据
#include <QTableView>
// Qt 表头控件，控制列宽和显示方式
#include <QHeaderView>
// Qt 状态栏控件（本程序使用工具栏替代）
#include <QStatusBar>
// Qt 菜单栏控件
#include <QMenuBar>
// Qt 菜单项控件
#include <QMenu>
// Qt 消息对话框，用于显示错误提示
#include <QMessageBox>
// Qt 标签控件，用于在工具栏中显示状态文字
#include <QLabel>
// Qt 输入对话框，用于获取用户输入的过滤条件
#include <QInputDialog>
// Qt 按钮控件
#include <QPushButton>
// Qt 工具栏控件
#include <QToolBar>
// Qt 大小策略，用于工具栏中的弹性空白
#include <QSizePolicy>

// getuid()：获取当前用户 UID，检查是否为 root
#include <unistd.h>

// BPF 后台工作类，负责 eBPF 程序的加载和数据采集
#include "bpf_worker.h"
// 表格数据模型类，为 QTableView 提供进程网速数据
#include "speed_model.h"

// 主窗口类：整合表格视图、BPF 工作线程和用户控件
class MainWindow : public QMainWindow
{
    Q_OBJECT

  public:
    MainWindow(QWidget *parent = nullptr) : QMainWindow(parent)
    {
        // 检查 root 权限：eBPF 程序需要 CAP_BPF 或 root 权限才能加载
        if (getuid() != 0)
        {
            QMessageBox::critical(this, "Error",
                "Please run as root (eBPF requires root privileges).");
            exit(1);
        }

        // 创建表格数据模型（管理进程网速数据）
        m_model = new SpeedModel(this);
        // 创建表格视图控件
        m_view = new QTableView(this);
        // 将数据模型绑定到表格视图
        m_view->setModel(m_model);
        // 启用交替行颜色，提高可读性
        m_view->setAlternatingRowColors(true);
        // 设置选择行为：单击选中整行
        m_view->setSelectionBehavior(QAbstractItemView::SelectRows);
        // 禁用编辑：表格仅用于显示，不可编辑
        m_view->setEditTriggers(QAbstractItemView::NoEditTriggers);
        // 最后一列（总下载）自动拉伸填满剩余宽度
        m_view->horizontalHeader()->setStretchLastSection(true);
        // 进程名列根据内容自适应宽度
        m_view->horizontalHeader()->setSectionResizeMode(
            SpeedModel::ColProcess, QHeaderView::ResizeToContents);

        // ---- 工具栏 ----
        auto *toolbar = addToolBar("Controls");

        // 开始/停止监控的切换按钮
        m_toggleBtn = new QPushButton("Start Monitoring", this);
        m_toggleBtn->setCheckable(true);  // 可选中/取消选中，类似开关
        m_toggleBtn->setStyleSheet(
            // 选中时（监控中）：绿色背景白色文字
            "QPushButton:checked { background-color: #4CAF50; color: white; }"
            // 默认样式：带内边距和字体大小
            "QPushButton { padding: 6px 16px; font-size: 13px; }");
        toolbar->addWidget(m_toggleBtn);

        // 重置统计按钮：清零所有累计数据
        auto *resetBtn = new QPushButton("Reset Statistics", this);
        toolbar->addWidget(resetBtn);
        // 过滤按钮：弹出对话框设置进程过滤条件
        auto *filterBtn = new QPushButton("Filter...", this);
        toolbar->addWidget(filterBtn);

        // 工具栏弹性空白：将状态标签推到右侧
        QWidget *spacer = new QWidget(this);
        spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        toolbar->addWidget(spacer);

        // 状态标签：显示当前监控状态（监控中/已停止/错误）
        m_statusLabel = new QLabel("Stopped", this);
        m_statusLabel->setStyleSheet("color: gray;");  // 默认灰色
        toolbar->addWidget(m_statusLabel);

        // 将表格视图设为主窗口的中央控件
        setCentralWidget(m_view);
        setWindowTitle("Net Speed Monitor");
        resize(780, 480);  // 设置初始窗口大小

        // ---- 菜单栏 ----
        auto *menu = menuBar()->addMenu("Actions");
        // 菜单项：重置统计
        auto *resetAct = menu->addAction("Reset Statistics");
        connect(resetAct, &QAction::triggered, this, &MainWindow::onReset);
        // 菜单项：设置过滤
        auto *filterAct = menu->addAction("Set Filter...");
        connect(filterAct, &QAction::triggered, this, &MainWindow::onSetFilter);

        // ---- BPF 工作线程 ----
        m_worker = new BpfWorker(this);

        // BPF 速率数据 -> 表格模型刷新
        // 跨线程信号：BpfWorker 在轮询线程中发射，SpeedModel 在主线程接收
        connect(m_worker, &BpfWorker::speedUpdated, m_model, &SpeedModel::updateSpeeds);
        // BPF 错误 -> 更新状态栏显示红色错误信息
        connect(m_worker, &BpfWorker::bpfError, this, [this](const QString &msg) {
            m_statusLabel->setText("Error: " + msg);
            m_statusLabel->setStyleSheet("color: red;");
            m_toggleBtn->setChecked(false);  // 按钮恢复为未选中状态
        });
        // BPF 状态变化 -> 同步按钮文字和状态标签
        connect(m_worker, &BpfWorker::activeChanged, this, &MainWindow::onActiveChanged);

        // ---- 信号连接：切换按钮 ----
        connect(m_toggleBtn, &QPushButton::toggled, this, [this](bool checked) {
            if (checked)
            {
                // 按钮被选中：启动 BPF 监控
                m_worker->start();
            }
            else
            {
                // 按钮被取消选中：停止 BPF 监控并清空表格
                m_worker->stop();
                m_model->resetStats();
                m_statusLabel->setText("Stopped");
                m_statusLabel->setStyleSheet("color: gray;");
            }
        });

        // 工具栏按钮点击 -> 触发对应的槽函数
        connect(resetBtn, &QPushButton::clicked, this, &MainWindow::onReset);
        connect(filterBtn, &QPushButton::clicked, this, &MainWindow::onSetFilter);
    }

    // 析构函数：确保 BPF 资源被释放
    ~MainWindow()
    {
        m_worker->stop();
    }

  private slots:
    // BPF 状态变化槽函数
    // 同步切换按钮的选中状态和文字、更新状态标签颜色
    void onActiveChanged(bool active)
    {
        // 临时阻止按钮信号，避免 setChecked 触发 toggled 信号导致递归
        m_toggleBtn->blockSignals(true);
        m_toggleBtn->setChecked(active);  // 同步按钮状态
        m_toggleBtn->blockSignals(false);  // 恢复信号

        if (active)
        {
            // BPF 已启动：按钮显示"停止"，状态标签绿色
            m_toggleBtn->setText("Stop Monitoring");
            m_statusLabel->setText("Monitoring...");
            m_statusLabel->setStyleSheet("color: green;");
        }
        else
        {
            // BPF 已停止：按钮显示"开始"，状态标签灰色
            m_toggleBtn->setText("Start Monitoring");
            m_statusLabel->setText("Stopped");
            m_statusLabel->setStyleSheet("color: gray;");
        }
    }

    // 重置统计槽函数
    // 同时清零 BPF 工作线程和表格模型中的累计数据
    void onReset()
    {
        m_worker->resetStats();  // 清零 BPF 端的累计值
        m_model->resetStats();   // 清空表格显示
    }

    // 设置过滤条件槽函数
    // 弹出输入对话框获取进程名，写入 BPF filter map
    void onSetFilter()
    {
        bool ok;
        // 弹出输入对话框，获取要过滤的进程名
        QString text = QInputDialog::getText(this, "Filter",
            "Process name (empty = all):", QLineEdit::Normal, "", &ok);
        // 用户点击取消则不执行任何操作
        if (!ok) return;

        // 将过滤规则写入 BPF filter map（空字符串表示不过滤）
        m_worker->setFilter(text, 0, "", 0, 0);
        // 更新状态标签显示当前过滤条件
        if (m_worker->isActive())
        {
            m_statusLabel->setText(text.isEmpty()
                ? "Monitoring... (no filter)"
                : QString("Monitoring... (filter: %1)").arg(text));
        }
    }

  private:
    QTableView *m_view = nullptr;         // 表格视图控件
    SpeedModel *m_model = nullptr;        // 表格数据模型
    BpfWorker *m_worker = nullptr;        // BPF 后台工作线程
    QPushButton *m_toggleBtn = nullptr;  // 开始/停止切换按钮
    QLabel *m_statusLabel = nullptr;      // 状态标签
};

// 程序入口点
int main(int argc, char *argv[])
{
    // 创建 Qt 应用程序实例，管理 GUI 事件循环
    QApplication app(argc, argv);
    // 创建主窗口
    MainWindow w;
    // 显示主窗口
    w.show();
    // 进入 Qt 事件循环，等待用户交互和定时器事件
    return app.exec();
}

// main.cpp 中定义了 Q_OBJECT 宏的 MainWindow 类
// 需要在 cpp 文件末尾包含 moc 生成的元对象代码
// AUTOMOC 会自动处理，但 cpp 中的 Q_OBJECT 类需要显式包含
#include "main.moc"
