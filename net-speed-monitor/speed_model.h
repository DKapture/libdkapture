// 头文件保护，防止重复包含
#pragma once

// Qt 表格数据模型抽象基类，提供行/列数据接口
#include <QAbstractTableModel>
// 引入 BpfWorker 的类型定义（SpeedMap、SpeedInfo）
#include "bpf_worker.h"

// 进程网速数据表格模型
// 继承 QAbstractTableModel，为 QTableView 提供数据
// 列：进程名、上传速率、下载速率、总上传、总下载
class SpeedModel : public QAbstractTableModel
{
    Q_OBJECT

  public:
    // 列索引枚举
    enum Column
    {
        ColProcess = 0,        // 第 0 列：进程名（格式 "名称[PID]"）
        ColUploadSpeed,        // 第 1 列：当前上传速率（字节/秒）
        ColDownloadSpeed,      // 第 2 列：当前下载速率（字节/秒）
        ColTotalUpload,        // 第 3 列：累计总上传字节数
        ColTotalDownload,      // 第 4 列：累计总下载字节数
        ColCount              // 列总数（非实际列，用于循环边界）
    };

    explicit SpeedModel(QObject *parent = nullptr);

    // 返回表格行数（即有数据的进程数量）
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    // 返回表格列数（固定为 ColCount = 5）
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    // 返回列标题文本（进程名、上传、下载、总上传、总下载）
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;
    // 返回指定单元格的数据（DisplayRole 显示文本，TextAlignmentRole 对齐方式）
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

  public slots:
    // 接收 BpfWorker 的 speedUpdated 信号，更新表格数据
    // 合并新数据、移除已消失的进程、按总流量排序
    void updateSpeeds(const SpeedMap &speeds);
    // 清空所有数据和键名列表
    void resetStats();

  private:
    // 将字节数格式化为人类可读的字符串（B、KB、MB、GB）
    static QString formatBytes(unsigned long long bytes);
    // 将速率格式化为字符串，在 formatBytes 基础上追加 "/s" 后缀
    static QString formatSpeed(unsigned long long bytesPerSec);

    // 当前所有进程的速率数据，键名格式 "进程名[PID]"
    SpeedMap m_speeds;
    // 有序键名列表，保持表格行的稳定顺序（按总流量降序排列）
    QStringList m_keys;
};
