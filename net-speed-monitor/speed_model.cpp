// 引入表格模型声明
#include "speed_model.h"

// C++ STL 排序算法，用于按总流量降序排列进程行
#include <algorithm>

// 构造函数：初始化 QAbstractTableModel 基类
SpeedModel::SpeedModel(QObject *parent) : QAbstractTableModel(parent) {}

// 返回表格行数（等于当前有数据的进程数量）
int SpeedModel::rowCount(const QModelIndex &) const
{
    return m_keys.size();
}

// 返回表格列数（固定为 5 列）
int SpeedModel::columnCount(const QModelIndex &) const
{
    return ColCount;
}

// 返回列标题数据
// 仅处理水平方向的 DisplayRole，返回预定义的列名
QVariant SpeedModel::headerData(int section, Qt::Orientation orientation,
                                int role) const
{
    // 只处理水平标题的显示角色，其他情况返回空 QVariant
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return {};

    // 列标题静态数组，与 Column 枚举一一对应
    static const char *names[] = {
        "Process",      // 进程名列
        "Upload",       // 上传速率列
        "Download",     // 下载速率列
        "Total Up",     // 总上传列
        "Total Down",   // 总下载列
    };
    return QString(names[section]);
}

// 返回指定单元格的数据
QVariant SpeedModel::data(const QModelIndex &index, int role) const
{
    // 无效索引或越界行号，返回空
    if (!index.isValid() || index.row() >= m_keys.size())
        return {};

    // 处理显示角色：返回单元格的文本内容
    if (role == Qt::DisplayRole)
    {
        // 通过行号获取进程键名
        const auto &key = m_keys[index.row()];
        // 从数据 map 中获取该进程的速率信息
        const auto &info = m_speeds[key];

        switch (index.column())
        {
        case ColProcess:
            // 进程名列直接显示键名
            return key;
        case ColUploadSpeed:
            // 上传速率：格式化为 "XX.X KB/s" 格式
            return formatSpeed(info.upload_bytes);
        case ColDownloadSpeed:
            // 下载速率：格式化为 "XX.X KB/s" 格式
            return formatSpeed(info.download_bytes);
        case ColTotalUpload:
            // 总上传：格式化为 "XX.X MB" 格式
            return formatBytes(info.total_upload);
        case ColTotalDownload:
            // 总下载：格式化为 "XX.X MB" 格式
            return formatBytes(info.total_download);
        }
    }

    // 文本对齐角色：数值列（上传速率、下载速率、总上传、总下载）右对齐
    // Qt6 需要显式转为 int 类型，不能隐式转换 QFlags 为 QVariant
    if (role == Qt::TextAlignmentRole && index.column() >= ColUploadSpeed)
        return int(Qt::AlignRight | Qt::AlignVCenter);

    return {};
}

// 更新表格数据（由 BpfWorker::speedUpdated 信号触发）
// 使用 beginResetModel/endResetModel 通知视图完整刷新
void SpeedModel::updateSpeeds(const SpeedMap &speeds)
{
    // 通知视图模型即将重置，视图会缓存当前状态
    beginResetModel();

    // 用最新速率数据替换旧数据
    m_speeds = speeds;

    // 保留已有进程的顺序，新进程追加到末尾
    for (const auto &key : speeds.keys())
    {
        if (!m_keys.contains(key))
            m_keys.append(key);
    }

    // 移除已消失的进程（上一秒有数据，这一秒没有）
    QStringList stale;
    for (const auto &key : m_keys)
    {
        if (!speeds.contains(key))
            stale.append(key);
    }
    for (const auto &key : stale)
        m_keys.removeOne(key);

    // 按总流量（上传+下载）降序排列
    // 流量大的进程显示在表格顶部
    std::sort(m_keys.begin(), m_keys.end(), [&](const QString &a, const QString &b) {
        auto ta = m_speeds.value(a).total_upload + m_speeds.value(a).total_download;
        auto tb = m_speeds.value(b).total_upload + m_speeds.value(b).total_download;
        return ta > tb;
    });

    // 通知视图模型重置完成，视图重新获取所有数据
    endResetModel();
}

// 重置统计：清空所有数据
void SpeedModel::resetStats()
{
    beginResetModel();
    m_speeds.clear();
    m_keys.clear();
    endResetModel();
}

// 将字节数格式化为人类可读的字符串
// 自动根据大小选择合适的单位：B、KB、MB、GB
QString SpeedModel::formatBytes(unsigned long long bytes)
{
    // 小于 1KB 直接显示字节数
    if (bytes < 1024)
        return QString("%1 B").arg(bytes);
    // 小于 1MB 显示为 KB，保留 1 位小数
    if (bytes < 1024ULL * 1024)
        return QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 1);
    // 小于 1GB 显示为 MB，保留 1 位小数
    if (bytes < 1024ULL * 1024 * 1024)
        return QString("%1 MB").arg(bytes / (1024.0 * 1024), 0, 'f', 2);
    // 大于等于 1GB 显示为 GB，保留 2 位小数
    return QString("%1 GB").arg(bytes / (1024.0 * 1024 * 1024), 0, 'f', 2);
}

// 将速率格式化为字符串
// 在 formatBytes 基础上追加 "/s" 后缀表示每秒
QString SpeedModel::formatSpeed(unsigned long long bytesPerSec)
{
    // 速率为 0 时显示 "0 B/s" 而非 "0 B/s"（避免 formatBytes 返回 "0 B" 的不一致）
    if (bytesPerSec == 0)
        return "0 B/s";
    return formatBytes(bytesPerSec) + "/s";
}
