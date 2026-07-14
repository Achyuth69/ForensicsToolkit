#pragma once
#include <QAbstractTableModel>
#include <QList>
#include <QVariant>

namespace Forensic::UI {

/**
 * Generic table model for displaying forensic data in QTableView.
 * Wraps any QList<T> and maps column indices to fields via a configurable
 * header/extractor pair.
 */
template<typename T>
class ForensicTableModel : public QAbstractTableModel {
public:
    using Extractor = std::function<QVariant(const T &, int col)>;

    explicit ForensicTableModel(QObject *parent = nullptr)
        : QAbstractTableModel(parent) {}

    void setHeaders(const QStringList &headers) { m_headers = headers; }
    void setExtractor(Extractor fn)              { m_extractor = fn;    }

    void setData(const QList<T> &data) {
        beginResetModel();
        m_data = data;
        endResetModel();
    }

    void appendRow(const T &item) {
        beginInsertRows({}, m_data.size(), m_data.size());
        m_data.append(item);
        endInsertRows();
    }

    void clear() {
        beginResetModel();
        m_data.clear();
        endResetModel();
    }

    const T& itemAt(int row) const { return m_data.at(row); }
    int      count()         const { return m_data.size();  }

    // QAbstractTableModel interface
    int rowCount   (const QModelIndex &) const override { return m_data.size();    }
    int columnCount(const QModelIndex &) const override { return m_headers.size(); }

    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override {
        if (!index.isValid() || role != Qt::DisplayRole) return {};
        if (index.row() >= m_data.size())               return {};
        if (!m_extractor)                                return {};
        return m_extractor(m_data.at(index.row()), index.column());
    }

    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override {
        if (role != Qt::DisplayRole) return {};
        if (orientation == Qt::Horizontal && section < m_headers.size())
            return m_headers.at(section);
        return section + 1;
    }

private:
    QStringList m_headers;
    QList<T>    m_data;
    Extractor   m_extractor;
};

} // namespace Forensic::UI
