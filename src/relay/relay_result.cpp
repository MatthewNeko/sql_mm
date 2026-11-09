/**
 * =============================================================================
 * SQLMM relay client
 * =============================================================================
 */

#include "relay_result.h"

#include <cstdlib>
#include <cstring>

void CRelayResultSet::AddColumn(const char *name, uint32_t len, uint16_t type)
{
    RelayColumn col;
    col.name.assign(name, len);
    col.type = type;
    m_columns.push_back(std::move(col));
    m_colCount = (uint32_t)m_columns.size();
}

void CRelayResultSet::AddCell(const char *data, uint32_t len)
{
    // Cells are stored NUL terminated so GetString() can be used as a C string
    // by callers that ignore the length out-parameter.
    m_offsets.push_back((uint32_t)m_blob.size());
    m_lengths.push_back(len);
    m_blob.append(data, len);
    m_blob.push_back('\0');
}

void CRelayResultSet::AddNullCell()
{
    m_offsets.push_back((uint32_t)m_blob.size());
    m_lengths.push_back(kNullCell);
}

void CRelayResultSet::EndRow()
{
    m_rowCount++;
}

uint32_t CRelayResultSet::CellIndex(unsigned int columnId) const
{
    if (!HasCurrentRow() || columnId >= m_colCount)
    {
        return kNullCell;
    }
    return (m_curRow - 1) * m_colCount + columnId;
}

const char *CRelayResultSet::CellText(uint32_t index) const
{
    if (index == kNullCell || index >= m_offsets.size())
    {
        return nullptr;
    }
    // NULL cells keep an offset but no bytes; report them as absent rather than
    // handing out a pointer to whatever follows in the arena.
    if (m_lengths[index] == kNullCell)
    {
        return nullptr;
    }
    return m_blob.data() + m_offsets[index];
}

int CRelayResultSet::GetRowCount()
{
    return (int)m_rowCount;
}

int CRelayResultSet::GetFieldCount()
{
    return (int)m_colCount;
}

bool CRelayResultSet::FieldNameToNum(const char *name, unsigned int *columnId)
{
    if (!name)
    {
        return false;
    }

    for (uint32_t i = 0; i < m_colCount; i++)
    {
        if (m_columns[i].name == name)
        {
            if (columnId)
            {
                *columnId = i;
            }
            return true;
        }
    }

    return false;
}

const char *CRelayResultSet::FieldNumToName(unsigned int colId)
{
    if (colId >= m_colCount)
    {
        return nullptr;
    }
    return m_columns[colId].name.c_str();
}

bool CRelayResultSet::MoreRows()
{
    return m_curRow < m_rowCount;
}

ISQLRow *CRelayResultSet::FetchRow()
{
    if (m_curRow >= m_rowCount)
    {
        // Same quirk as the original implementation: park one past the end so
        // CurrentRow() reports NULL.
        m_curRow = m_rowCount + 1;
        return nullptr;
    }
    m_curRow++;
    return this;
}

ISQLRow *CRelayResultSet::CurrentRow()
{
    if (!HasCurrentRow())
    {
        return nullptr;
    }
    return this;
}

bool CRelayResultSet::Rewind()
{
    m_curRow = 0;
    return true;
}

int CRelayResultSet::GetFieldType(unsigned int field)
{
    if (field >= m_colCount)
    {
        return MM_MYSQL_TYPE_UNKNOWN;
    }
    return (int)m_columns[field].type;
}

const char *CRelayResultSet::GetString(unsigned int columnId, size_t *length)
{
    uint32_t index = CellIndex(columnId);
    const char *text = CellText(index);

    if (length)
    {
        *length = (text && index != kNullCell) ? m_lengths[index] : 0;
    }

    return text;
}

size_t CRelayResultSet::GetDataSize(unsigned int columnId)
{
    uint32_t index = CellIndex(columnId);
    if (index == kNullCell || m_lengths[index] == kNullCell)
    {
        return 0;
    }
    return m_lengths[index];
}

float CRelayResultSet::GetFloat(unsigned int columnId)
{
    const char *text = CellText(CellIndex(columnId));
    return text ? (float)atof(text) : 0.0f;
}

int CRelayResultSet::GetInt(unsigned int columnId)
{
    const char *text = CellText(CellIndex(columnId));
    return text ? atoi(text) : 0;
}

int64_t CRelayResultSet::GetInt64(unsigned int columnId)
{
    const char *text = CellText(CellIndex(columnId));
    return text ? atoll(text) : 0;
}

bool CRelayResultSet::IsNull(unsigned int columnId)
{
    uint32_t index = CellIndex(columnId);
    if (index == kNullCell)
    {
        return true;
    }
    return m_lengths[index] == kNullCell;
}

ISQLResult *CRelayStatement::GetResultSet()
{
    if (current >= sets.size())
    {
        return nullptr;
    }
    return sets[current].get();
}

bool CRelayStatement::FetchMoreResults()
{
    if (current + 1 >= sets.size())
    {
        return false;
    }
    current++;
    return true;
}

unsigned int CRelayStatement::GetInsertId()
{
    return insertId;
}

unsigned int CRelayStatement::GetAffectedRows()
{
    return affectedRows;
}
