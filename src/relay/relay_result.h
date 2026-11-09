/**
 * =============================================================================
 * SQLMM relay client
 *
 * In-memory result sets. The old direct-connect path kept a MYSQL_RES around
 * and answered accessors from mysql_fetch_row; here every cell arrives in one
 * response frame and is copied into a flat arena. Cell pointers handed out by
 * GetString() point into that arena and stay valid until the query object is
 * destroyed, which is stricter than the old MYSQL_ROW behaviour.
 * =============================================================================
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "public/mysql_mm.h"

struct RelayColumn
{
    std::string name;
    uint16_t type = 0;
};

class CRelayResultSet : public ISQLResult, public ISQLRow
{
public:
    // Marker used in the length array for SQL NULL.
    static constexpr uint32_t kNullCell = 0xFFFFFFFFu;

    void AddColumn(const char *name, uint32_t len, uint16_t type);
    void AddCell(const char *data, uint32_t len);
    void AddNullCell();
    void EndRow();

    // ISQLResult
    int GetRowCount() override;
    int GetFieldCount() override;
    bool FieldNameToNum(const char *name, unsigned int *columnId) override;
    const char *FieldNumToName(unsigned int colId) override;
    bool MoreRows() override;
    ISQLRow *FetchRow() override;
    ISQLRow *CurrentRow() override;
    bool Rewind() override;
    int GetFieldType(unsigned int field) override;
    const char *GetString(unsigned int columnId, size_t *length = nullptr) override;
    size_t GetDataSize(unsigned int columnId) override;
    float GetFloat(unsigned int columnId) override;
    int GetInt(unsigned int columnId) override;
    bool IsNull(unsigned int columnId) override;
    int64_t GetInt64(unsigned int columnId) override;

private:
    bool HasCurrentRow() const
    {
        return m_curRow >= 1 && m_curRow <= m_rowCount;
    }

    // Returns the index into the flat cell arrays for the current row, or
    // kNullCell when the position is invalid.
    uint32_t CellIndex(unsigned int columnId) const;

    const char *CellText(uint32_t index) const;

    std::vector<RelayColumn> m_columns;
    std::string m_blob;
    std::vector<uint32_t> m_offsets;
    std::vector<uint32_t> m_lengths;

    uint32_t m_colCount = 0;
    uint32_t m_rowCount = 0;
    uint32_t m_curRow = 0;
};

class CRelayStatement : public ISQLQuery
{
public:
    std::vector<std::unique_ptr<CRelayResultSet>> sets;

    size_t current = 0;
    uint32_t insertId = 0;
    uint32_t affectedRows = 0;

    // ISQLQuery
    ISQLResult *GetResultSet() override;
    bool FetchMoreResults() override;
    unsigned int GetInsertId() override;
    unsigned int GetAffectedRows() override;
};
