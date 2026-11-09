/**
 * =============================================================================
 * SQLMM relay client
 * =============================================================================
 */

#include "relay_operations.h"

#include <cstdio>

#include "relay_protocol.h"
#include "sql_mm.h"
#include "tier0/dbg.h"

namespace
{
// Decodes a RESULT or ERROR frame. Returns false with err set for ERROR frames
// and for anything malformed.
bool ParseResponseFrame(const std::vector<char> &frame, uint32_t expectedRequestId,
                        std::vector<std::unique_ptr<CRelayStatement>> &out, int32_t &failIndex, std::string &err)
{
    if (frame.empty())
    {
        err = "empty relay response";
        return false;
    }

    Relay::Reader reader(frame.data(), frame.size());

    uint8_t type = 0;
    uint32_t reqId = 0;
    if (!reader.U8(type) || !reader.U32(reqId))
    {
        err = "truncated relay response";
        return false;
    }

    if (type == (uint8_t)Relay::Message::Error)
    {
        uint8_t opcode = 0;
        int32_t index = -1;
        std::string message;
        if (!reader.U8(opcode) || !reader.I32(index) || !reader.Str(message))
        {
            err = "malformed relay error";
            return false;
        }
        failIndex = index;
        err = message.empty() ? "relay reported an unspecified error" : message;
        return false;
    }

    if (type != (uint8_t)Relay::Message::Result)
    {
        err = "unexpected relay response type";
        return false;
    }

    if (reqId != expectedRequestId)
    {
        // Cannot happen with the serialised request/response model; treat it as
        // a desync instead of trusting the payload.
        err = "relay response out of order";
        return false;
    }

    uint16_t stmtCount = 0;
    if (!reader.U16(stmtCount))
    {
        err = "malformed relay result";
        return false;
    }

    out.clear();
    out.reserve(stmtCount);

    for (uint16_t s = 0; s < stmtCount; s++)
    {
        uint64_t insertId = 0;
        uint64_t affectedRows = 0;
        uint16_t setCount = 0;
        if (!reader.U64(insertId) || !reader.U64(affectedRows) || !reader.U16(setCount))
        {
            err = "malformed relay statement";
            return false;
        }

        std::unique_ptr<CRelayStatement> stmt(new CRelayStatement());
        stmt->insertId = (uint32_t)insertId;
        stmt->affectedRows = (uint32_t)affectedRows;

        for (uint16_t rs = 0; rs < setCount; rs++)
        {
            uint16_t colCount = 0;
            if (!reader.U16(colCount))
            {
                err = "malformed relay result set";
                return false;
            }

            std::unique_ptr<CRelayResultSet> set(new CRelayResultSet());

            for (uint16_t c = 0; c < colCount; c++)
            {
                const char *name = nullptr;
                uint32_t nameLen = 0;
                uint16_t colType = 0;
                if (!reader.Str(name, nameLen) || !reader.U16(colType))
                {
                    err = "malformed relay column";
                    return false;
                }
                set->AddColumn(name, nameLen, colType);
            }

            uint32_t rowCount = 0;
            if (!reader.U32(rowCount))
            {
                err = "malformed relay row count";
                return false;
            }

            for (uint32_t r = 0; r < rowCount; r++)
            {
                for (uint16_t c = 0; c < colCount; c++)
                {
                    int32_t cellLen = -1;
                    if (!reader.I32(cellLen))
                    {
                        err = "malformed relay cell";
                        return false;
                    }
                    if (cellLen < 0)
                    {
                        set->AddNullCell();
                        continue;
                    }
                    const char *cell = nullptr;
                    if (!reader.Raw((size_t)cellLen, cell))
                    {
                        err = "truncated relay cell";
                        return false;
                    }
                    set->AddCell(cell, (uint32_t)cellLen);
                }
                set->EndRow();
            }

            stmt->sets.push_back(std::move(set));
        }

        out.push_back(std::move(stmt));
    }

    return true;
}

// Attempts to bring the relay session up. Returns false with err set.
bool EnsureRelaySession(RelayConnection *con, std::string &err)
{
    if (con->Link().IsHandshaked())
    {
        return true;
    }
    if (!con->Link().EnsureSession(con->Info(), err))
    {
        con->SetConnected(false);
        return false;
    }
    con->SetFeatures(con->Link().Features());
    con->SetConnected(true);
    return true;
}
} // namespace

void TRelayConnectOp::RunThreadPart()
{
    // An explicit Connect() means "establish a new session", so drop any
    // existing one instead of short-circuiting on the live handshake.
    m_pCon->Link().Close();
    if (!m_pCon->Link().EnsureSession(m_pCon->Info(), m_error, /*force=*/true))
    {
        m_pCon->SetConnected(false);
        return;
    }
    m_pCon->SetFeatures(m_pCon->Link().Features());
    m_pCon->SetConnected(true);
    m_ok = true;
}

void TRelayConnectOp::RunThinkPart()
{
    if (!m_ok)
    {
        ConMsg("Failed to establish a MySQL connection: %s\n", m_error.c_str());
    }
    if (m_callback)
    {
        m_callback(m_ok);
    }
}

void TRelayConnectOp::CancelThinkPart()
{
    m_callback = nullptr;
}

void TRelayQueryOp::RunThreadPart()
{
    if (!EnsureRelaySession(m_pCon, m_error))
    {
        m_error = "relay session unavailable: " + m_error;
        return;
    }

    uint32_t reqId = m_pCon->NextRequestId();

    Relay::Writer writer(Relay::Message::Query);
    writer.U32(reqId).Str(m_szQuery);

    std::vector<char> response;
    if (!m_pCon->Link().Request(writer.Buffer(), response, m_error))
    {
        m_pCon->SetConnected(false);
        m_error = "relay request failed: " + m_error;
        return;
    }

    std::vector<std::unique_ptr<CRelayStatement>> statements;
    int32_t failIndex = -1;
    if (!ParseResponseFrame(response, reqId, statements, failIndex, m_error))
    {
        return;
    }

    if (!statements.empty())
    {
        m_pStatement = std::move(statements[0]);
    }
}

void TRelayQueryOp::RunThinkPart()
{
    if (!m_pStatement)
    {
        ConMsg("MySQL query error: %s\n", m_error.c_str());
        if (m_callback)
        {
            m_callback(nullptr);
        }
        return;
    }

    if (m_callback)
    {
        m_callback(m_pStatement.get());
    }
}

void TRelayQueryOp::CancelThinkPart()
{
    m_callback = nullptr;
    m_pStatement.reset();
}

void TRelayTransactOp::FreeQueries()
{
    m_queryPtrs.clear();
    m_statements.clear();
}

void TRelayTransactOp::RunThreadPart()
{
    if (!EnsureRelaySession(m_pCon, m_error))
    {
        m_error = "relay session unavailable: " + m_error;
        return;
    }

    if (m_txn.queries.size() > 0xFFFF)
    {
        m_error = "transaction has too many statements";
        return;
    }

    uint32_t reqId = m_pCon->NextRequestId();

    Relay::Writer writer(Relay::Message::Transaction);
    writer.U32(reqId).U16((uint16_t)m_txn.queries.size());
    for (const std::string &query : m_txn.queries)
    {
        writer.Str(query);
    }

    std::vector<char> response;
    if (!m_pCon->Link().Request(writer.Buffer(), response, m_error))
    {
        m_pCon->SetConnected(false);
        m_error = "relay request failed: " + m_error;
        return;
    }

    if (!ParseResponseFrame(response, reqId, m_statements, m_failIndex, m_error))
    {
        return;
    }

    m_queryPtrs.reserve(m_statements.size());
    for (const std::unique_ptr<CRelayStatement> &stmt : m_statements)
    {
        m_queryPtrs.push_back(stmt.get());
    }
}

void TRelayTransactOp::RunThinkPart()
{
    if (!m_error.empty())
    {
        std::string full = "MySQL query error: " + m_error + "\n";
        META_CONPRINTF("TMySQLTransactOp ERROR: %s", full.c_str());
        if (m_failureCallback)
        {
            m_failureCallback(full, m_failIndex);
        }
        return;
    }

    if (m_successCallback)
    {
        m_successCallback(m_queryPtrs);
    }
}

void TRelayTransactOp::CancelThinkPart()
{
    m_successCallback = nullptr;
    m_failureCallback = nullptr;
    FreeQueries();
}
