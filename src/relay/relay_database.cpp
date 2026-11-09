/**
 * =============================================================================
 * SQLMM relay client
 * =============================================================================
 */

#include "relay_database.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "relay_operations.h"
#include "tier0/dbg.h"

extern std::vector<RelayConnection *> g_vecMysqlConnections;
extern bool g_bInFrame;

namespace
{
const char *CopyString(std::string &dest, const char *src)
{
    if (!src)
    {
        return nullptr;
    }
    dest = src;
    return dest.c_str();
}

// Byte-wise MySQL string escaping.
//
// This replaces mysql_real_escape_string, which cannot be called without a live
// server handle. It is safe for UTF-8/utf8mb4 because no byte of a multi-byte
// sequence is below 0x80, so escaping byte-by-byte never splits a character.
std::string EscapeBytes(const char *input, size_t length, bool noBackslashEscapes)
{
    std::string out;
    out.reserve(length + length / 8 + 1);

    for (size_t i = 0; i < length; i++)
    {
        char c = input[i];

        if (noBackslashEscapes)
        {
            // Only quotes can terminate the string literal in this mode.
            if (c == '\'')
            {
                out += "''";
            }
            else
            {
                out.push_back(c);
            }
            continue;
        }

        switch (c)
        {
            case '\0':
                out += "\\0";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\x1a':
                out += "\\Z";
                break;
            case '\'':
                out += "\\'";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            default:
                out.push_back(c);
                break;
        }
    }

    return out;
}
} // namespace

RelayConnection::RelayConnection(const MySQLConnectionInfo info)
{
    m_info = info;
    m_info.host = CopyString(m_host, info.host);
    m_info.user = CopyString(m_user, info.user);
    m_info.pass = CopyString(m_pass, info.pass);
    m_info.database = CopyString(m_database, info.database);
}

RelayConnection::~RelayConnection()
{
    ConMsg("Destroying MySQL relay connection %s\n", m_info.database ? m_info.database : "");

    if (m_thread)
    {
        {
            std::lock_guard<std::mutex> lock(m_Lock);
            m_Terminate = true;
            m_QueueEvent.notify_all();
        }

        m_thread->join();
        m_thread.reset();
        m_Terminate = false;
    }

    while (!m_ThinkQueue.empty())
    {
        ThreadOperation *op = m_ThinkQueue.front();
        m_ThinkQueue.pop();

        op->CancelThinkPart();
        delete op;
    }

    m_link.Close();
}

void RelayConnection::Connect(ConnectCallbackFunc callback)
{
    TRelayConnectOp *op = new TRelayConnectOp(this, callback);
    AddToThreadQueue(op);
}

void RelayConnection::Query(char *query, QueryCallbackFunc callback)
{
    if (!query)
    {
        return;
    }
    TRelayQueryOp *op = new TRelayQueryOp(this, std::string(query), callback);
    AddToThreadQueue(op);
}

void RelayConnection::Query(const char *query, QueryCallbackFunc callback, ...)
{
    if (!query)
    {
        return;
    }

    va_list args;
    va_start(args, callback);

    va_list vaCopy;
    va_copy(vaCopy, args);
    const int iLen = std::vsnprintf(NULL, 0, query, vaCopy);
    va_end(vaCopy);

    std::vector<char> formatted(iLen > 0 ? (size_t)iLen + 1 : 1);
    std::vsnprintf(formatted.data(), formatted.size(), query, args);
    va_end(args);

    TRelayQueryOp *op = new TRelayQueryOp(this, std::string(formatted.data()), callback);
    AddToThreadQueue(op);
}

void RelayConnection::ExecuteTransaction(Transaction txn, TransactionSuccessCallbackFunc success,
                                         TransactionFailureCallbackFunc failure)
{
    TRelayTransactOp *op = new TRelayTransactOp(this, std::move(txn), success, failure);
    AddToThreadQueue(op);
}

void RelayConnection::Destroy()
{
    if (g_bInFrame)
    {
        m_bDestroyed = true;
        return;
    }

    g_vecMysqlConnections.erase(std::remove(g_vecMysqlConnections.begin(), g_vecMysqlConnections.end(), this),
                                g_vecMysqlConnections.end());
    delete this;
}

void RelayConnection::RunFrame()
{
    if (m_bDestroyed || !m_ThinkQueue.size())
    {
        return;
    }

    ThreadOperation *op;
    {
        std::lock_guard<std::mutex> lock(m_ThinkLock);
        op = m_ThinkQueue.front();
        m_ThinkQueue.pop();
    }

    op->RunThinkPart();
    delete op;
}

void RelayConnection::ThreadRun()
{
    std::unique_lock<std::mutex> lock(m_Lock);

    while (true)
    {
        if (m_threadQueue.empty())
        {
            if (m_Terminate)
            {
                break;
            }

            m_QueueEvent.wait(lock);
            continue;
        }

        ThreadOperation *op = m_threadQueue.front();
        m_threadQueue.pop();

        lock.unlock();
        op->RunThreadPart();

        {
            std::lock_guard<std::mutex> thinkLock(m_ThinkLock);
            m_ThinkQueue.push(op);
        }

        lock.lock();
    }
}

void RelayConnection::AddToThreadQueue(ThreadOperation *threadOperation)
{
    if (!m_thread)
    {
        m_thread = std::unique_ptr<std::thread>(new std::thread(&RelayConnection::ThreadRun, this));
    }

    {
        std::lock_guard<std::mutex> lock(m_Lock);
        m_threadQueue.push(threadOperation);
        m_QueueEvent.notify_one();
    }
}

std::string RelayConnection::Escape(const char *string)
{
    if (!string)
    {
        return std::string();
    }
    return EscapeBytes(string, strlen(string), (Features() & Relay::FeatureNoBackslashEscapes) != 0);
}

std::string RelayConnection::Escape(char *string)
{
    return Escape(static_cast<const char *>(string));
}
