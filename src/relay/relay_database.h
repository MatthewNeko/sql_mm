/**
 * =============================================================================
 * SQLMM relay client
 *
 * IMySQLConnection implementation backed by the relay server instead of
 * libmysqlclient. The public interface is untouched, so consumers of
 * ISQLInterface do not notice the change.
 *
 * Threading is the same shape as the old direct path: the game thread only
 * enqueues work, a per-connection worker thread does the I/O, and the result
 * callback runs from RunFrame() on the game thread.
 * =============================================================================
 */

#pragma once

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

#include "common/database.h"
#include "public/mysql_mm.h"
#include "relay_link.h"

class RelayConnection : public IMySQLConnection
{
public:
    explicit RelayConnection(const MySQLConnectionInfo info);
    // ISQLConnection has no virtual destructor, so this cannot be an override.
    ~RelayConnection();

    void Connect(ConnectCallbackFunc callback) override;
    void Query(char *query, QueryCallbackFunc callback) override;
    void Query(const char *query, QueryCallbackFunc callback, ...) override;
    void ExecuteTransaction(Transaction txn, TransactionSuccessCallbackFunc success, TransactionFailureCallbackFunc failure) override;
    void Destroy() override;
    std::string Escape(char *string) override;
    std::string Escape(const char *string) override;

    void RunFrame();

    bool IsDestroyed() const
    {
        return m_bDestroyed;
    }

    // Set by Destroy() when called from inside a frame; RunFrame's caller
    // deletes the object at the end of the frame.
    void MarkDestroyed()
    {
        m_bDestroyed = true;
    }

    bool IsConnected() const
    {
        return m_bConnected.load(std::memory_order_relaxed);
    }

    void SetConnected(bool connected)
    {
        m_bConnected.store(connected, std::memory_order_relaxed);
    }

    uint32_t Features() const
    {
        return m_features.load(std::memory_order_relaxed);
    }

    void SetFeatures(uint32_t features)
    {
        m_features.store(features, std::memory_order_relaxed);
    }

    RelayLink &Link()
    {
        return m_link;
    }

    const MySQLConnectionInfo &Info() const
    {
        return m_info;
    }

    uint32_t NextRequestId()
    {
        return ++m_requestId;
    }

    // Public in the original design; callers only read it.
    MySQLConnectionInfo m_info;

private:
    void ThreadRun();
    void AddToThreadQueue(ThreadOperation *threadOperation);

    std::queue<ThreadOperation *> m_threadQueue;
    std::queue<ThreadOperation *> m_ThinkQueue;
    std::unique_ptr<std::thread> m_thread;
    std::condition_variable m_QueueEvent;
    std::mutex m_Lock;
    std::mutex m_ThinkLock;
    bool m_Terminate = false;

    std::atomic<bool> m_bDestroyed { false };
    std::atomic<bool> m_bConnected { false };
    std::atomic<uint32_t> m_features { 0 };
    uint32_t m_requestId = 0;

    RelayLink m_link;

    // Backing storage for the pointers in m_info, which callers expect to stay
    // valid for the connection's lifetime.
    std::string m_host;
    std::string m_user;
    std::string m_pass;
    std::string m_database;
};
