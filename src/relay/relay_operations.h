/**
 * =============================================================================
 * SQLMM relay client
 *
 * Threaded operations, one per public API call. Each runs its socket I/O on the
 * connection's worker thread and hands the result to the game thread through
 * the think queue, exactly like the old TMySQL*Op classes.
 * =============================================================================
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "relay_database.h"
#include "relay_result.h"

class TRelayConnectOp : public ThreadOperation
{
public:
    TRelayConnectOp(RelayConnection *con, ConnectCallbackFunc callback) : m_pCon(con), m_callback(callback) {}

    void RunThreadPart() override;
    void RunThinkPart() override;
    void CancelThinkPart() override;

private:
    RelayConnection *m_pCon;
    ConnectCallbackFunc m_callback;
    std::string m_error;
    bool m_ok = false;
};

class TRelayQueryOp : public ThreadOperation
{
public:
    TRelayQueryOp(RelayConnection *con, std::string query, QueryCallbackFunc callback)
        : m_pCon(con), m_szQuery(std::move(query)), m_callback(callback)
    {
    }

    void RunThreadPart() override;
    void RunThinkPart() override;
    void CancelThinkPart() override;

private:
    RelayConnection *m_pCon;
    std::string m_szQuery;
    QueryCallbackFunc m_callback;
    std::unique_ptr<CRelayStatement> m_pStatement;
    std::string m_error;
};

class TRelayTransactOp : public ThreadOperation
{
public:
    TRelayTransactOp(RelayConnection *con, Transaction txn, TransactionSuccessCallbackFunc success,
                     TransactionFailureCallbackFunc failure)
        : m_pCon(con), m_txn(std::move(txn)), m_successCallback(success), m_failureCallback(failure)
    {
    }

    void RunThreadPart() override;
    void RunThinkPart() override;
    void CancelThinkPart() override;

private:
    RelayConnection *m_pCon;
    Transaction m_txn;
    TransactionSuccessCallbackFunc m_successCallback;
    TransactionFailureCallbackFunc m_failureCallback;

    std::vector<std::unique_ptr<CRelayStatement>> m_statements;
    std::vector<ISQLQuery *> m_queryPtrs;

    std::string m_error;
    int32_t m_failIndex = -1;

    void FreeQueries();
};
