/**
 * =============================================================================
 * SQLMM relay client
 * =============================================================================
 */

#include "relay_client.h"
#include "relay_database.h"

extern std::vector<RelayConnection *> g_vecMysqlConnections;

IMySQLConnection *CRelayClient::CreateMySQLConnection(MySQLConnectionInfo info)
{
    auto connection = new RelayConnection(info);
    g_vecMysqlConnections.push_back(connection);

    return connection;
}
