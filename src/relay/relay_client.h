/**
 * =============================================================================
 * SQLMM relay client
 *
 * IMySQLClient implementation. Every connection it hands out is a relay
 * session; the plugin never speaks the MySQL wire protocol itself.
 * =============================================================================
 */

#pragma once

#include "public/mysql_mm.h"

class CRelayClient : public IMySQLClient
{
public:
    IMySQLConnection *CreateMySQLConnection(MySQLConnectionInfo info) override;
};
