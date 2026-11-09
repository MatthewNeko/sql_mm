/**
 * =============================================================================
 * SQLMM relay client
 * =============================================================================
 */

// rand_s needs this before <stdlib.h> is pulled in, and <cstdio> does that on
// MSVC. Defining it first is the only reliable order.
#ifdef _WIN32
#define _CRT_RAND_S
#endif

#include "relay_socket.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace
{
constexpr size_t kMaxChunk = 1u << 20;

size_t ChunkSize(size_t remaining)
{
    return remaining > kMaxChunk ? kMaxChunk : remaining;
}

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;

bool Valid(NativeSocket s)
{
    return s != INVALID_SOCKET;
}

void CloseSocket(NativeSocket s)
{
    closesocket(s);
}

bool WouldBlock()
{
    int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS;
}

void SetNonBlocking(NativeSocket s, bool nonBlocking)
{
    u_long mode = nonBlocking ? 1 : 0;
    ioctlsocket(s, FIONBIO, &mode);
}
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;

bool Valid(NativeSocket s)
{
    return s >= 0;
}

void CloseSocket(NativeSocket s)
{
    ::close(s);
}

bool WouldBlock()
{
    return errno == EINPROGRESS || errno == EWOULDBLOCK || errno == EAGAIN;
}

void SetNonBlocking(NativeSocket s, bool nonBlocking)
{
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0)
    {
        return;
    }
    fcntl(s, F_SETFL, nonBlocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
}
#endif

NativeSocket AsNative(intptr_t s)
{
    return (NativeSocket)s;
}

intptr_t AsHandle(NativeSocket s)
{
    return (intptr_t)s;
}
} // namespace

RelaySocket::~RelaySocket()
{
    Close();
}

bool RelayRandomBytes(void *buf, size_t len)
{
#ifdef _WIN32
    uint8_t *p = (uint8_t *)buf;
    while (len > 0)
    {
        unsigned int value = 0;
        if (rand_s(&value) != 0)
        {
            return false;
        }
        size_t take = len < sizeof(value) ? len : sizeof(value);
        memcpy(p, &value, take);
        p += take;
        len -= take;
    }
    return true;
#else
    int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        return false;
    }
    uint8_t *p = (uint8_t *)buf;
    size_t remaining = len;
    while (remaining > 0)
    {
        ssize_t got = ::read(fd, p, remaining);
        if (got < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            ::close(fd);
            return false;
        }
        if (got == 0)
        {
            ::close(fd);
            return false;
        }
        p += got;
        remaining -= (size_t)got;
    }
    ::close(fd);
    return true;
#endif
}

bool RelaySocket::GlobalInit()
{
#ifdef _WIN32
    static bool initialized = false;
    if (!initialized)
    {
        WSADATA data;
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
        {
            return false;
        }
        initialized = true;
    }
#endif
    return true;
}

void RelaySocket::GlobalShutdown()
{
#ifdef _WIN32
    WSACleanup();
#endif
}

void RelaySocket::Close()
{
    if (m_sock >= 0)
    {
        CloseSocket(AsNative(m_sock));
        m_sock = -1;
    }
}

bool RelaySocket::Connect(const char *host, uint16_t port, int timeoutMs)
{
    Close();

    if (!host || !host[0])
    {
        return false;
    }

    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portStr[16];
    snprintf(portStr, sizeof(portStr), "%u", (unsigned)port);

    addrinfo *results = nullptr;
    if (getaddrinfo(host, portStr, &hints, &results) != 0 || !results)
    {
        return false;
    }

    if (timeoutMs <= 0)
    {
        timeoutMs = 5000;
    }

    for (addrinfo *it = results; it; it = it->ai_next)
    {
        NativeSocket s = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (!Valid(s))
        {
            continue;
        }

        // Blocking connect cannot be given a timeout, so run it non-blocking
        // and wait on select(). Without this a dead relay host hangs the
        // connection's worker thread forever.
        SetNonBlocking(s, true);

        bool connected = false;
        if (::connect(s, it->ai_addr, (int)it->ai_addrlen) == 0)
        {
            connected = true;
        }
        else if (WouldBlock())
        {
            fd_set writeSet;
            FD_ZERO(&writeSet);
            FD_SET(s, &writeSet);

            timeval tv;
            tv.tv_sec = timeoutMs / 1000;
            tv.tv_usec = (timeoutMs % 1000) * 1000;

            int selected = ::select((int)s + 1, nullptr, &writeSet, nullptr, &tv);            if (selected > 0)
            {
                int soError = 0;
#ifdef _WIN32
                int len = sizeof(soError);
#else
                socklen_t len = sizeof(soError);
#endif
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soError, &len) == 0 && soError == 0)
                {
                    connected = true;
                }
            }
        }

        if (!connected)
        {
            CloseSocket(s);
            continue;
        }

        SetNonBlocking(s, false);

        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));

        m_sock = AsHandle(s);
        break;
    }

    freeaddrinfo(results);

    return m_sock >= 0;
}

void RelaySocket::SetTimeouts(int recvMs, int sendMs)
{
    if (m_sock < 0)
    {
        return;
    }

#ifdef _WIN32
    DWORD recvTimeout = (DWORD)recvMs;
    DWORD sendTimeout = (DWORD)sendMs;
    setsockopt(AsNative(m_sock), SOL_SOCKET, SO_RCVTIMEO, (const char *)&recvTimeout, sizeof(recvTimeout));
    setsockopt(AsNative(m_sock), SOL_SOCKET, SO_SNDTIMEO, (const char *)&sendTimeout, sizeof(sendTimeout));
#else
    timeval recvTv;
    recvTv.tv_sec = recvMs / 1000;
    recvTv.tv_usec = (recvMs % 1000) * 1000;
    timeval sendTv;
    sendTv.tv_sec = sendMs / 1000;
    sendTv.tv_usec = (sendMs % 1000) * 1000;
    setsockopt(AsNative(m_sock), SOL_SOCKET, SO_RCVTIMEO, &recvTv, sizeof(recvTv));
    setsockopt(AsNative(m_sock), SOL_SOCKET, SO_SNDTIMEO, &sendTv, sizeof(sendTv));
#endif
}

bool RelaySocket::SendAll(const void *data, size_t len)
{
    if (m_sock < 0)
    {
        return false;
    }

    const char *p = (const char *)data;
    while (len > 0)
    {
        size_t chunk = ChunkSize(len);
#ifdef _WIN32
        int sent = ::send(AsNative(m_sock), p, (int)chunk, 0);
#else
        ssize_t sent = ::send(AsNative(m_sock), p, chunk, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR)
        {
            continue;
        }
#endif
        if (sent <= 0)
        {
            Close();
            return false;
        }
        p += sent;
        len -= (size_t)sent;
    }

    return true;
}

bool RelaySocket::RecvAll(void *data, size_t len)
{
    if (m_sock < 0)
    {
        return false;
    }

    char *p = (char *)data;
    while (len > 0)
    {
        size_t chunk = ChunkSize(len);
#ifdef _WIN32
        int got = ::recv(AsNative(m_sock), p, (int)chunk, 0);
#else
        ssize_t got = ::recv(AsNative(m_sock), p, chunk, 0);
        if (got < 0 && errno == EINTR)
        {
            continue;
        }
#endif
        if (got <= 0)
        {
            Close();
            return false;
        }
        p += got;
        len -= (size_t)got;
    }

    return true;
}
