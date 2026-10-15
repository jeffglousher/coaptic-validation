/*
 * cmake_coap_defines.h -- optional #defines used for building libcoap
 *
 * Copyright (C) 2024-2025 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_DEFINES_H_
#define COAP_DEFINES_H_

/* Define to 1 to build with Unix socket support. */
#define COAP_AF_UNIX_SUPPORT 1

/* Define to 1 if the library has async separate response support. */
#define COAP_ASYNC_SUPPORT 1

/* Define to 1 if the library has client support. */
#define COAP_CLIENT_SUPPORT 1

/* Define to 1 if the system has small stack size. */
/* #undef COAP_CONSTRAINED_STACK */

/* Define to 1 to build without TCP support. */
#define COAP_DISABLE_TCP 0

/* Define to 1 if the system has epoll support. */
/* #undef COAP_EPOLL_SUPPORT */

/* Define to 1 to build with IPv4 support. */
#define COAP_IPV4_SUPPORT 1

/* Define to 1 to build with IPv6 support. */
#define COAP_IPV6_SUPPORT 1

/* Define to 0-8 for maximum logging level. */
#define COAP_MAX_LOGGING_LEVEL 8

/* Define to 1 if the library has OSCORE support. */
/* #undef COAP_OSCORE_SUPPORT */

/* Define to 1 if the library has proxy support. */
#define COAP_PROXY_SUPPORT 1

/* Define to 1 to build with Q-Block (RFC 9177) support. */
#define COAP_Q_BLOCK_SUPPORT 1

/* Define to 1 if the library has server support. */
#define COAP_SERVER_SUPPORT 1

/* Define to 1 if the library has thread deadlock detection support. */
/* #undef COAP_THREAD_RECURSIVE_CHECK */

/* Define to 1 if the library has thread safe support. */
#define COAP_THREAD_SAFE ON

/* Define to 1 if the system has libgnutls28 */
/* #undef COAP_WITH_LIBGNUTLS */

/* Define to 1 if the system has libmbedtls */
/* #undef COAP_WITH_LIBMBEDTLS */

/* Define to 1 if the system has openssl */
/* #undef COAP_WITH_LIBOPENSSL */

/* Define to 1 if the system has libtinydtls */
/* #undef COAP_WITH_LIBTINYDTLS */

/* Define to 1 if the system has wolfSSL */
/* #undef COAP_WITH_LIBWOLFSSL */

/* Define to 1 if the library is to have observe persistence. */
#define COAP_WITH_OBSERVE_PERSIST 1

/* Define to 1 if the library has WebSockets support. */
#define COAP_WS_SUPPORT 1

#endif /* COAP_DEFINES_H_ */
