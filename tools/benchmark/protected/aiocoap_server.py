"""aiocoap server fixture with explicit unprotected or OSCORE admission."""
import argparse
import asyncio
import logging
import aiocoap
import aiocoap.credentials
import aiocoap.resource
from aiocoap.oscore_sitewrapper import OscoreSiteWrapper
from context import Context


class Payload(aiocoap.resource.Resource):
    def __init__(self, size, protected):
        super().__init__()
        self.body = bytes(i % 251 for i in range(size))
        self.protected = protected

    async def render_get(self, request):
        if self.protected and not request.remote.authenticated_claims:
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED)
        return aiocoap.Message(code=aiocoap.CONTENT, payload=self.body, content_format=42, etag=b"fixture")


async def serve(args):
    site = aiocoap.resource.Site()
    site.add_resource(("bench",), Payload(args.bytes, bool(args.credentials)))
    if args.credentials:
        credentials = aiocoap.credentials.CredentialsMap()
        credentials["ephemeral-benchmark"] = Context(args.credentials, server=True)
        site = OscoreSiteWrapper(site, credentials)
    context = await aiocoap.Context.create_server_context(site, bind=(args.host, args.port), transports=["simplesocketserver"])
    try:
        await asyncio.get_running_loop().create_future()
    finally:
        await context.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bytes", type=int, required=True)
    parser.add_argument("--credentials")
    parser.add_argument("--uvloop", action="store_true")
    args = parser.parse_args()
    if args.host != "127.0.0.1" or not 1 <= args.bytes <= 1048576 or not 1 <= args.port <= 65535:
        parser.error("loopback fixture bounds")
    logging.basicConfig(level=logging.ERROR)
    if args.uvloop:
        import uvloop
        uvloop.run(serve(args))
    else:
        asyncio.run(serve(args))


if __name__ == "__main__":
    main()
