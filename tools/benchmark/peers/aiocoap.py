"""Independent aiocoap server with no per-request logging or process spawning."""
import argparse
import asyncio
import aiocoap
import aiocoap.resource


class Payload(aiocoap.resource.Resource):
    def __init__(self, size):
        super().__init__()
        self.body = bytes(index % 251 for index in range(size))

    async def render_get(self, request):
        return aiocoap.Message(code=aiocoap.CONTENT, payload=self.body, content_format=42)


async def serve(args):
    site = aiocoap.resource.Site()
    site.add_resource(("bench",), Payload(args.bytes))
    context = await aiocoap.Context.create_server_context(site, bind=(args.host, args.port))
    try:
        await asyncio.get_running_loop().create_future()
    finally:
        await context.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bytes", type=int, required=True)
    parser.add_argument("--uvloop", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.bytes <= 1024 * 1024:
        parser.error("payload outside fixture bounds")
    if args.uvloop:
        import uvloop
        uvloop.run(serve(args))
    else:
        asyncio.run(serve(args))


if __name__ == "__main__":
    main()
