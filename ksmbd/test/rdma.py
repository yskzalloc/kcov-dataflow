#!/usr/bin/env python3
import ctypes, struct, socket, time
librdma = ctypes.CDLL("librdmacm.so.1")
ec = librdma.rdma_create_event_channel()
print(f"ec={ec}")
cm_id = ctypes.c_void_p()
librdma.rdma_create_id(ec, ctypes.byref(cm_id), None, 1)
print(f"cm_id={cm_id.value}")
dst = struct.pack("HH4s8s", socket.AF_INET, socket.htons(445), socket.inet_aton("127.0.0.1"), b"\x00"*8)
src = struct.pack("HH4s8s", socket.AF_INET, 0, socket.inet_aton("127.0.0.1"), b"\x00"*8)
r = librdma.rdma_resolve_addr(cm_id, src, dst, 2000)
print(f"resolve_addr={r}")
if r == 0:
    ev = ctypes.c_void_p()
    r2 = librdma.rdma_get_cm_event(ec, ctypes.byref(ev))
    print(f"get_event={r2}")
    if r2 == 0:
        etype = ctypes.c_int.from_address(ev.value).value
        print(f"event_type={etype} (0=ADDR_RESOLVED, 2=ADDR_ERROR)")
        librdma.rdma_ack_cm_event(ev)
        if etype == 0:
            r3 = librdma.rdma_resolve_route(cm_id, 2000)
            print(f"resolve_route={r3}")
            if r3 == 0:
                ev2 = ctypes.c_void_p()
                r4 = librdma.rdma_get_cm_event(ec, ctypes.byref(ev2))
                print(f"route_event={r4}")
                if r4 == 0:
                    et2 = ctypes.c_int.from_address(ev2.value).value
                    print(f"route_type={et2} (1=ROUTE_RESOLVED)")
                    librdma.rdma_ack_cm_event(ev2)
else:
    print("RESOLVE FAILED")
