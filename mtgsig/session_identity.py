"""The process-cached m324 collector, with explicit caller-owned lifetime.

Native generates one NSUUID inside dispatch_once, removes its hyphens and
appends the initializing thread flag and the literal '1'. This helper does
not generate randomness or maintain a global cache. Generate once per SDK
session and reuse the result in registration m324 and SIUA['2'][16].
"""
from uuid import UUID


def m324_from_uuid(uuid_value, *, main_thread):
    """Reproduce one initialized m324 value from explicit native inputs.

    ``main_thread`` means the thread that first initializes the native once
    block, not the thread signing a later request. The UUID is independent of
    IDFV, OneID, the local SAK UUID and mtgsig.a1.
    """
    if not isinstance(uuid_value, (str, UUID)):
        raise TypeError("m324 UUID must be text or UUID")
    if type(main_thread) is not bool:
        raise TypeError("m324 main_thread must be bool")
    try:
        value = UUID(str(uuid_value))
    except ValueError:
        raise ValueError("m324 UUID is invalid") from None
    return value.hex.upper() + ("1" if main_thread else "0") + "1"
