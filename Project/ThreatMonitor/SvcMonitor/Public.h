/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that app can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_SvcMonitor,
    0xcdc5fdc9,0x7e61,0x44d1,0x8c,0xf5,0xa9,0x3b,0xc5,0x84,0xa6,0x4a);
// {cdc5fdc9-7e61-44d1-8cf5-a93bc584a64a}
