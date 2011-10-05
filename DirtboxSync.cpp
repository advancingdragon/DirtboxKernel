// Dirtbox synchronization primitives

#include "DirtboxEmulator.h"
#include <stdio.h>

#define DIRT_NAME_SIZE 32

// NOTE: The current method of simulating kernel synchronization objects
// with named Windows objects is leaky since objects are never destroyed.
HANDLE Dirtbox::GetDirtObject(PVOID Object)
{
    CHAR ObjectName[DIRT_NAME_SIZE];
    sprintf_s(ObjectName, DIRT_NAME_SIZE, "Dirtbox_%08x", Object);

    PDISPATCHER_HEADER Header = (PDISPATCHER_HEADER)Object;
    switch (Header->Type)
    {
    case EventNotificationObject:
        return CreateEventA(NULL, TRUE, Header->SignalState, ObjectName);
    case EventSynchronizationObject:
        return CreateEventA(NULL, FALSE, Header->SignalState, ObjectName);
    case TimerNotificationObject:
        return CreateWaitableTimerA(NULL, TRUE, ObjectName);
    case TimerSynchronizationObject:
        return CreateWaitableTimerA(NULL, FALSE, ObjectName);
    default:
        return NULL;
    }
}
