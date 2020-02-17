///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#ifndef _NDIS_H_

#define _NDIS_H_

#include "Ntddk.h"
#include "Pe.h"

namespace s2e {
namespace windows {

static const uint32_t NDIS_STATUS_SUCCESS = 0;
static const uint32_t NDIS_STATUS_PENDING = STATUS_PENDING;
static const uint32_t NDIS_STATUS_FAILURE = 0xC0000001L;
static const uint32_t NDIS_STATUS_CLOSING = 0xC0010002L;
static const uint32_t NDIS_STATUS_BAD_VERSION = 0xC0010004L;
static const uint32_t NDIS_STATUS_BAD_CHARACTERISTICS = 0xC0010005L;
static const uint32_t NDIS_STATUS_ADAPTER_NOT_FOUND = 0xC0010006L;
static const uint32_t NDIS_STATUS_OPEN_FAILED = 0xC0010007L;
static const uint32_t NDIS_STATUS_UNSUPPORTED_MEDIA = 0xC0010019L;
static const uint32_t NDIS_STATUS_RESOURCES = 0xc000009a;
static const uint32_t NDIS_STATUS_RESOURCE_CONFLICT = 0xc001001E;

static const uint32_t NDIS_STATUS_MEDIA_CONNECT = 0x4001000BL;
static const uint32_t NDIS_STATUS_MEDIA_DISCONNECT = 0x4001000CL;

static const uint32_t OID_GEN_MEDIA_CONNECT_STATUS = 0x00010114;

#define NDIS_ERROR_CODE unsigned long
typedef uint32_t NDIS_HANDLE, *PNDIS_HANDLE;

typedef int NDIS_STATUS, *PNDIS_STATUS; // note default size
typedef UNICODE_STRING32 NDIS_STRING, *PNDIS_STRING;

struct NDIS_PROTOCOL_CHARACTERISTICS32 {
    uint8_t MajorNdisVersion;
    uint8_t MinorNdisVersion;
    uint16_t __align;
    uint32_t Reserved;
    uint32_t OpenAdapterCompleteHandler;
    uint32_t CloseAdapterCompleteHandler;
    uint32_t SendCompleteHandler;
    uint32_t TransferDataCompleteHandler;
    uint32_t ResetCompleteHandler;
    uint32_t RequestCompleteHandler;
    uint32_t ReceiveHandler;
    uint32_t ReceiveCompleteHandler;
    uint32_t StatusHandler;
    uint32_t StatusCompleteHandler;
    NDIS_STRING Name;
    //
    // MajorNdisVersion must be set to 0x04 or 0x05
    // with any of the following members.
    //
    uint32_t ReceivePacketHandler;
    uint32_t BindAdapterHandler;
    uint32_t UnbindAdapterHandler;
    uint32_t PnPEventHandler;
    uint32_t UnloadHandler;

    uint32_t Reserved1[4];
    //
    // MajorNdisVersion must be set to 0x05
    // with any of the following members.
    //
    uint32_t CoSendCompleteHandler;
    uint32_t CoStatusHandler;
    uint32_t CoReceivePacketHandler;
    uint32_t CoAfRegisterNotifyHandler;
} __attribute__((packed));

struct NDIS_COMMON_OPEN_BLOCK32 {
    uint32_t MacHandle;                 // PVOID
    NDIS_HANDLE BindingHandle;          // Miniport's open context
    uint32_t MiniportHandle;            // PNDIS_MINIPORT_BLOCK pointer to the miniport
    uint32_t ProtocolHandle;            // PNDIS_PROTOCOL_BLOCK pointer to our protocol
    NDIS_HANDLE ProtocolBindingContext; // context when calling ProtXX funcs
    uint32_t MiniportNextOpen;          // PNDIS_OPEN_BLOCK used by adapter's OpenQueue
    uint32_t ProtocolNextOpen;          // PNDIS_OPEN_BLOCK used by protocol's OpenQueue
    NDIS_HANDLE MiniportAdapterContext; // context for miniport
    BOOLEAN Reserved1;
    BOOLEAN Reserved2;
    BOOLEAN Reserved3;
    BOOLEAN Reserved4;
    uint32_t BindDeviceName; // PNDIS_STRING
    KSPIN_LOCK Reserved5;
    uint32_t RootDeviceName; // PNDIS_STRING

    //
    // These are referenced by the macros used by protocols to call.
    // All of the ones referenced by the macros are internal NDIS handlers for the
    // miniports
    //
    union {
        uint32_t SendHandler;
        uint32_t WanSendHandler;
    };
    uint32_t TransferDataHandler;

    //
    // These are referenced internally by NDIS
    //
    uint32_t SendCompleteHandler;
    uint32_t TransferDataCompleteHandler;
    uint32_t ReceiveHandler;
    uint32_t ReceiveCompleteHandler;
    uint32_t WanReceiveHandler;
    uint32_t RequestCompleteHandler;

    //
    // NDIS 4.0 extensions
    //
    uint32_t ReceivePacketHandler;
    uint32_t SendPacketsHandler;

    //
    // More Cached Handlers
    //
    uint32_t ResetHandler;
    uint32_t RequestHandler;
    uint32_t ResetCompleteHandler;
    uint32_t StatusHandler;
    uint32_t StatusCompleteHandler;

    //#if defined(NDIS_WRAPPER)
    ULONG Flags;
    LONG References;
    KSPIN_LOCK SpinLock; // guards Closing
    NDIS_HANDLE FilterHandle;
    ULONG ProtocolOptions;
    USHORT CurrentLookahead;
    USHORT ConnectDampTicks;
    USHORT DisconnectDampTicks;
    uint16_t align;
    //
    // These are optimizations for getting to driver routines. They are not
    // necessary, but are here to save a dereference through the Driver block.
    //
    uint32_t WSendHandler;
    uint32_t WTransferDataHandler;

    //
    //  NDIS 4.0 miniport entry-points
    //
    uint32_t WSendPacketsHandler;

    uint32_t CancelSendPacketsHandler;

    //
    //  Contains the wake-up events that are enabled for the open.
    //
    ULONG WakeUpEnable;
    //
    // event to be signalled when close complets
    //
    uint32_t CloseCompleteEvent; // PKEVENT

    uint8_t QC[0x14]; // QUEUED_CLOSE

    LONG AfReferences;

    uint32_t NextGlobalOpen; // PNDIS_OPEN_BLOCK

    //#endif

} __attribute__((packed));

//
// one of these per open on an adapter/protocol
//
struct NDIS_OPEN_BLOCK32 {
    NDIS_COMMON_OPEN_BLOCK32 NdisCommonOpenBlock;

    //#if defined(NDIS_WRAPPER)

    //
    // The stuff below is for CO drivers/protocols. This part is not allocated for
    // CL drivers.
    //
    struct _NDIS_OPEN_CO {
        //
        // this is the list of the call manager opens done on this adapter
        //
        uint32_t NextAf; // struct _NDIS_CO_AF_BLOCK *

        //
        //  NDIS 5.0 miniport entry-points, filled in at open time.
        //
        uint32_t MiniportCoCreateVcHandler;
        uint32_t MiniportCoRequestHandler;

        //
        // NDIS 5.0 protocol completion routines, filled in at RegisterAf/OpenAf
        // time
        //
        uint32_t CoCreateVcHandler;
        uint32_t CoDeleteVcHandler;
        uint32_t CmActivateVcCompleteHandler;
        uint32_t CmDeactivateVcCompleteHandler;
        uint32_t CoRequestCompleteHandler;

        //
        // lists for queuing connections. There is both a queue for currently
        // active connections and a queue for connections that are not active.
        //
        LIST_ENTRY32 ActiveVcHead;
        LIST_ENTRY32 InactiveVcHead;
        LONG PendingAfNotifications;
        uint32_t AfNotifyCompleteEvent; // PKEVENT
    } NDIS_OPEN_CO;
    //#endif
} __attribute__((packed));

struct NDIS_PROTOCOL_BLOCK32 {
    uint32_t OpenQueue;    // PNDIS_OPEN_BLOCK
    uint64_t Ref;          // REFERENCE
    uint32_t DeregEvent;   // PKEVENT
    uint32_t NextProtocol; // Link to next struct _NDIS_PROTOCOL_BLOCK

    NDIS_PROTOCOL_CHARACTERISTICS32 ProtocolCharacteristics; // handler addresses

    uint8_t WorkItem[0x10]; // WORK_QUEUE_ITEM
    uint8_t Mutex[0x20];    // KMUTEX32
    uint32_t MutexOwner;
    uint32_t BindDeviceName;       // UNICODE_STRING
    uint32_t RootDeviceName;       // UNICODE_STRING
    uint32_t AssociatedMiniDriver; // NDIS_M_DRIVER_BLOCK
    uint32_t BindingAdapter;
} __attribute__((packed));

typedef struct _NDIS_MINIPORT_CHARACTERISTICS32 {
    uint8_t MajorNdisVersion;
    uint8_t MinorNdisVersion;
    uint32_t Reserved;
    uint32_t CheckForHangHandler;
    uint32_t DisableInterruptHandler;
    uint32_t EnableInterruptHandler;
    uint32_t HaltHandler;
    uint32_t HandleInterruptHandler;
    uint32_t InitializeHandler;
    uint32_t ISRHandler;
    uint32_t QueryInformationHandler;
    uint32_t ReconfigureHandler;
    uint32_t ResetHandler;
    uint32_t SendHandler;
    uint32_t SetInformationHandler;
    uint32_t TransferDataHandler;
    //
    // Version used is V4.0 or V5.0
    // with following members
    //
    uint32_t ReturnPacketHandler;
    uint32_t SendPacketsHandler;
    uint32_t AllocateCompleteHandler;
    //
    // Version used is V5.0 with the following members
    //
    uint32_t CoCreateVcHandler;
    uint32_t CoDeleteVcHandler;
    uint32_t CoActivateVcHandler;
    uint32_t CoDeactivateVcHandler;
    uint32_t CoSendPacketsHandler;
    uint32_t CoRequestHandler;
    //
    // Version used is V5.1 with the following members
    //
    uint32_t CancelSendPacketsHandler;
    uint32_t PnPEventNotifyHandler;
    uint32_t AdapterShutdownHandler;
} NDIS_MINIPORT_CHARACTERISTICS32, *PNDIS_MINIPORT_CHARACTERISTICS32;

typedef enum _NDIS_PARAMETER_TYPE {
    NdisParameterInteger = 0,
    NdisParameterHexInteger,
    NdisParameterString,
    NdisParameterMultiString,
    NdisParameterBinary,
} NDIS_PARAMETER_TYPE,
    *PNDIS_PARAMETER_TYPE;

typedef struct _NDIS_CONFIGURATION_PARAMETER {
    NDIS_PARAMETER_TYPE ParameterType;
    union {
        uint32_t IntegerData;
        NDIS_STRING StringData;
        BINARY_DATA32 BinaryData;
    } ParameterData;
} NDIS_CONFIGURATION_PARAMETER, *PNDIS_CONFIGURATION_PARAMETER;

typedef enum _NDIS_INTERFACE_TYPE {
    NdisInterfaceInternal = Internal,
    NdisInterfaceIsa = Isa,
    NdisInterfaceEisa = Eisa,
    NdisInterfaceMca = MicroChannel,
    NdisInterfaceTurboChannel = TurboChannel,
    NdisInterfacePci = PCIBus,
    NdisInterfacePcMcia = PCMCIABus,
    NdisInterfaceCBus = CBus,
    NdisInterfaceMPIBus = MPIBus,
    NdisInterfaceMPSABus = MPSABus,
    NdisInterfaceProcessorInternal = ProcessorInternal,
    NdisInterfaceInternalPowerBus = InternalPowerBus,
    NdisInterfacePNPISABus = PNPISABus,
    NdisInterfacePNPBus = PNPBus,
    NdisMaximumInterfaceType
} NDIS_INTERFACE_TYPE,
    *PNDIS_INTERFACE_TYPE;

typedef enum _NDIS_MEDIUM {
    NdisMedium802_3,
    NdisMedium802_5,
    NdisMediumWan,
    NdisMediumDix,
    NdisMediumWirelessWan,
    NdisMediumIrda,
    NdisMediumBpc,
    NdisMediumCoWan,
    NdisMedium1394,
    NdisMediumMax,
} NDIS_MEDIUM,
    *PNDIS_MEDIUM;

typedef NDIS_STATUS (*W_INITIALIZE_HANDLER)(PNDIS_STATUS OpenErrorStatus,           // OUT
                                            /*PUINT*/ uint32_t SelectedMediumIndex, // OUT
                                            PNDIS_MEDIUM MediumArray, uint32_t MediumArraySize,
                                            NDIS_HANDLE MiniportAdapterContext,
                                            NDIS_HANDLE WrapperConfigurationContext);

typedef MDL32 NDIS_BUFFER32;

struct NDIS_PACKET_PRIVATE32 {
    UINT PhysicalCount;
    UINT TotalLength;
    uint32_t Head; // PNDIS_BUFFER
    uint32_t Tail; // PNDIS_BUFFER

    uint32_t Pool; // PNDIS_PACKET_POOL
    UINT Count;
    ULONG Flags;
    BOOLEAN ValidCounts;
    UCHAR NdisPacketFlags;
    USHORT NdisPacketOobOffset;
} __attribute__((packed));

struct NDIS_PACKET32 {
    NDIS_PACKET_PRIVATE32 Private;

    // All sizeofs were PVOID
    union {
        struct {
            UCHAR MiniportReserved[2 * sizeof(uint32_t)];
            UCHAR WrapperReserved[2 * sizeof(uint32_t)];
        };

        struct {
            UCHAR MiniportReservedEx[3 * sizeof(uint32_t)];
            UCHAR WrapperReservedEx[sizeof(uint32_t)];
        };

        struct {
            UCHAR MacReserved[4 * sizeof(uint32_t)];
        };
    };

    uint32_t Reserved[2]; // uintptr_t
                          // UCHAR           ProtocolReserved[1];
} __attribute__((packed));

struct NDIS_PACKET_OOB_DATA32 {
    union {
        uint64_t TimeToSend;
        uint64_t TimeSent;
    };
    uint64_t TimeReceived;
    UINT HeaderSize;
    UINT SizeMediaSpecificInfo;
    uint32_t MediaSpecificInformation; // PVOID

    NDIS_STATUS Status;
} __attribute__((packed));

//
//  NDIS per-packet information.
//
enum NDIS_PER_PACKET_INFO {
    TcpIpChecksumPacketInfo,
    IpSecPacketInfo,
    TcpLargeSendPacketInfo,
    ClassificationHandlePacketInfo,
    NdisReserved,
    ScatterGatherListPacketInfo,
    Ieee8021QInfo,
    OriginalPacketInfo,
    PacketCancelId,
    OriginalNetBufferList,
    CachedNetBufferList,
    ShortPacketPaddingInfo,
    MaxPerPacketInfo
};

struct NDIS_PACKET_EXTENSION32 {
    uint32_t NdisPacketInfo[MaxPerPacketInfo]; // PVOID
} __attribute__((packed));

struct NDIS_MINIPORT_TIMER32 {
    KTIMER32 Timer;
    KDPC32 Dpc;
    uint32_t MiniportTimerFunction; // PNDIS_TIMER_FUNCTION
    uint32_t MiniportTimerContext;  // PVOID
    uint32_t Miniport;              // PNDIS_MINIPORT_BLOCK
    uint32_t NextDeferredTimer;     // struct _NDIS_MINIPORT_TIMER  *
} __attribute__((packed));

/*
lkd> dt ndis!_NDIS_MINIPORT_BLOCK
   +0x000 Signature        : Ptr32 Void
   +0x004 NextMiniport     : Ptr32 _NDIS_MINIPORT_BLOCK
   +0x008 DriverHandle     : Ptr32 _NDIS_M_DRIVER_BLOCK
   +0x00c MiniportAdapterContext : Ptr32 Void
   +0x010 MiniportName     : _UNICODE_STRING
   +0x018 BindPaths        : Ptr32 _NDIS_BIND_PATHS
   +0x01c OpenQueue        : Ptr32 Void
   +0x020 ShortRef         : _REFERENCE
   +0x028 DeviceContext    : Ptr32 Void
   +0x02c Padding1         : UChar
   +0x02d LockAcquired     : UChar
   +0x02e PmodeOpens       : UChar
   +0x02f AssignedProcessor : UChar
   +0x030 Lock             : Uint4B
   +0x034 MediaRequest     : Ptr32 _NDIS_REQUEST
   +0x038 Interrupt        : Ptr32 _NDIS_MINIPORT_INTERRUPT
   +0x03c Flags            : Uint4B
   +0x040 PnPFlags         : Uint4B
   +0x044 PacketList       : _LIST_ENTRY
   +0x04c FirstPendingPacket : Ptr32 _NDIS_PACKET
   +0x050 ReturnPacketsQueue : Ptr32 _NDIS_PACKET
   +0x054 RequestBuffer    : Uint4B
   +0x058 SetMCastBuffer   : Ptr32 Void
   +0x05c PrimaryMiniport  : Ptr32 _NDIS_MINIPORT_BLOCK
   +0x060 WrapperContext   : Ptr32 Void
   +0x064 BusDataContext   : Ptr32 Void
   +0x068 PnPCapabilities  : Uint4B
   +0x06c Resources        : Ptr32 _CM_RESOURCE_LIST
   +0x070 WakeUpDpcTimer   : _NDIS_TIMER
   +0x0b8 BaseName         : _UNICODE_STRING
   +0x0c0 SymbolicLinkName : _UNICODE_STRING
   +0x0c8 CheckForHangSeconds : Uint4B
   +0x0cc CFHangTicks      : Uint2B
   +0x0ce CFHangCurrentTick : Uint2B
   +0x0d0 ResetStatus      : Int4B
   +0x0d4 ResetOpen        : Ptr32 Void
   +0x0d8 EthDB            : Ptr32 _X_FILTER
   +0x0d8 NullDB           : Ptr32 _X_FILTER
   +0x0dc TrDB             : Ptr32 _X_FILTER
   +0x0e0 FddiDB           : Ptr32 _X_FILTER
   +0x0e4 ArcDB            : Ptr32 _ARC_FILTER
   +0x0e8 PacketIndicateHandler : Ptr32     void
   +0x0ec SendCompleteHandler : Ptr32     void
   +0x0f0 SendResourcesHandler : Ptr32     void
   +0x0f4 ResetCompleteHandler : Ptr32     void
   +0x0f8 MediaType        : _NDIS_MEDIUM
   +0x0fc BusNumber        : Uint4B
   +0x100 BusType          : _NDIS_INTERFACE_TYPE
   +0x104 AdapterType      : _NDIS_INTERFACE_TYPE
   +0x108 DeviceObject     : Ptr32 _DEVICE_OBJECT
   +0x10c PhysicalDeviceObject : Ptr32 _DEVICE_OBJECT
   +0x110 NextDeviceObject : Ptr32 _DEVICE_OBJECT
   +0x114 MapRegisters     : Ptr32 _MAP_REGISTER_ENTRY
   +0x118 CallMgrAfList    : Ptr32 _NDIS_AF_LIST
   +0x11c MiniportThread   : Ptr32 Void
   +0x120 SetInfoBuf       : Ptr32 Void
   +0x124 SetInfoBufLen    : Uint2B
   +0x126 MaxSendPackets   : Uint2B
   +0x128 FakeStatus       : Int4B
   +0x12c LockHandler      : Ptr32 Void
   +0x130 pAdapterInstanceName : Ptr32 _UNICODE_STRING
   +0x134 TimerQueue       : Ptr32 _NDIS_MINIPORT_TIMER
   +0x138 MacOptions       : Uint4B
   +0x13c PendingRequest   : Ptr32 _NDIS_REQUEST
   +0x140 MaximumLongAddresses : Uint4B
   +0x144 MaximumShortAddresses : Uint4B
   +0x148 CurrentLookahead : Uint4B
   +0x14c MaximumLookahead : Uint4B
   +0x150 HandleInterruptHandler : Ptr32     void
   +0x154 DisableInterruptHandler : Ptr32     void
   +0x158 EnableInterruptHandler : Ptr32     void
   +0x15c SendPacketsHandler : Ptr32     void
   +0x160 DeferredSendHandler : Ptr32     unsigned char
   +0x164 EthRxIndicateHandler : Ptr32     void
   +0x168 TrRxIndicateHandler : Ptr32     void
   +0x16c FddiRxIndicateHandler : Ptr32     void
   +0x170 EthRxCompleteHandler : Ptr32     void
   +0x174 TrRxCompleteHandler : Ptr32     void
   +0x178 FddiRxCompleteHandler : Ptr32     void
   +0x17c StatusHandler    : Ptr32     void
   +0x180 StatusCompleteHandler : Ptr32     void
   +0x184 TDCompleteHandler : Ptr32     void
   +0x188 QueryCompleteHandler : Ptr32     void
   +0x18c SetCompleteHandler : Ptr32     void
   +0x190 WanSendCompleteHandler : Ptr32     void
   +0x194 WanRcvHandler    : Ptr32     void
   +0x198 WanRcvCompleteHandler : Ptr32     void
   +0x19c NextGlobalMiniport : Ptr32 _NDIS_MINIPORT_BLOCK
   +0x1a0 WorkQueue        : [7] _SINGLE_LIST_ENTRY
   +0x1bc SingleWorkItems  : [6] _SINGLE_LIST_ENTRY
   +0x1d4 SendFlags        : UChar
   +0x1d5 TrResetRing      : UChar
   +0x1d6 ArcnetAddress    : UChar
   +0x1d7 XState           : UChar
   +0x1d8 ArcBuf           : Ptr32 _NDIS_ARC_BUF
   +0x1d8 BusInterface     : Ptr32 Void
   +0x1dc Log              : Ptr32 _NDIS_LOG
   +0x1e0 SlotNumber       : Uint4B
   +0x1e4 AllocatedResources : Ptr32 _CM_RESOURCE_LIST
   +0x1e8 AllocatedResourcesTranslated : Ptr32 _CM_RESOURCE_LIST
   +0x1ec PatternList      : _SINGLE_LIST_ENTRY
   +0x1f0 PMCapabilities   : _NDIS_PNP_CAPABILITIES
   +0x200 DeviceCaps       : _DEVICE_CAPABILITIES
   +0x240 WakeUpEnable     : Uint4B
   +0x244 CurrentDevicePowerState : _DEVICE_POWER_STATE
   +0x248 pIrpWaitWake     : Ptr32 _IRP
   +0x24c WaitWakeSystemState : _SYSTEM_POWER_STATE
   +0x250 VcIndex          : _LARGE_INTEGER
   +0x258 VcCountLock      : Uint4B
   +0x25c WmiEnabledVcs    : _LIST_ENTRY
   +0x264 pNdisGuidMap     : Ptr32 _NDIS_GUID
   +0x268 pCustomGuidMap   : Ptr32 _NDIS_GUID
   +0x26c VcCount          : Uint2B
   +0x26e cNdisGuidMap     : Uint2B
   +0x270 cCustomGuidMap   : Uint2B
   +0x272 CurrentMapRegister : Uint2B
   +0x274 AllocationEvent  : Ptr32 _KEVENT
   +0x278 BaseMapRegistersNeeded : Uint2B
   +0x27a SGMapRegistersNeeded : Uint2B
   +0x27c MaximumPhysicalMapping : Uint4B
   +0x280 MediaDisconnectTimer : _NDIS_TIMER
   +0x2c8 MediaDisconnectTimeOut : Uint2B
   +0x2ca InstanceNumber   : Uint2B
   +0x2cc OpenReadyEvent   : _NDIS_EVENT
   +0x2dc PnPDeviceState   : _NDIS_PNP_DEVICE_STATE
   +0x2e0 OldPnPDeviceState : _NDIS_PNP_DEVICE_STATE
   +0x2e4 SetBusData       : Ptr32     unsigned long
   +0x2e8 GetBusData       : Ptr32     unsigned long
   +0x2ec DeferredDpc      : _KDPC
   +0x310 NdisStats        : _NDIS_STATS
   +0x328 IndicatedPacket  : [32] Ptr32 _NDIS_PACKET
   +0x3a8 RemoveReadyEvent : Ptr32 _KEVENT
   +0x3ac AllOpensClosedEvent : Ptr32 _KEVENT
   +0x3b0 AllRequestsCompletedEvent : Ptr32 _KEVENT
   +0x3b4 InitTimeMs       : Uint4B
   +0x3b8 WorkItemBuffer   : [6] _NDIS_MINIPORT_WORK_ITEM
   +0x400 SystemAdapterObject : Ptr32 _DMA_ADAPTER
   +0x404 DriverVerifyFlags : Uint4B
   +0x408 OidList          : Ptr32 _OID_LIST
   +0x40c InternalResetCount : Uint2B
   +0x40e MiniportResetCount : Uint2B
   +0x410 MediaSenseConnectCount : Uint2B
   +0x412 MediaSenseDisconnectCount : Uint2B
   +0x414 xPackets         : Ptr32 Ptr32 _NDIS_PACKET
   +0x418 UserModeOpenReferences : Uint4B
   +0x41c SavedSendHandler : Ptr32 Void
   +0x41c SavedWanSendHandler : Ptr32 Void
   +0x420 SavedSendPacketsHandler : Ptr32     void
   +0x424 SavedCancelSendPacketsHandler : Ptr32     void
   +0x428 WSendPacketsHandler : Ptr32     void
   +0x42c MiniportAttributes : Uint4B
   +0x430 SavedSystemAdapterObject : Ptr32 _DMA_ADAPTER
   +0x434 NumOpens         : Uint2B
   +0x436 CFHangXTicks     : Uint2B
   +0x438 RequestCount     : Uint4B
   +0x43c IndicatedPacketsCount : Uint4B
   +0x440 PhysicalMediumType : Uint4B
   +0x444 LastRequest      : Ptr32 _NDIS_REQUEST
   +0x448 DmaAdapterRefCount : Int4B
   +0x44c FakeMac          : Ptr32 Void
   +0x450 LockDbg          : Uint4B
   +0x454 LockDbgX         : Uint4B
   +0x458 LockThread       : Ptr32 Void
   +0x45c InfoFlags        : Uint4B
   +0x460 TimerQueueLock   : Uint4B
   +0x464 ResetCompletedEvent : Ptr32 _KEVENT
   +0x468 QueuedBindingCompletedEvent : Ptr32 _KEVENT
   +0x46c DmaResourcesReleasedEvent : Ptr32 _KEVENT
   +0x470 SavedPacketIndicateHandler : Ptr32     void
   +0x474 RegisteredInterrupts : Uint4B
   +0x478 SGListLookasideList : Ptr32 _NPAGED_LOOKASIDE_LIST
   +0x47c ScatterGatherListSize : Uint4B
   +0x480 WakeUpTimerEvent : Ptr32 _KEVENT
   +0x484 SecurityDescriptor : Ptr32 Void
   +0x488 NumUserOpens     : Uint4B
   +0x48c NumAdminOpens    : Uint4B
   +0x490 Ref              : _ULONG_REFERENCE

*/

static const uint32_t NDIS_COMMON_OPEN_BLOCK_SIZE = 0xbc;
static const uint32_t NDIS_OPEN_BLOCK_SIZE = 0xf4;
static const uint32_t NDIS_PROTOCOL_BLOCK_SIZE = 0xc4;
static const uint32_t NDIS_PROTOCOL_CHARACTERISTICS_SIZE = 0x6c;
static const uint32_t NDIS_MINIPORT_BLOCK_SIZE = 0x494;
static const uint32_t NDIS_M_SEND_COMPLETE_HANDLER_OFFSET = 0xec;
static const uint32_t NDIS_M_STATUS_HANDLER_OFFSET = 0x17c;
} // namespace windows
} // namespace s2e

#endif
