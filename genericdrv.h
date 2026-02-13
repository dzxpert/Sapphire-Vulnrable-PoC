/**
 * genericdrv.h - Interface for genericdrv kernel driver
 * 
 * This driver provides direct access to:
 * - Physical memory (read/write)
 * - I/O ports (read/write)
 * - PCI configuration space
 * 
 * WARNING: This driver is extremely dangerous and can cause system instability,
 * data corruption, or security vulnerabilities. Use only in controlled environments.
 */

#ifndef GENERICDRV_H
#define GENERICDRV_H

#include <windows.h>

// Device name for CreateFile
#define GENERICDRV_DEVICE_NAME "\\\\.\\genericdrv"

// IOCTL code construction macro
#define GENERICDRV_DEVICE_TYPE 0xFA00

#define CTL_CODE_GENERICDRV(function) \
    CTL_CODE(GENERICDRV_DEVICE_TYPE, function, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IOCTL Codes (verified from driver disassembly)
#define IOCTL_GENERICDRV_UNKNOWN_1      CTL_CODE_GENERICDRV(0xBB8)  // 0xFA002EE0
#define IOCTL_GENERICDRV_UNKNOWN_2      CTL_CODE_GENERICDRV(0xBB9)  // 0xFA002EE4
#define IOCTL_GENERICDRV_UNKNOWN_3      CTL_CODE_GENERICDRV(0xBBA)  // 0xFA002EE8 (returns error)
#define IOCTL_GENERICDRV_READ_MEMORY    CTL_CODE_GENERICDRV(0xBBB)  // 0xFA002EEC
#define IOCTL_GENERICDRV_WRITE_MEMORY   CTL_CODE_GENERICDRV(0xBBC)  // 0xFA002EF0
#define IOCTL_GENERICDRV_UNKNOWN_4      CTL_CODE_GENERICDRV(0xBBE)  // 0xFA002EF8 (returns error)
#define IOCTL_GENERICDRV_ADVANCED_IO    CTL_CODE_GENERICDRV(0xBBF)  // 0xFA002EFC
#define IOCTL_GENERICDRV_PCI_CONFIG_DWORD CTL_CODE_GENERICDRV(0xBC0)  // 0xFA002F00
#define IOCTL_GENERICDRV_VERSION        CTL_CODE_GENERICDRV(0xBC2)  // 0xFA002F08 (CORRECT! Returns 393221)
#define IOCTL_GENERICDRV_UNKNOWN_5      CTL_CODE_GENERICDRV(0xBC4)  // 0xFA002F10
#define IOCTL_GENERICDRV_PCI_CONFIG_WORD  CTL_CODE_GENERICDRV(0xBC5)  // 0xFA002F14
#define IOCTL_GENERICDRV_UNKNOWN_6      CTL_CODE_GENERICDRV(0xBCB)  // 0xFA002F2C (returns error)
#define IOCTL_GENERICDRV_REGISTER_DEVICE  CTL_CODE_GENERICDRV(0xBCD)  // 0xFA002F34 (CORRECT! Enables memory/IO)
#define IOCTL_GENERICDRV_CLEANUP        CTL_CODE_GENERICDRV(0xBCE)  // 0xFA002F38

// Valid handle IDs (hardcoded in driver)
#define HANDLE_ID_0     178     // 0xB2
#define HANDLE_ID_1     3232    // 0xCA0
#define HANDLE_ID_2     3234    // 0xCA2
#define HANDLE_ID_3     3235    // 0xCA3
#define HANDLE_ID_4     3236    // 0xCA4
#define HANDLE_ID_5     3240    // 0xCA8
#define HANDLE_ID_6     3244    // 0xCAC

// Access types for read/write operations
#define ACCESS_TYPE_BYTE    0
#define ACCESS_TYPE_WORD    1
#define ACCESS_TYPE_DWORD   2

// Operation types for advanced I/O
#define ADVANCED_IO_WRITE   0
#define ADVANCED_IO_READ    3

// Request structure for memory/port read operations (16 bytes)
typedef struct _GENERICDRV_READ_REQUEST {
    DWORD HandleId;         // Offset 0: Valid handle ID
    DWORD Address;          // Offset 4: Physical address or I/O port
    DWORD AccessType;       // Offset 8: 0=byte, 1=word, 2=dword
    DWORD Value;            // Offset 12: Output - read value
} GENERICDRV_READ_REQUEST, *PGENERICDRV_READ_REQUEST;

// Request structure for memory/port write operations (16 bytes)
typedef struct _GENERICDRV_WRITE_REQUEST {
    DWORD HandleId;         // Offset 0: Valid handle ID
    DWORD Address;          // Offset 4: Physical address or I/O port
    DWORD AccessType;       // Offset 8: 0=byte, 1=word, 2=dword
    DWORD Value;            // Offset 12: Input - value to write
} GENERICDRV_WRITE_REQUEST, *PGENERICDRV_WRITE_REQUEST;

// Request structure for advanced I/O operations (22 bytes)
typedef struct _GENERICDRV_ADVANCED_IO_REQUEST {
    DWORD HandleId;         // Offset 0: Valid handle ID
    DWORD Address;          // Offset 4: Physical address or I/O port
    DWORD OperationType;    // Offset 8: 0=write, 3=read
    WORD Port;              // Offset 12: Port number for bulk operations
    WORD Reserved;          // Offset 14: Padding
    DWORD Count;            // Offset 16: Count for bulk operations
    WORD Result;            // Offset 20: Output result
} GENERICDRV_ADVANCED_IO_REQUEST, *PGENERICDRV_ADVANCED_IO_REQUEST;

// Request structure for PCI configuration access (38 bytes)
typedef struct _GENERICDRV_PCI_REQUEST {
    DWORD HandleId;         // Offset 0: Valid handle ID
    DWORD Parameter;        // Offset 4: PCI parameter
    WORD Result;            // Offset 8: Output result
    BYTE Data[28];          // Offset 10: Additional data
} GENERICDRV_PCI_REQUEST, *PGENERICDRV_PCI_REQUEST;

// Request structure for device registration (62 bytes)
typedef struct _GENERICDRV_REGISTER_REQUEST {
    WORD DeviceId;          // Offset 0: Device ID to register
    WORD Reserved1;         // Offset 2: Padding
    DWORD Reserved2;        // Offset 4: Reserved
    BYTE DeviceInfo[54];    // Offset 8: Device information
} GENERICDRV_REGISTER_REQUEST, *PGENERICDRV_REGISTER_REQUEST;

// Version structure (4 bytes)
typedef struct _GENERICDRV_VERSION {
    DWORD Version;          // Driver version (393221 / 0x60005)
} GENERICDRV_VERSION, *PGENERICDRV_VERSION;

// Helper function prototypes
HANDLE GenericDrv_Open(void);
void GenericDrv_Close(HANDLE hDevice);
BOOL GenericDrv_RegisterDevice(HANDLE hDevice, WORD deviceId);
BOOL GenericDrv_GetVersion(HANDLE hDevice, DWORD* pVersion);
BOOL GenericDrv_ReadPhysicalMemory(HANDLE hDevice, DWORD handleId, DWORD address, DWORD accessType, DWORD* pValue);
BOOL GenericDrv_WritePhysicalMemory(HANDLE hDevice, DWORD handleId, DWORD address, DWORD accessType, DWORD value);
BOOL GenericDrv_ReadIOPort(HANDLE hDevice, DWORD handleId, DWORD port, DWORD accessType, DWORD* pValue);
BOOL GenericDrv_WriteIOPort(HANDLE hDevice, DWORD handleId, DWORD port, DWORD accessType, DWORD value);

// Inline helper implementations
static inline HANDLE GenericDrv_Open(void) {
    return CreateFileA(
        GENERICDRV_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
}

static inline void GenericDrv_Close(HANDLE hDevice) {
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
    }
}

// Register device - MUST be called before memory/IO operations!
static inline BOOL GenericDrv_RegisterDevice(HANDLE hDevice, WORD deviceId) {
    GENERICDRV_REGISTER_REQUEST request = {0};
    GENERICDRV_REGISTER_REQUEST response = {0};
    DWORD bytesReturned = 0;
    
    request.DeviceId = deviceId;
    
    return DeviceIoControl(
        hDevice,
        IOCTL_GENERICDRV_REGISTER_DEVICE,
        &request,
        sizeof(request),
        &response,  // Driver expects output buffer!
        sizeof(response),
        &bytesReturned,
        NULL
    );
}

static inline BOOL GenericDrv_GetVersion(HANDLE hDevice, DWORD* pVersion) {
    DWORD bytesReturned = 0;
    GENERICDRV_VERSION version = {0};
    
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_GENERICDRV_VERSION,
        NULL,
        0,
        &version,
        sizeof(version),
        &bytesReturned,
        NULL
    );
    
    if (result && pVersion) {
        *pVersion = version.Version;
    }
    
    return result;
}

static inline BOOL GenericDrv_ReadPhysicalMemory(
    HANDLE hDevice,
    DWORD handleId,
    DWORD address,
    DWORD accessType,
    DWORD* pValue
) {
    GENERICDRV_READ_REQUEST request = {0};
    DWORD bytesReturned = 0;
    
    request.HandleId = handleId;
    request.Address = address;
    request.AccessType = accessType;
    
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_GENERICDRV_READ_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );
    
    if (result && pValue) {
        *pValue = request.Value;
    }
    
    return result;
}

static inline BOOL GenericDrv_WritePhysicalMemory(
    HANDLE hDevice,
    DWORD handleId,
    DWORD address,
    DWORD accessType,
    DWORD value
) {
    GENERICDRV_WRITE_REQUEST request = {0};
    DWORD bytesReturned = 0;
    
    request.HandleId = handleId;
    request.Address = address;
    request.AccessType = accessType;
    request.Value = value;
    
    return DeviceIoControl(
        hDevice,
        IOCTL_GENERICDRV_WRITE_MEMORY,
        &request,
        sizeof(request),
        NULL,
        0,
        &bytesReturned,
        NULL
    );
}

static inline BOOL GenericDrv_ReadIOPort(
    HANDLE hDevice,
    DWORD handleId,
    DWORD port,
    DWORD accessType,
    DWORD* pValue
) {
    return GenericDrv_ReadPhysicalMemory(hDevice, handleId, port, accessType, pValue);
}

static inline BOOL GenericDrv_WriteIOPort(
    HANDLE hDevice,
    DWORD handleId,
    DWORD port,
    DWORD accessType,
    DWORD value
) {
    return GenericDrv_WritePhysicalMemory(hDevice, handleId, port, accessType, value);
}

#endif // GENERICDRV_H
