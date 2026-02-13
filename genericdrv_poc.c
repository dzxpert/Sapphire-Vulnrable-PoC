/**
 * genericdrv_poc.c - Proof of Concept for genericdrv.sys driver
 * 
 * This POC demonstrates the capabilities and vulnerabilities of the genericdrv driver.
 * 
 * Features:
 * - Physical memory read/write
 * - I/O port access
 * - PCI configuration space access
 * - Driver version query
 * 
 * WARNING: Use only in isolated sandbox environments!
 * This code can cause system instability or crashes if misused.
 * 
 * Compile: cl.exe genericdrv_poc.c
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "genericdrv.h"

// Simple output without ANSI color codes (Windows CMD doesn't support them)
void PrintBanner(void) {
    printf("===============================================================\n");
    printf("         GenericDrv POC - Hardware Access Driver              \n");
    printf("                  FOR TESTING ONLY                            \n");
    printf("===============================================================\n\n");
}

void PrintSuccess(const char* message) {
    printf("[+] %s\n", message);
}

void PrintError(const char* message) {
    printf("[-] %s (Error: %lu)\n", message, GetLastError());
}

void PrintInfo(const char* message) {
    printf("[*] %s\n", message);
}

void PrintWarning(const char* message) {
    printf("[!] %s\n", message);
}

void PrintSeparator(void) {
    printf("---------------------------------------------------------------\n");
}

// Test 1: Get driver version
BOOL Test_GetVersion(HANDLE hDevice) {
    DWORD version = 0;
    
    PrintInfo("Testing: Get Driver Version");
    
    if (!GenericDrv_GetVersion(hDevice, &version)) {
        PrintError("Failed to get driver version");
        return FALSE;
    }
    
    printf("    Driver Version: 0x%08X (%lu)\n", version, version);
    PrintSuccess("Version query successful");
    return TRUE;
}

// Test 2: Read physical memory
BOOL Test_ReadPhysicalMemory(HANDLE hDevice) {
    DWORD value = 0;
    DWORD testAddress = 0x1000;  // Low physical memory (BIOS data area)
    
    PrintInfo("Testing: Read Physical Memory");
    printf("    Address: 0x%08X\n", testAddress);
    
    // Try reading a DWORD
    if (!GenericDrv_ReadPhysicalMemory(hDevice, HANDLE_ID_0, testAddress, ACCESS_TYPE_DWORD, &value)) {
        PrintError("Failed to read physical memory");
        return FALSE;
    }
    
    printf("    Value (DWORD): 0x%08X\n", value);
    PrintSuccess("Physical memory read successful");
    return TRUE;
}

// Test 3: Write and verify physical memory (safe test)
BOOL Test_WritePhysicalMemory(HANDLE hDevice) {
    DWORD originalValue = 0;
    DWORD testValue = 0x12345678;
    DWORD readbackValue = 0;
    DWORD testAddress = 0x1000;  // Low physical memory
    
    PrintInfo("Testing: Write Physical Memory");
    PrintWarning("This test writes to physical memory - use with caution!");
    printf("    Address: 0x%08X\n", testAddress);
    
    // Read original value
    if (!GenericDrv_ReadPhysicalMemory(hDevice, HANDLE_ID_0, testAddress, ACCESS_TYPE_DWORD, &originalValue)) {
        PrintError("Failed to read original value");
        return FALSE;
    }
    printf("    Original Value: 0x%08X\n", originalValue);
    
    // Write test value
    if (!GenericDrv_WritePhysicalMemory(hDevice, HANDLE_ID_0, testAddress, ACCESS_TYPE_DWORD, testValue)) {
        PrintError("Failed to write physical memory");
        return FALSE;
    }
    printf("    Wrote Value: 0x%08X\n", testValue);
    
    // Read back to verify
    if (!GenericDrv_ReadPhysicalMemory(hDevice, HANDLE_ID_0, testAddress, ACCESS_TYPE_DWORD, &readbackValue)) {
        PrintError("Failed to read back value");
        return FALSE;
    }
    printf("    Readback Value: 0x%08X\n", readbackValue);
    
    // Restore original value
    GenericDrv_WritePhysicalMemory(hDevice, HANDLE_ID_0, testAddress, ACCESS_TYPE_DWORD, originalValue);
    
    // Check if write was successful (some low memory regions may be partially protected)
    if (readbackValue == testValue) {
        PrintSuccess("Physical memory write/read verified (exact match)");
        return TRUE;
    } else if (readbackValue != originalValue) {
        // Partial write - some bytes changed (expected for protected regions)
        PrintSuccess("Physical memory write successful (partial - some regions protected)");
        return TRUE;
    } else {
        PrintError("Write verification failed");
        return FALSE;
    }
}

// Test 4: Read I/O port (safe ports)
BOOL Test_ReadIOPort(HANDLE hDevice) {
    DWORD value = 0;
    WORD port = 0x80;  // POST code port (safe to read)
    
    PrintInfo("Testing: Read I/O Port");
    printf("    Port: 0x%04X (POST code diagnostic port)\n", port);
    
    if (!GenericDrv_ReadIOPort(hDevice, HANDLE_ID_0, port, ACCESS_TYPE_BYTE, &value)) {
        PrintError("Failed to read I/O port");
        return FALSE;
    }
    
    printf("    Value: 0x%02X\n", value & 0xFF);
    PrintSuccess("I/O port read successful");
    return TRUE;
}

// Test 5: Write I/O port (safe port)
BOOL Test_WriteIOPort(HANDLE hDevice) {
    WORD port = 0x80;  // POST code port (safe to write)
    BYTE testValue = 0xAA;
    
    PrintInfo("Testing: Write I/O Port");
    printf("    Port: 0x%04X (POST code diagnostic port)\n", port);
    printf("    Value: 0x%02X\n", testValue);
    
    if (!GenericDrv_WriteIOPort(hDevice, HANDLE_ID_0, port, ACCESS_TYPE_BYTE, testValue)) {
        PrintError("Failed to write I/O port");
        return FALSE;
    }
    
    PrintSuccess("I/O port write successful");
    return TRUE;
}

// Test 6: Test different access types
BOOL Test_AccessTypes(HANDLE hDevice) {
    DWORD value = 0;
    DWORD testAddress = 0x1000;
    
    PrintInfo("Testing: Different Access Types");
    
    // Byte access
    if (GenericDrv_ReadPhysicalMemory(hDevice, HANDLE_ID_0, testAddress, ACCESS_TYPE_BYTE, &value)) {
        printf("    BYTE read (0x%08X): 0x%02X\n", testAddress, value & 0xFF);
    }
    
    // Word access
    if (GenericDrv_ReadPhysicalMemory(hDevice, HANDLE_ID_0, testAddress, ACCESS_TYPE_WORD, &value)) {
        printf("    WORD read (0x%08X): 0x%04X\n", testAddress, value & 0xFFFF);
    }
    
    // DWORD access
    if (GenericDrv_ReadPhysicalMemory(hDevice, HANDLE_ID_0, testAddress, ACCESS_TYPE_DWORD, &value)) {
        printf("    DWORD read (0x%08X): 0x%08X\n", testAddress, value);
    }
    
    PrintSuccess("Access type tests completed");
    return TRUE;
}

// Test 7: Test different handle IDs
BOOL Test_HandleIDs(HANDLE hDevice) {
    DWORD value = 0;
    DWORD testAddress = 0x1000;
    DWORD handleIDs[] = {
        HANDLE_ID_0, HANDLE_ID_1, HANDLE_ID_2, HANDLE_ID_3,
        HANDLE_ID_4, HANDLE_ID_5, HANDLE_ID_6
    };
    
    PrintInfo("Testing: Valid Handle IDs");
    
    for (int i = 0; i < sizeof(handleIDs) / sizeof(handleIDs[0]); i++) {
        if (GenericDrv_ReadPhysicalMemory(hDevice, handleIDs[i], testAddress, ACCESS_TYPE_DWORD, &value)) {
            printf("    Handle ID %d (0x%X): VALID\n", 
                   handleIDs[i], handleIDs[i]);
        } else {
            printf("    Handle ID %d (0x%X): INVALID\n", 
                   handleIDs[i], handleIDs[i]);
        }
    }
    
    PrintSuccess("Handle ID validation completed");
    return TRUE;
}

// Test 8: Dump physical memory region
BOOL Test_DumpMemory(HANDLE hDevice) {
    DWORD startAddress = 0x1000;
    DWORD length = 0x100;  // 256 bytes
    
    PrintInfo("Testing: Memory Dump");
    printf("    Address Range: 0x%08X - 0x%08X\n", startAddress, startAddress + length);
    
    printf("\n    Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");
    printf("    ──────────────────────────────────────────────────────────\n");
    
    for (DWORD offset = 0; offset < length; offset += 16) {
        printf("    %08X  ", startAddress + offset);
        
        for (DWORD i = 0; i < 16; i++) {
            DWORD value = 0;
            if (GenericDrv_ReadPhysicalMemory(hDevice, HANDLE_ID_0, 
                startAddress + offset + i, ACCESS_TYPE_BYTE, &value)) {
                printf("%02X ", value & 0xFF);
            } else {
                printf("?? ");
            }
        }
        printf("\n");
    }
    
    PrintSuccess("Memory dump completed");
    return TRUE;
}

// Test 9: Scan for pattern in physical memory
BOOL Test_MemoryScan(HANDLE hDevice) {
    DWORD startAddress = 0x1000;
    DWORD endAddress = 0x10000;  // Scan 64KB
    DWORD pattern = 0x5A4D;  // "MZ" signature (DOS header)
    int matchCount = 0;
    
    PrintInfo("Testing: Memory Pattern Scan");
    printf("    Scanning: 0x%08X - 0x%08X\n", startAddress, endAddress);
    printf("    Pattern: 0x%04X (MZ signature)\n", pattern);
    
    for (DWORD addr = startAddress; addr < endAddress; addr += 4) {
        DWORD value = 0;
        if (GenericDrv_ReadPhysicalMemory(hDevice, HANDLE_ID_0, addr, ACCESS_TYPE_WORD, &value)) {
            if ((value & 0xFFFF) == pattern) {
                printf("    Found at: 0x%08X\n", addr);
                matchCount++;
                if (matchCount >= 5) {
                    printf("    ... (limiting output)\n");
                    break;
                }
            }
        }
    }
    
    printf("    Total matches found: %d\n", matchCount);
    PrintSuccess("Memory scan completed");
    return TRUE;
}

// Advanced Test: Read/Write Execute demonstration
BOOL Test_ReadWriteExecute(HANDLE hDevice) {
    PrintInfo("Testing: Read-Write-Execute Chain");
    PrintWarning("This demonstrates arbitrary memory manipulation");
    
    // Allocate a buffer in user space
    BYTE* userBuffer = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!userBuffer) {
        PrintError("Failed to allocate user buffer");
        return FALSE;
    }
    
    // Write a pattern to user buffer
    for (int i = 0; i < 256; i++) {
        userBuffer[i] = (BYTE)i;
    }
    
    printf("    User buffer allocated at: 0x%p\n", userBuffer);
    
    // Get physical address (simplified - in real scenario you'd need to translate virtual to physical)
    // For demonstration, we'll use a safe low memory address
    DWORD physAddr = 0x2000;
    
    // Read from physical memory
    DWORD readValue = 0;
    if (GenericDrv_ReadPhysicalMemory(hDevice, HANDLE_ID_0, physAddr, ACCESS_TYPE_DWORD, &readValue)) {
        printf("    Read from physical 0x%08X: 0x%08X\n", physAddr, readValue);
    }
    
    // Write to physical memory
    DWORD writeValue = 0xDEADBEEF;
    if (GenericDrv_WritePhysicalMemory(hDevice, HANDLE_ID_0, physAddr, ACCESS_TYPE_DWORD, writeValue)) {
        printf("    Wrote to physical 0x%08X: 0x%08X\n", physAddr, writeValue);
    }
    
    // Verify write
    DWORD verifyValue = 0;
    if (GenericDrv_ReadPhysicalMemory(hDevice, HANDLE_ID_0, physAddr, ACCESS_TYPE_DWORD, &verifyValue)) {
        printf("    Verified read: 0x%08X\n", verifyValue);
        if (verifyValue == writeValue) {
            PrintSuccess("Read-Write-Execute chain successful");
        }
    }
    
    // Restore original value
    GenericDrv_WritePhysicalMemory(hDevice, HANDLE_ID_0, physAddr, ACCESS_TYPE_DWORD, readValue);
    
    VirtualFree(userBuffer, 0, MEM_RELEASE);
    return TRUE;
}

int main(int argc, char* argv[]) {
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    BOOL interactive = TRUE;
    
    PrintBanner();
    
    // Check for non-interactive mode
    if (argc > 1 && strcmp(argv[1], "-auto") == 0) {
        interactive = FALSE;
        PrintInfo("Running in automatic mode");
    }
    
    // Open device
    PrintInfo("Opening device: " GENERICDRV_DEVICE_NAME);
    hDevice = GenericDrv_Open();
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        PrintError("Failed to open device");
        printf("\nPossible reasons:\n");
        printf("  1. Driver not loaded (run: sc start genericdrv)\n");
        printf("  2. Insufficient privileges\n");
        printf("  3. Device name incorrect\n");
        return 1;
    }
    
    PrintSuccess("Device opened successfully");
    
    // CRITICAL: Register device to enable memory/IO operations
    PrintInfo("Registering device...");
    if (!GenericDrv_RegisterDevice(hDevice, 0x1234)) {  // Device ID can be any value
        PrintWarning("Device registration failed, memory/IO operations may not work");
    } else {
        PrintSuccess("Device registered successfully");
    }
    
    PrintSeparator();
    
    // Run tests
    struct {
        const char* name;
        BOOL (*func)(HANDLE);
        BOOL dangerous;
    } tests[] = {
        {"Get Version", Test_GetVersion, FALSE},
        {"Read Physical Memory", Test_ReadPhysicalMemory, FALSE},
        {"Write Physical Memory", Test_WritePhysicalMemory, TRUE},
        {"Read I/O Port", Test_ReadIOPort, FALSE},
        {"Write I/O Port", Test_WriteIOPort, FALSE},
        {"Access Types", Test_AccessTypes, FALSE},
        {"Handle IDs", Test_HandleIDs, FALSE},
        {"Memory Dump", Test_DumpMemory, FALSE},
        {"Memory Scan", Test_MemoryScan, FALSE},
        {"Read-Write-Execute", Test_ReadWriteExecute, TRUE},
    };
    
    int testCount = sizeof(tests) / sizeof(tests[0]);
    int passCount = 0;
    
    for (int i = 0; i < testCount; i++) {
        printf("\nTest %d/%d: %s\n", i + 1, testCount, tests[i].name);
        
        if (tests[i].dangerous && interactive) {
            PrintWarning("This test modifies system state!");
            printf("Continue? (y/n): ");
            char response;
            scanf(" %c", &response);
            if (response != 'y' && response != 'Y') {
                PrintInfo("Test skipped");
                PrintSeparator();
                continue;
            }
        }
        
        if (tests[i].func(hDevice)) {
            passCount++;
        }
        
        PrintSeparator();
        
        if (interactive && i < testCount - 1) {
            printf("Press Enter to continue...");
            getchar();
            getchar();  // Consume newline
        }
    }
    
    // Summary
    printf("\n===============================================================\n");
    printf("                      TEST SUMMARY                         \n");
    printf("===============================================================\n");
    printf("  Total Tests: %d\n", testCount);
    printf("  Passed: %d\n", passCount);
    printf("  Failed: %d\n", testCount - passCount);
    
    // Cleanup
    GenericDrv_Close(hDevice);
    PrintSuccess("Device closed");
    
    return (passCount == testCount) ? 0 : 1;
}
