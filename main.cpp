#include <iostream>
#include <vector>
#include <cstdint>
#include <Windows.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <immintrin.h>
#include <tlhelp32.h>

struct MemoryRegion {
    uintptr_t baseAddress;
    size_t size;
};

bool ReadProcessMemoryEx(HANDLE hProcess, uintptr_t address, void* buffer, size_t size) {
    SIZE_T bytesRead;
    return ReadProcessMemory(
        hProcess,
        reinterpret_cast<LPCVOID>(address),
        buffer,
        size,
        &bytesRead
    );
}

std::vector<MemoryRegion> GetMemoryRegions(HANDLE hProcess) {
    std::vector<MemoryRegion> regions;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address {0};

    while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE)) {
            regions.push_back({
                reinterpret_cast<uintptr_t>(mbi.BaseAddress),
                mbi.RegionSize
            });
        }
        
        address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return regions;
}

template <typename T>
std::vector<uintptr_t> SearchValue(
    HANDLE hProcess,
    T value,
    const std::vector<MemoryRegion>& regionsToSearch
) {
    const size_t maxBufferSize = 4096 * 1024;
    std::vector<uintptr_t> results;
    std::mutex resultsMutex;

    auto searchTask = [&](size_t start, size_t end) {
        std::vector<uint8_t> localBuffer(maxBufferSize);

        for (size_t i = start; i < end; ++i) {
            const auto& region = regionsToSearch[i];

            if (region.size < sizeof(T)) {
                continue;
            }

            size_t bytesRead = std::min(region.size, maxBufferSize);

            if (ReadProcessMemoryEx(hProcess, region.baseAddress, localBuffer.data(), bytesRead)) {
                for (size_t j = 0; j <= bytesRead - sizeof(T); j += sizeof(T)) {
                    T* current = reinterpret_cast<T*>(&localBuffer[j]);
                    if (*current == value) {
                        std::lock_guard<std::mutex> lock(resultsMutex);
                        results.push_back(region.baseAddress + j);
                    }
                }
            }
        }
    };

    const size_t threadCount = std::min<size_t>(
        static_cast<size_t>(std::thread::hardware_concurrency()), 
        regionsToSearch.size()
    );
    std::vector<std::thread> threads;
    size_t chunkSize = regionsToSearch.size() / threadCount;

    for (size_t i {0}; i < threadCount; ++i) {
        size_t start = i * chunkSize;
        size_t end = (i == threadCount - 1) ? regionsToSearch.size() : start + chunkSize;
        threads.emplace_back(searchTask, start, end);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    return results;
}

void WriteResultsToFile(
    const std::string& filename,
    const std::vector<uintptr_t>& results,
    const std::string& message
) {
    std::ofstream outFile(filename, std::ios_base::trunc);  
    if (outFile.is_open()) {
        outFile << message << "\n";
        for (const auto& addr : results) {
            outFile << "0x" << std::hex << addr << std::dec << "\n";
        }

        outFile.close();
    }
}

std::vector<MemoryRegion> FilterRegions(const std::vector<MemoryRegion>& regions) {
    std::vector<MemoryRegion> filtered;

    for (const auto& region : regions) {
        if (region.size > 0x1000) {
            filtered.push_back(region);
        }
    }

    return filtered;
}

int main() {
    auto startTotal = std::chrono::high_resolution_clock::now();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 1;
    }

    PROCESSENTRY32 ProcEntry;
    ProcEntry.dwSize = sizeof(PROCESSENTRY32);

    DWORD processId;
    std::string processName;
    std::cout << "Write process name please...\t";
    std::cin >> processName;
    if (Process32First(hSnapshot, &ProcEntry)) {
        do {
            if (!strcmp(ProcEntry.szExeFile, processName.c_str())) {
                CloseHandle(hSnapshot);
                processId = ProcEntry.th32ProcessID;
                
                break;
            }
        } while (Process32Next(hSnapshot, &ProcEntry));
    }

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        processId
    );

    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << "\n";
        return 1;
    }

    int initialValue {0};
    std::cout << "Enter initial value (e.g. current ammo): ";
    std::cin >> initialValue;

    auto startGetRegions = std::chrono::high_resolution_clock::now();
    std::vector<MemoryRegion> allRegions = GetMemoryRegions(hProcess);
    auto endGetRegions = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsedGetRegions = endGetRegions - startGetRegions;

    auto startFilterRegions = std::chrono::high_resolution_clock::now();
    std::vector<MemoryRegion> filteredRegions = FilterRegions(allRegions);
    auto endFilterRegions = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsedFilterRegions = endFilterRegions - startFilterRegions;

    auto startSearch = std::chrono::high_resolution_clock::now();
    std::vector<uintptr_t> results = SearchValue<int>(hProcess, initialValue, allRegions);
    auto endSearch = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsedSearch = endSearch - startSearch;

    WriteResultsToFile("addresses.txt", results, "Initial search results:");

    std::ofstream resultFile("result.txt", std::ios_base::trunc);
    if (!resultFile.is_open()) {
        std::cerr << "Failed to open result.txt for appending.\n";
        return 1;
    } else {
        resultFile << "Time to get memory regions: " << elapsedGetRegions.count() << " seconds\n";
        resultFile << "Time to filter memory regions: " << elapsedFilterRegions.count() << " seconds\n";
        resultFile << "Time to search initial value: " << elapsedSearch.count() << " seconds\n";
    }

    resultFile.close();

    while (true) {
        int newValue {0};
        std::cout << "Enter new value (e.g. ammo after shot, 0 to exit): ";
        std::cin >> newValue;

        if (newValue == 0) {
            break;
        }

        auto startNarrowSearch = std::chrono::high_resolution_clock::now();
        std::vector<uintptr_t> narrowedResults;

        for (uintptr_t addr : results) {
            int valueAtAddress;
            if (ReadProcessMemoryEx(hProcess, addr, &valueAtAddress, sizeof(valueAtAddress))) {
                if (valueAtAddress == newValue) {
                    narrowedResults.push_back(addr);
                }
            } else {
                continue;
            }
        }

        auto endNarrowSearch = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsedNarrowSearch = endNarrowSearch - startNarrowSearch;

        WriteResultsToFile("addresses.txt", narrowedResults, "Narrowed search results:");
        if (resultFile.is_open()) {
            resultFile << "Time to narrow search: " << elapsedNarrowSearch.count() << " seconds\n";
        }

        if (narrowedResults.empty()) {
            std::cout << "No addresses match the new value.\n";
            break;
        }

        results = narrowedResults;
    }

    resultFile << "Search completed.\n";
    resultFile.close();
}
