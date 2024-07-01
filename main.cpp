#include <Windows.h>
#include <stdio.h>

int main(void)
{
    /*TODO: 본인 가상머신에 탑재된 x86 PE 파일의 경로로 대체하기*/
    char path_pefile[] = "C:\\abex_crackme1.exe";

    HANDLE hFile = NULL, hFileMap = NULL; /*Win32 API 호출 과정에서 사용되는 변수*/
    LPBYTE lpFileBase = NULL; /*메모리에 매핑된 파일 컨텐츠의 위치*/
    DWORD dwSize = 0; /*PE 파일 사이즈*/

    PIMAGE_DOS_HEADER pDosHeader = NULL; /*DOS 헤더 구조체의 포인터*/
    PIMAGE_NT_HEADERS pNtHeader = NULL; /*NT 헤더 구조체의 포인터*/

    hFile = CreateFileA(path_pefile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        /*실습 중 여기에 진입하게 된다면,
        * 콘솔에서 출력되는 에러 코드를 확인한 뒤 MSDN
        "https://learn.microsoft.com/ko-kr/windows/win32/debug/system-error-codes--0-499-"
        에서 에러 코드의 의미를 확인해 볼 것.*/
        printf("CreateFileA() failed. Error code=%lu\n", GetLastError());
        return GetLastError();
    }
    dwSize = GetFileSize(hFile, 0);
    printf("File size=%lu bytes\n\n", dwSize);

    hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    lpFileBase = (LPBYTE)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, dwSize);
    /*lpFileBase 포인터는 OS에 의해 메모리에 로드된 PE 파일의 가장 첫 바이트를 가리킴*/
    printf("File signature=%c%c\n", lpFileBase[0], lpFileBase[1]);

    pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    printf("Offset to the NT header=%#x\n\n", pDosHeader->e_lfanew);

    pNtHeader = (PIMAGE_NT_HEADERS)(lpFileBase + pDosHeader->e_lfanew);
    printf("OptionalHeader.BaseOfCode=%#x\n", pNtHeader->OptionalHeader.BaseOfCode);
    printf("OptionalHeader.SizeOfCode=%#x\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("OptionalHeader.AddressOfEntryPoint=%#x\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("OptionalHeader.BaseOfData=%#x\n", pNtHeader->OptionalHeader.BaseOfData);
    printf("OptionalHeader.ImageBase=%#x\n\n", pNtHeader->OptionalHeader.ImageBase);

    /*TODO: 여기서부터 코딩 시작*/
    printf("### SECTION INFORMATION ###\n");
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)(&pNtHeader->OptionalHeader) + (pNtHeader->FileHeader.SizeOfOptionalHeader));

    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        printf("%d번째 section: %s\n", i+1, pSectionHeader[i].Name);
        printf("PointerToRawData: %#x \n", pSectionHeader[i].PointerToRawData);
        printf("SizeOfRawData: %#x \n", pSectionHeader[i].SizeOfRawData);
        printf("VirtualAddress: %#x \n", pSectionHeader[i].VirtualAddress);
        printf("VirtualSize: %#x \n\n", pSectionHeader[i].Misc.VirtualSize);
    }

    printf("### IAT ###\n");
    int SectionNum = 0;

    for (int i = pNtHeader->FileHeader.NumberOfSections - 1; i >= 0; i--) {
        if (pSectionHeader[i].VirtualAddress <= pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress) {
            SectionNum = i;
            break;
        }
    }
    
    int RVAtoRAW = pSectionHeader[SectionNum].PointerToRawData - pSectionHeader[SectionNum].VirtualAddress;
    int IATraw = pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress + RVAtoRAW;

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(lpFileBase + IATraw);

    printf("IAT가 저장된 섹션: %s\n", pSectionHeader[SectionNum].Name);
    printf("RVA to RAW: 0x%x->0x%x\n", pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress, IATraw);

    for (int i = 0; pImportDesc[i].Name != NULL; i++) {
        printf("ImportDescriptor[%d].Name=%s\n", i, lpFileBase + pImportDesc[i].Name + RVAtoRAW);

        DWORD ori_rva_raw = pImportDesc[i].OriginalFirstThunk + RVAtoRAW;
        int* ori = (int *)(ori_rva_raw + lpFileBase);

        while (*ori != NULL) {
            printf("  - function name (RVA=0x%x), %s\n", *ori, *ori + lpFileBase + RVAtoRAW + 2);
            ori += 1;
        }
   
    }


    /*Windows로부터 할당받은 리소스를 역순으로 반환*/
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMap);
    CloseHandle(hFile);
    /*main() 함수가 끝까지 실행되었음을 알리기 위해 0을 반환*/
    return 0;
}
