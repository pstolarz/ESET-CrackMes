#include <windows.h>

/*
    ESET crackme remote call debugging module.

    Extracted the remote thread code (in the "remote.bin" file) may be debugged
    using this app. The app prepares remote_args struct exactly the same way
    as the crackme and passes it to the remote call.

    (c) 2014 by Piotr Stolarz [pstolarz@o2.pl]
 */

static const char *remote_bin = "remote.bin";

typedef void (*remote_prc_t)(LPVOID);

/*
    Prepare thread_args struct
 */
static LPVOID create_remote_args()
{
    static const UINT8 xored_congrats[] =
        {0x35, 0x31, 0xfa, 0xc8, 0x85, 0x80, 0x24, 0x87,
         0x9b, 0x45, 0xa2, 0xca, 0xde, 0xb5, 0x9d, 0x0a,
         0x77, 0x46, 0x5b, 0x5b, 0x99, 0x7a, 0x63, 0xd3,
         0xe7, 0x4e, 0xe3, 0x99, 0x42, 0x99, 0xfe, 0x4e};

    const size_t sz_remote_args = 0x904;
    UINT8 *remote_args = malloc(sz_remote_args);

    srand(time(NULL));
    memset(remote_args, 0, sz_remote_args);

    if (remote_args)
    {
        HMODULE l_kernel32 = LoadLibrary("kernel32.dll");
        HMODULE l_user32 = LoadLibrary("user32.dll");
        HMODULE l_wininet = LoadLibrary("wininet.dll");

        if (l_kernel32!=NULL && l_user32!=NULL && l_wininet!=NULL)
        {
            FARPROC proc_LoadLibraryA = GetProcAddress(l_kernel32, "LoadLibraryA");
            FARPROC proc_ExitProcess = GetProcAddress(l_kernel32, "ExitProcess");

            FARPROC proc_MessageBoxA = GetProcAddress(l_user32, "MessageBoxA");

            FARPROC proc_InternetOpenA = GetProcAddress(l_wininet, "InternetOpenA");
            FARPROC proc_InternetConnectA = GetProcAddress(l_wininet, "InternetConnectA");
            FARPROC proc_HttpOpenRequestA = GetProcAddress(l_wininet, "HttpOpenRequestA");
            FARPROC proc_HttpSendRequestA = GetProcAddress(l_wininet, "HttpSendRequestA");
            FARPROC proc_InternetReadFile = GetProcAddress(l_wininet, "InternetReadFile");
            FARPROC proc_InternetCloseHandle = GetProcAddress(l_wininet, "InternetCloseHandle");

            if (proc_LoadLibraryA && proc_ExitProcess && proc_MessageBoxA && proc_InternetOpenA &&
                proc_InternetConnectA && proc_HttpOpenRequestA && proc_HttpSendRequestA &&
                proc_InternetReadFile && proc_InternetCloseHandle)
            {
                /* genreate random key-val */
                UINT32 key_val = ((rand()&0xff)<<24) | ((rand()&0xff)<<16) |
                    ((rand()&0xff)<<8) | (rand()&0xff);

                *(UINT16*)(&remote_args[0x0018]) = (UINT16)0x50;

                strcpy((char*)(&remote_args[0x001a]), "localhost");
                strcpy((char*)(&remote_args[0x0119]), "index.php");

                *(UINT32*)(&remote_args[0x0224]) = (UINT32)proc_MessageBoxA;
                *(UINT32*)(&remote_args[0x0228]) = (UINT32)proc_InternetOpenA;
                *(UINT32*)(&remote_args[0x022c]) = (UINT32)proc_LoadLibraryA;
                *(UINT32*)(&remote_args[0x0230]) = (UINT32)proc_InternetConnectA;
                *(UINT32*)(&remote_args[0x0234]) = (UINT32)proc_HttpOpenRequestA;
                *(UINT32*)(&remote_args[0x0238]) = (UINT32)proc_HttpSendRequestA;
                *(UINT32*)(&remote_args[0x023c]) = (UINT32)proc_InternetReadFile;
                *(UINT32*)(&remote_args[0x0240]) = (UINT32)proc_InternetCloseHandle;
                *(UINT32*)(&remote_args[0x0244]) = (UINT32)proc_ExitProcess;

                strcpy((char*)(&remote_args[0x054E]), "THE END.");
                strcpy((char*)(&remote_args[0x05ce]), "wget");
                strcpy((char*)(&remote_args[0x064e]), "Content-Type:application/x-www-form-urlencoded");
                sprintf((char*)(&remote_args[0x06ce]), "key=%08X", key_val);
                strcpy((char*)(&remote_args[0x074e]), "POST");
                strcpy((char*)(&remote_args[0x078e]), "!bw8");
                sprintf((char*)(&remote_args[0x07ee]), "%08X", key_val);
                strcpy((char*)(&remote_args[0x080e]), "wininet.dll");

                memcpy(&remote_args[0x082E], xored_congrats, sizeof(xored_congrats));
                *(UINT32*)(&remote_args[0x0900]) = (UINT32)sizeof(xored_congrats);
            } else printf("Can't resolve export procs\n");
        } else printf("Can't load libraries\n");
    }

    return (LPVOID)remote_args;
}

/*
 */
int main(int argc, char **args)
{
    HANDLE  h_rfile = CreateFile(
        remote_bin, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h_rfile!=INVALID_HANDLE_VALUE)
    {
        HANDLE h_rmap;
        DWORD sz_rfile = GetFileSize(h_rfile, NULL);

        h_rmap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, SEC_COMMIT|PAGE_EXECUTE_READWRITE, 0, sz_rfile, NULL);
        if (h_rmap!=NULL)
        {
            /* Due to some problem with direct mapping of the file with the remote code into the
               memory, the memory is reserved at first and next the file content is copied to it */
            LPVOID map_base = MapViewOfFile(h_rmap, FILE_MAP_WRITE|FILE_MAP_EXECUTE, 0, 0, sz_rfile);
            if (map_base!=NULL)
            {
                DWORD n_read=0;
                if (ReadFile(h_rfile, map_base, sz_rfile, &n_read, NULL) && sz_rfile>0 && n_read==sz_rfile)
                {
                    remote_prc_t remote_prc = (remote_prc_t)map_base;
                    LPVOID remote_args = create_remote_args();
                    if (remote_args) {
                        remote_prc(remote_args);
                        free(remote_args);
                    }
                } else printf("ReadFile() error: %d, bytes read: %d, bytes to read: %d\n",
                    GetLastError(), n_read, sz_rfile);

                UnmapViewOfFile(map_base);
            } else printf("MapViewOfFile() error: %d\n", GetLastError());
        } else printf("CreateFileMapping() error: %d\n", GetLastError());

        CloseHandle(h_rfile);
    } else printf("CreateFile() error: %d\n", GetLastError());

    return 0;
}
