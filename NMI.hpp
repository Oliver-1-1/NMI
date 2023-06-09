typedef ULONG KEPROCESSORINDEX; /**< Bitmap indexes != process numbers, apparently. */
typedef struct _KAFFINITY_EX
{
	USHORT Count;
	USHORT Size;
	ULONG Reserved;
	ULONGLONG Bitmap[20];

} KAFFINITY_EX, * PKAFFINITY_EX;

EXTERN_C NTSYSAPI BOOLEAN  NTAPI KeInterlockedSetProcessorAffinityEx(PKAFFINITY_EX pAffinity, KEPROCESSORINDEX idxProcessor);

NTSTATUS NmiDisable(PVOID ntoskrnl) {
    PUCHAR KiNmiInProgress = NULL;

    KiNmiInProgress = (PUCHAR)util::FindPattern(ntoskrnl, "\x81\x25\x00\x00\x00\x00\x00\x00\x00\x00\xB9\x00\x00\x00\x00", "xx????????x????");

    if (KiNmiInProgress){
        SIZE_T read = 0;
        UCHAR dummy;
        MM_COPY_ADDRESS address;
        address.VirtualAddress = (void*)KiNmiInProgress;

        if (!NT_SUCCESS(MmCopyMemory(&dummy, address, sizeof(UCHAR), MM_COPY_MEMORY_VIRTUAL, &read))) return STATUS_UNSUCCESSFUL;
        
        while (dummy != 0x48){
            ++KiNmiInProgress;
            address.VirtualAddress = (void*)KiNmiInProgress;
            if (!NT_SUCCESS(MmCopyMemory(&dummy, address, sizeof(UCHAR), MM_COPY_MEMORY_VIRTUAL, &read))) return STATUS_UNSUCCESSFUL;
        }

        KiNmiInProgress = reinterpret_cast<PUCHAR>(util::ResolveRelativeAddress(KiNmiInProgress, 3, 7));

        for (int i = 0; i < KeQueryActiveProcessorCountEx(0); i++){
            KeInterlockedSetProcessorAffinityEx((PKAFFINITY_EX)KiNmiInProgress, i);
        }
        
    }

    return STATUS_SUCCESS;
}

typedef union {
	struct {
		UCHAR NmiActive;
		UCHAR MceActive;
	};
	USHORT CombinedNmiMceActive;
} NMIACTIVE;
UCHAR IsNmiActive() {
	ULONG_PTR prcb = __readgsqword(0x20);
	NMIACTIVE s = *(NMIACTIVE*)(prcb + 0x7BE6);
	return s.NmiActive; // Should return 0 or 1
}
