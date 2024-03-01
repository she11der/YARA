rule SIGNATURE_BASE_Regin_Sample_2 : FILE
{
	meta:
		description = "Auto-generated rule - file hiddenmod_hookdisk_and_kdbg_8949d000.bin"
		author = "@MalwrSignatures"
		id = "1091a598-e964-5f67-9267-531d66831bee"
		date = "2014-11-26"
		modified = "2023-12-15"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_regin_fiveeyes.yar#L175-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a7b285d4b896b66fce0ebfcd15db53b3a74a0400"
		logic_hash = "a11d03d10661c1fc094450b250056196e5d8d16bd171eba9e37c7524aa2301d2"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "\\SYSTEMROOT\\system32\\lsass.exe" wide
		$s1 = "atapi.sys" fullword wide
		$s2 = "disk.sys" fullword wide
		$s3 = "IoGetRelatedDeviceObject" fullword ascii
		$s4 = "HAL.dll" fullword ascii
		$s5 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" ascii
		$s6 = "PsGetCurrentProcessId" fullword ascii
		$s7 = "KeGetCurrentIrql" fullword ascii
		$s8 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
		$s9 = "KeSetImportanceDpc" fullword ascii
		$s10 = "KeQueryPerformanceCounter" fullword ascii
		$s14 = "KeInitializeEvent" fullword ascii
		$s15 = "KeDelayExecutionThread" fullword ascii
		$s16 = "KeInitializeTimerEx" fullword ascii
		$s18 = "PsLookupProcessByProcessId" fullword ascii
		$s19 = "ExReleaseFastMutexUnsafe" fullword ascii
		$s20 = "ExAcquireFastMutexUnsafe" fullword ascii

	condition:
		all of them and filesize <40KB and filesize >30KB
}
