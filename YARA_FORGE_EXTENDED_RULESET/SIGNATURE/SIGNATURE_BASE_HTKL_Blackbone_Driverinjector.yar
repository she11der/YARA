import "pe"

rule SIGNATURE_BASE_HTKL_Blackbone_Driverinjector : FILE
{
	meta:
		description = "Detects BlackBone Driver injector"
		author = "Florian Roth (Nextron Systems)"
		id = "0d992a6c-c57a-5895-af0d-9c167d922601"
		date = "2018-09-11"
		modified = "2023-12-05"
		reference = "https://github.com/DarthTon/Blackbone"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L4484-L4510"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d6a5f02a465ea46892e1de54a3482aace387ab0d2cdb949e263ce63f4f9edbb7"
		score = 60
		quality = 85
		tags = "FILE"
		hash1 = "8062a4284c719412270614458150cb4abbdf77b2fc35f770ce9c45d10ccb1f4d"
		hash2 = "2d2fc27200c22442ac03e2f454b6e1f90f2bbc17017f05b09f7824fac6beb14b"
		hash3 = "e45da157483232d9c9c72f44b13fca2a0d268393044db00104cc1afe184ca8d1"

	strings:
		$s1 = "=INITtH=PAGEtA" fullword ascii
		$s2 = "BBInjectDll" fullword ascii
		$s3 = "LdrLoadDll" fullword ascii
		$s4 = "\\??\\pipe\\%ls" fullword wide
		$s5 = "Failed to retrieve Kernel base address. Aborting" fullword ascii
		$x2 = "BlackBone: %s: APC injection failed with status 0x%X" fullword ascii
		$x3 = "BlackBone: PDE_BASE/PTE_BASE not found " fullword ascii
		$x4 = "%s: Invalid injection type specified - %d" fullword ascii
		$x6 = "Trying to map C:\\windows\\system32\\cmd.exe into current process" fullword wide
		$x7 = "\\BlackBoneDrv\\bin\\" ascii
		$x8 = "DosDevices\\BlackBone" wide

	condition:
		uint16(0)==0x5a4d and filesize <8000KB and (3 of them or 1 of ($x*))
}
