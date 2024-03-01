import "pe"

rule SIGNATURE_BASE_APT28_CHOPSTICK : FILE
{
	meta:
		description = "Detects a malware that behaves like CHOPSTICK mentioned in APT28 report"
		author = "Florian Roth (Nextron Systems)"
		id = "08bc4cc2-1844-5218-bb89-20a3ac70a951"
		date = "2015-06-02"
		modified = "2023-12-05"
		reference = "https://goo.gl/v3ebal"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt28.yar#L10-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f4db2e0881f83f6a2387ecf446fcb4a4c9f99808"
		logic_hash = "750b2d5157856e0ffd840406eec601ded51ced7ccb20b577f336bbaf32681835"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "jhuhugit.tmp" fullword ascii
		$s8 = "KERNEL32.dll" fullword ascii
		$s9 = "IsDebuggerPresent" fullword ascii
		$s10 = "IsProcessorFeaturePresent" fullword ascii
		$s11 = "TerminateProcess" fullword ascii
		$s13 = "DeleteFileA" fullword ascii
		$s15 = "GetProcessHeap" fullword ascii
		$s16 = "!This program cannot be run in DOS mode." fullword ascii
		$s17 = "LoadLibraryA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <722KB and all of them
}
