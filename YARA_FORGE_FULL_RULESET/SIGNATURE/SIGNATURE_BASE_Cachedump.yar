import "pe"

rule SIGNATURE_BASE_Cachedump : FILE
{
	meta:
		description = "Detects a tool used by APT groups - from files cachedump.exe, cachedump64.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ebcaeb73-d2df-5a4c-9f50-b4a01293b88b"
		date = "2016-09-08"
		modified = "2023-12-05"
		reference = "http://goo.gl/igxLyF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3364-L3384"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7e4d710ed9dab12114e87fa33abe6db6245c780b31bcd94fbd21e75aaa355ca8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "cf58ca5bf8c4f87bb67e6a4e1fb9e8bada50157dacbd08a92a4a779e40d569c4"
		hash2 = "e38edac8c838a043d0d9d28c71a96fe8f7b7f61c5edf69f1ce0c13e141be281f"

	strings:
		$s1 = "Failed to open key SECURITY\\Cache in RegOpenKeyEx. Is service running as SYSTEM ? Do you ever log on domain ? " fullword ascii
		$s2 = "Unable to open LSASS.EXE process" fullword ascii
		$s3 = "Service not found. Installing CacheDump Service (%s)" fullword ascii
		$s4 = "CacheDump service successfully installed." fullword ascii
		$s5 = "Kill CacheDump service (shouldn't be used)" fullword ascii
		$s6 = "cacheDump [-v | -vv | -K]" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 1 of them ) or (3 of them )
}
