rule SIGNATURE_BASE_CN_Honker_Pr_Debug : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file debug.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "6d759818-b762-56f4-8475-82a7d18a659c"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L360-L375"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d11e6c6f675b3be86e37e50184dadf0081506a89"
		logic_hash = "0b7508e3a508adc9416f16549290e06468520c156dbd5192e5a352820586af9f"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "This exploit will execute \"net user temp 123456 /add & net localg" ascii

	condition:
		uint16(0)==0x5a4d and filesize <820KB and all of them
}
