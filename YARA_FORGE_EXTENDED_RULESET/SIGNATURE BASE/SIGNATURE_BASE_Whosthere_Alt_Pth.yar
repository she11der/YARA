rule SIGNATURE_BASE_Whosthere_Alt_Pth : FILE
{
	meta:
		description = "Auto-generated rule - file pth.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "92e98381-9142-58af-82ce-4df9eb0a0039"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_passthehashtoolkit.yar#L116-L134"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "fbfc8e1bc69348721f06e96ff76ae92f3551f33ed3868808efdb670430ae8bd0"
		logic_hash = "137b0dae105f97b5d4352d16e52144e72306e61be57c5d93df77ad3f5808018e"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "c:\\debug.txt" fullword ascii
		$s1 = "pth.dll" fullword ascii
		$s2 = "\"Primary\" string found at %.8Xh" fullword ascii
		$s3 = "\"Primary\" string not found!" fullword ascii
		$s4 = "segment 1 found at %.8Xh" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <240KB and 4 of them
}
