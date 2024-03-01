import "pe"

rule SIGNATURE_BASE_Servpw : FILE
{
	meta:
		description = "Detects a tool used by APT groups - file servpw.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "48b9dae1-16b3-563c-ac4e-b71f3a86b38a"
		date = "2016-09-08"
		modified = "2023-12-05"
		reference = "http://goo.gl/igxLyF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3325-L3344"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "150466c23ea7aa20f6e60c592ab6bd2f42e3a48a65a6665b89a9f19fa61aae8f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "97b39ac28794a7610ed83ad65e28c605397ea7be878109c35228c126d43e2f46"
		hash2 = "0f340b471ef34c69f5413540acd3095c829ffc4df38764e703345eb5e5020301"

	strings:
		$s1 = "Unable to open target process: %d, pid %d" fullword ascii
		$s2 = "LSASS.EXE" fullword wide
		$s3 = "WriteProcessMemory failed: %d" fullword ascii
		$s4 = "lsremora64.dll" fullword ascii
		$s5 = "CreateRemoteThread failed: %d" fullword ascii
		$s6 = "Thread code: %d, path: %s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 3 of them ) or ( all of them )
}
