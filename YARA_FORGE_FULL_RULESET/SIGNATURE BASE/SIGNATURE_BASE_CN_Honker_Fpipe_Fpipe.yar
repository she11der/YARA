rule SIGNATURE_BASE_CN_Honker_Fpipe_Fpipe : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file FPipe.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "0d84aa8f-dc15-5bb7-a568-224c6a837685"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L2270-L2286"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a2c51c6fa93a3dfa14aaf31fb1c48a3a66a32d11"
		logic_hash = "bde46f2508dc82f91e39cc7bd88960e836522b068546ce65ebc07db69b3d4493"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Unable to create TCP listen socket. %s%d" fullword ascii
		$s2 = "http://www.foundstone.com" fullword ascii
		$s3 = "%s %s port %d. Address is already in use" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and all of them
}
