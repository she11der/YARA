rule SIGNATURE_BASE_X_Way2_5_X_Way : FILE
{
	meta:
		description = "Chinese Hacktool Set - file X-way.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8e878671-2a7c-5c6e-a905-05d303f42e0f"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1386-L1407"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8ba8530fbda3e8342e8d4feabbf98c66a322dac6"
		logic_hash = "6261de5db1e7527f7726effe26ed5f88638e6cb378db4c99183dddcd42ae231f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "TTFTPSERVERFRM" fullword wide
		$s1 = "TPORTSCANSETFRM" fullword wide
		$s2 = "TIISSHELLFRM" fullword wide
		$s3 = "TADVSCANSETFRM" fullword wide
		$s4 = "ntwdblib.dll" fullword ascii
		$s5 = "TSNIFFERFRM" fullword wide
		$s6 = "TCRACKSETFRM" fullword wide
		$s7 = "TCRACKFRM" fullword wide
		$s8 = "dbnextrow" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 5 of them
}
