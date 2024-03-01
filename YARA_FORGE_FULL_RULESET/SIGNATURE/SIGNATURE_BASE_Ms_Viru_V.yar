rule SIGNATURE_BASE_Ms_Viru_V : FILE
{
	meta:
		description = "Chinese Hacktool Set - file v.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "88a01e7a-8210-5e0c-a9b8-b7c9b991e16b"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1953-L1971"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ecf4ba6d1344f2f3114d52859addee8b0770ed0d"
		logic_hash = "028b589c11eeacb2edfeeaeaebf2da370e540cba964c9ebbb19e4c734afe190f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "c:\\windows\\system32\\command.com /c " fullword ascii
		$s2 = "Easy Usage Version -- Edited By: racle@tian6.com" fullword ascii
		$s3 = "OH,Sry.Too long command." fullword ascii
		$s4 = "Success! Commander." fullword ascii
		$s5 = "Hey,how can racle work without ur command ?" fullword ascii
		$s6 = "The exploit thread was unable to map the virtual 8086 address space" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 3 of them
}
