rule SIGNATURE_BASE_Othertools_Xiaoa : FILE
{
	meta:
		description = "Chinese Hacktool Set - file xiaoa.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "a456d373-2063-5264-8cf4-d0a5918392fc"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2089-L2107"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6988acb738e78d582e3614f83993628cf92ae26d"
		logic_hash = "451ed602bd1e9dd7e4020108ea133b60c546965bd77be349d07be42150f80fee"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
		$s2 = "The shell \"cmd\" success!" fullword ascii
		$s3 = "Not Windows NT family OS." fullword ascii
		$s4 = "Unable to get kernel base address." fullword ascii
		$s5 = "run \"%s\" failed,code: %d" fullword ascii
		$s6 = "Windows Kernel Local Privilege Exploit " fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 2 of them
}
