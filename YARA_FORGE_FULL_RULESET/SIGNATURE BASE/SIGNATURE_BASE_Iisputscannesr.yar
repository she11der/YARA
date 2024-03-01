rule SIGNATURE_BASE_Iisputscannesr : FILE
{
	meta:
		description = "Chinese Hacktool Set - file IISPutScannesr.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c5d358e8-955f-5b96-89e7-eb0b6c4d0af0"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2013-L2027"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2dd8fee20df47fd4eed5a354817ce837752f6ae9"
		logic_hash = "27c190050aabcdff3713b388adb0113ad2334c107a2a7b3d682c209b102cf642"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "yoda & M.o.D." ascii
		$s2 = "-> come.to/f2f **************" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}
