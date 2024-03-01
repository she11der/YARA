rule SIGNATURE_BASE_CN_Tools_Srss : FILE
{
	meta:
		description = "Chinese Hacktool Set - file srss.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "13191e2e-fbcd-5e0b-af55-cc10f2583c1b"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktool_scripts.yar#L44-L58"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "092ab0797947692a247fe80b100fb4df0f9c37a0"
		logic_hash = "e01fd60adc32be26b0940ecc127a17bfcfe2ebfcf6cefea76ba6adc61d3c18d4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "srss.exe -idx 0 -ip"
		$s1 = "-port 21 -logfilter \"_USER ,_P" ascii

	condition:
		filesize <100 and all of them
}
