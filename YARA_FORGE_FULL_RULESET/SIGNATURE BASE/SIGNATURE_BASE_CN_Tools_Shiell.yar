rule SIGNATURE_BASE_CN_Tools_Shiell : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Shiell.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7ac7d79d-3f4e-54e7-bb97-ce94cbbb40a2"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L950-L966"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b432d80c37abe354d344b949c8730929d8f9817a"
		logic_hash = "44c494c24c090b21c3c201d57f910e8f4d5132a863715a090fa1e18c9d349d48"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "C:\\Users\\Tong\\Documents\\Visual Studio 2012\\Projects\\Shift shell" ascii
		$s2 = "C:\\Windows\\System32\\Shiell.exe" fullword wide
		$s3 = "Shift shell.exe" fullword wide
		$s4 = "\" /v debugger /t REG_SZ /d \"" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1500KB and 2 of them
}
