rule SIGNATURE_BASE_APT_Magichound_Malmacro : FILE
{
	meta:
		description = "Detects malicious macro / powershell in Office document"
		author = "Florian Roth (Nextron Systems)"
		id = "ad573f52-dbda-5852-ad73-9ef47dd6e7df"
		date = "2017-02-17"
		modified = "2023-12-05"
		reference = "https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_magichound.yar#L33-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "198c6e7ab957d5c1bb45449b0b2210532e97ed11700f8435201200746e0dfa48"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "66d24a529308d8ab7b27ddd43a6c2db84107b831257efb664044ec4437f9487b"
		hash2 = "e5b643cb6ec30d0d0b458e3f2800609f260a5f15c4ac66faf4ebf384f7976df6"

	strings:
		$s1 = "powershell.exe " fullword ascii
		$s2 = "CommandButton1_Click" fullword ascii
		$s3 = "URLDownloadToFile" fullword ascii

	condition:
		( uint16(0)==0xcfd0 and filesize <8000KB and all of them )
}
