import "pe"

rule SIGNATURE_BASE_Passsniffer_Zip_Folder_Readme
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file readme.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "f5965aa8-0f78-56fd-8e3e-6dc013942cb3"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1845-L1860"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a52545ae62ddb0ea52905cbb61d895a51bfe9bcd"
		logic_hash = "d9e6cd2ba7e98481664b0560184a07349bb471dd370c4b73ef5f5f05a8e89946"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "PassSniffer.exe" fullword ascii
		$s1 = "POP3/FTP Sniffer" fullword ascii
		$s2 = "Password Sniffer V1.0" fullword ascii

	condition:
		1 of them
}
