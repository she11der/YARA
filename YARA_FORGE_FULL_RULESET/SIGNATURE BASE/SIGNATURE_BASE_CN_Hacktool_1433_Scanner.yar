import "pe"

rule SIGNATURE_BASE_CN_Hacktool_1433_Scanner : FILE
{
	meta:
		description = "Detects a chinese MSSQL scanner"
		author = "Florian Roth (Nextron Systems)"
		id = "77712d29-1a32-59e7-999a-a2ef02212886"
		date = "2014-12-10"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L703-L720"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3e51e3596fc90bcea46236728da5437a9b6f56a42d64a651940321f575b32129"
		score = 40
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "del Weak1.txt" ascii fullword
		$s3 = "del Attack.txt" ascii fullword
		$s4 = "del /s /Q C:\\Windows\\system32\\doors\\" ascii
		$s5 = "!&start iexplore http://www.crsky.com/soft/4818.html)" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of ($s*)
}
