import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Burst_Thecard
{
	meta:
		description = "Disclosed hacktool set - file Thecard.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "a9946aeb-2042-522f-8d91-f8b96341bb64"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1421-L1438"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "50b01ea0bfa5ded855b19b024d39a3d632bacb4c"
		logic_hash = "29e1fb2e0bfa60e5406f9fd1c0ec99f0fc1b416ffc4d59846627e40959a32c63"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "tasklist |find \"Clear.bat\"||start Clear.bat" fullword ascii
		$s1 = "Http://www.coffeewl.com" fullword ascii
		$s2 = "ping -n 2 localhost 1>nul 2>nul" fullword ascii
		$s3 = "for /L %%a in (" ascii
		$s4 = "MODE con: COLS=42 lines=5" fullword ascii

	condition:
		all of them
}
